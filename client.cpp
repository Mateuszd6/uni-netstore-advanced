#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ctime>
#include <poll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <atomic>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <unordered_map>
#include <future>
namespace fs = std::filesystem;

#include "common.hpp"
#include "work_queue.hpp"
#include "cmd.hpp"
#include "connection.hpp"

#define TTL_VALUE 4

struct client_options
{
    std::optional<std::string> mcast_addr = {};
    std::optional<std::string> out_fldr = {};
    std::optional<uint32> cmd_port = {};
    std::optional<uint32> timeout = 5;
};

struct search_entry
{
    std::string filename;
    sockaddr_in server_uaddr;
};

struct available_server
{
    sockaddr_in uaddr;
    in_addr maddr;
    size_t free_space;
};

// TODO: rename?
struct accept_msg_content
{
    sockaddr_in uaddr;
    uint64 awaiting_port_num;
};

// global server options.
static client_options co{};

static std::atomic_uint64_t cmd_seq_counter{0};
static std::vector<search_entry> last_search_result{};

static std::mutex awaitng_packets_mutex{};
static std::unordered_map<uint64, std::unique_ptr<work_queue<send_packet>>> awaiting_packets{};

// We could use iostreams here, but for consistency, lets not use them.
std::string get_input_line()
{
    char* lineptr = nullptr;
    size_t n = 0;
    if (getline(&lineptr, &n, stdin) == -1)
    {
        // If eof was reached (C-d clicked in the console), prevent program from
        // going crazy and just exit safetly. It isn't specified in the task,
        // but we won't be able to read any commands after this anyway.
        if (feof(stdin))
        {
            logger.trace("C-d read from the console. Exitting.");
            free(lineptr);
            return "exit";
        }
        else
            logger.syserr("getline");
    }

    std::string retval{lineptr};
    while(!retval.empty() && retval.back() == '\n')
        retval.pop_back();

    free(lineptr);
    return retval;
}

// TODO: This is a copypaste of the server function.
// If file exists this will load its contents into the vector and return (true,
// contents) pair, otherwise (false, _) is returned, where _ could be anything.
std::pair<bool, std::vector<uint8>>
load_file_if_exists(fs::path file_path)
{
    std::vector<uint8> contents{};
    if (fs::exists(file_path))
    {
        constexpr static size_t buffer_size = 4096;
        std::ifstream file{file_path};
        char buffer[buffer_size];

        assert(file.is_open());
        while (!(file.eof() || file.fail())) {
            file.read(buffer, buffer_size);
            contents.reserve(contents.size() + file.gcount());
            contents.insert(contents.end(), buffer, buffer + file.gcount());
        }

        return {true, contents};
    }

    return {false, contents};
}

std::pair<bool, std::string>
receive_file_over_tcp(char const* addr, char const* port, fs::path out_file_path)
{
    logger.trace("Receiving file %s from %s:%s", out_file_path.c_str(), addr, port);

    int sock = connect_to_stream(addr, port, chrono::seconds{*co.timeout});
    if (sock < 0)
        return {false, "Cound not connect to the server"};

    std::vector<uint8> file_content;
    uint8 buffer[send_block_size];
    ssize_t len;
    while ((len = read(sock, buffer, send_block_size)) > 0)
    {
        logger.trace("Got %lu bytes", len);
        std::copy(buffer, buffer + len, std::back_inserter(file_content));
    }

    safe_close(sock);

    if (len < 0)
    {
        if (errno == EAGAIN)
            return {false, "Server timeout"};
        else
            return {false, "Error while reading the socket"};
    }

    std::ofstream output_file{out_file_path, std::ofstream::binary};
    if (output_file.fail())
        return {false, "Could not create a file"};

    output_file.write((char const*)file_content.data(), file_content.size());
    output_file.close();
    logger.trace("File saved successfully");
    return {true, ""};
}

std::pair<bool, std::string>
send_file_over_tcp(char const* addr, char const* port, std::vector<uint8> data)
{
    logger.trace("Sending %lu bytes to %s:%s", data.size(), addr, port);

    int sock = connect_to_stream(addr, port, chrono::seconds{*co.timeout});
    if (sock < 0)
    {
        return {false, "Cound not connect to the server"};
    }

    if (send_stream(sock, data.data(), data.size()) != data.size())
    {
        safe_close(sock);
        return {false, "Error sending the file"};
    }

    logger.trace("Sending successfull");
    safe_close(sock);
    return {true, ""};
}

template<typename T>
struct basic_packet_handler
{
protected:
    // This fucntion is done every time packet is received. If it returns true,
    // then no more packets will be consumed.
    virtual bool on_packet_receive(send_packet const& packet) { return false; }

    // This is called to obtain the result, once after package receive loop
    // finishes.
    virtual T get_result() { return T{}; }

public:
    uint64 const cmd_seq;
    bool aborted;

    basic_packet_handler(uint64 id) : cmd_seq{id} {
        aborted = false;

        // Subscribe for packets:
        std::lock_guard<std::mutex> m{awaitng_packets_mutex};

        // TODO: Don't do it, or if it happens, change the packed seq num
        assert(awaiting_packets.count(cmd_seq) == 0);
        awaiting_packets.emplace(
            cmd_seq,
            std::make_unique<work_queue<send_packet>>(chrono::system_clock::now() +
                                                      chrono::seconds{*co.timeout}));
    }

    T receive_packets(uint64 cmd_seq) {
        for (;;) {
            // Its safer to use at instread of [], because of the thread safety.
            std::lock_guard<std::mutex> m{awaitng_packets_mutex};
            std::optional<send_packet> c = awaiting_packets[cmd_seq]->consume();
            if (!c.has_value())
            {
                logger.trace("No more [%lu] packets", cmd_seq);
                break;
            }

            if (on_packet_receive(c.value()))
                break;
        }

        std::lock_guard<std::mutex> m{awaitng_packets_mutex};
        aborted = awaiting_packets[cmd_seq]->was_aborted();
        awaiting_packets.erase(cmd_seq);
        logger.trace("Done packet handling for cmd: %lu", cmd_seq);

        return get_result();
    }
};

struct hello_packet_handler : basic_packet_handler<std::vector<available_server>>
{
    using basic_packet_handler::basic_packet_handler;
protected:
    std::vector<available_server> servers;

    bool on_packet_receive(send_packet const& packet) override {
        logger.trace_packet("Received from", packet, cmd_type::cmplx);

        // TODO: Validate the size of a msg.


        // TODO: Use strview because we use zeros that are not part of the message.
        auto mcast_addr = string_to_addr((char const*)packet.cmd.cmplx.get_data());
        if (!mcast_addr)
        {
            logger.pckg_error(packet.from_addr, "Address returned by server is invalid");
        }
        else
        {
            servers.emplace_back(
                available_server{packet.from_addr, *mcast_addr, packet.cmd.cmplx.get_param()});
        }

        return false;
    }

    std::vector<available_server> get_result() override {
        return std::move(servers);
    }
};

struct list_packet_handler : basic_packet_handler<std::vector<search_entry>>
{
    using basic_packet_handler::basic_packet_handler;
protected:
    std::vector<search_entry> search_result;

    bool on_packet_receive(send_packet const& packet) override {
        logger.trace_packet("Received from", packet, cmd_type::simpl);

        // TODO: Watch out for more than one \n in a row.
        uint8 const* str = &packet.cmd.simpl.data[0];
        while (*str)
        {
            uint8 const* p = str;
            while (*p && *p != '\n')
                ++p;

            search_result.emplace_back(
                search_entry{std::string{(char const*)str, (size_t)(p - str)},
                             packet.from_addr});

            if (*p == '\n')
                ++p;
            str = p;
        }

        return false;
    }

    std::vector<search_entry> get_result() override {
        return std::move(search_result);
    }
};

struct add_packet_handler : basic_packet_handler<std::optional<accept_msg_content>>
{
    using basic_packet_handler::basic_packet_handler;
protected:
    // Non-null if one server has agree to take the file.
    std::optional<accept_msg_content> result = {};

    bool on_packet_receive(send_packet const& packet) override {

        // If we've got one reposne, we dont have to wait for more.
        if (packet.cmd.check_header("CAN_ADD"))
        {
            // TODO: SANITIZE THE PACKET!
            logger.trace_packet("Received", packet, cmd_type::cmplx);

            result = accept_msg_content{packet.from_addr, packet.cmd.cmplx.get_param()};
            return true;
        }
        else if (packet.cmd.check_header("NO_WAY"))
        {
            // TODO: SANITIZE THE PACKET!
            logger.trace_packet("Received", packet, cmd_type::simpl);
            return true;
        }

        return false;
    }

    std::optional<accept_msg_content> get_result() override {
        return std::move(result);
    }
};

struct get_packet_handler : basic_packet_handler<std::optional<accept_msg_content>>
{
    using basic_packet_handler::basic_packet_handler;
protected:
    // Non-null if one server has agree to take the file.
    std::optional<accept_msg_content> result = {};

    bool on_packet_receive(send_packet const& packet) override {
        // TODO: SANITIZE THE PACKET!

        // If we've got one reposne, we dont have to wait for more.
        if (packet.cmd.check_header("CONNECT_ME"))
        {
            logger.trace_packet("Received", packet, cmd_type::cmplx);

            result = accept_msg_content{packet.from_addr, packet.cmd.cmplx.get_param()};
            return true;
        }

        return false;
    }

    std::optional<accept_msg_content> get_result() override {
        return std::move(result);
    }
};

void packets_thread(int sock, int interfd)
{
    struct pollfd pfd[2];
    pfd[0].fd = interfd;
    pfd[0].events = POLLIN | POLLERR | POLLHUP;
    pfd[1].fd = sock;
    pfd[1].events = POLLIN | POLLERR | POLLHUP;;

    for (;;)
    {
        send_packet response{};
        int ret = poll(pfd, 2, -1);
        ssize_t rcv_len;

        if (pfd[0].revents & POLLIN)
        {
            logger.trace("Main thread tells me to stop. I'm gonna die now!");
            return;
        }

        if (pfd[1].revents & POLLIN)
        {
            logger.trace("Got client");
            rcv_len = recvfrom(sock, response.cmd.bytes, sizeof(response.cmd.bytes), 0,
                               (sockaddr*)&response.from_addr, &response.from_addr_len);
        }

        // If there was an error:
        if (rcv_len < 0 && errno != EAGAIN)
        {
            logger.trace("Error: %s(%d)", strerror(errno), errno);
            logger.trace("Closing!");
            safe_close(sock);
            exit(1); // TODO: Investigate
        }
        else if (rcv_len == 0) // TODO: Socket has been closed (How do we
                               //       even get here when mutlicasting)?
        {
            logger.trace("NO IDEA WHAT IS HAPPENING!!!!");
            exit(1);
        }
        else if (rcv_len > 0)
        {
            std::lock_guard<std::mutex> m{awaitng_packets_mutex};

            if (awaiting_packets.count(response.cmd.get_cmd_seq()))
                awaiting_packets[response.cmd.get_cmd_seq()]->push(response);
            else
                logger.pckg_error(response.from_addr, nullptr);
        }
    }
}

void try_upload_file(int sock,
                     sockaddr_in remote_address,
                     std::string filename,
                     std::vector<uint8> file_data)
{
    logger.trace("Fetching the list");
    uint64 fetch_packet_id = cmd_seq_counter++;
    hello_packet_handler ph{fetch_packet_id};
    auto[request, size] = command::make_simpl("HELLO", fetch_packet_id, 0, 0);
    logger.trace_packet("Sending to", send_packet{request, remote_address}, cmd_type::simpl);
    send_dgram(sock, remote_address, request.bytes, size);

    std::vector<available_server> servers = ph.receive_packets(fetch_packet_id);
    if (ph.aborted) {
        logger.trace("packet handling aborted!");
        return;
    }

    std::sort(servers.begin(), servers.end(),
              [](auto const& x, auto const& y) {
                  return x.free_space > y.free_space;
              });

    logger.trace("Got %lu servers. Querying...", servers.size());
    std::optional<accept_msg_content> server_agreement = {};
    for(auto&& serv : servers)
    {
        uint64 packet_id = cmd_seq_counter++;
        auto[request, size] = command::make_cmplx(
            "ADD", packet_id, file_data.size(),
            (uint8 const*)filename.c_str(),
            filename.size());

        add_packet_handler ph{packet_id};
        logger.trace_packet("Sending to", send_packet{request, serv.uaddr}, cmd_type::cmplx);
        send_dgram(sock, serv.uaddr, request.bytes, size);

        server_agreement = ph.receive_packets(packet_id);
        if (ph.aborted) {
            logger.trace("packet handling aborted!");
            return;
        }

        if (server_agreement)
        {
            logger.trace("Found server that agreeded to store a file");
            break;
        }
    }

    if (server_agreement)
    {
        std::string addr_str = addr_to_string(server_agreement->uaddr.sin_addr);
        std::string port_str = std::to_string(server_agreement->awaiting_port_num);

        logger.trace("Starting TCP conn at port %s", port_str.c_str());
        auto[success, reason] = send_file_over_tcp(addr_str.c_str(),
                                                   port_str.c_str(),
                                                   file_data);

        if (success)
        {
            logger.println("File {%s} uploaded (%s:%s)",
                           filename.c_str(),
                           addr_str.c_str(),
                           port_str.c_str());
        }
        else
        {
            logger.println("File %s uploading failed (%s:%s) %s",
                           filename.c_str(),
                           addr_str.c_str(),
                           port_str.c_str(),
                           reason.c_str());
        }
    }
    else
        logger.println("File %s too big", filename.c_str());
}

void try_receive_file(int sock, search_entry found_server, std::string filename)
{
    uint64 packet_id = cmd_seq_counter++;
    get_packet_handler ph{packet_id};
    auto[request, size] = command::make_simpl(
        "GET",
        packet_id,
        (uint8 const*)found_server.filename.c_str(),
        found_server.filename.size());

    logger.trace_packet("Sending to",
                        send_packet{request, found_server.server_uaddr},
                        cmd_type::simpl);

    send_dgram(sock, found_server.server_uaddr, request.bytes, size);

    std::optional<accept_msg_content> server_agreement = ph.receive_packets(packet_id);
    if (ph.aborted) {
        logger.trace("packet handling aborted!");
        return;
    }

    bool failed = false;
    std::string fail_reason = "";
    std::string uaddr_str = "";
    std::string port_str = "";

    if (!server_agreement)
    {
        failed = true;
        fail_reason = "Server did not respond";
    }

    if (!failed)
    {
        fs::path out{* co.out_fldr};
        out /= filename;

        uaddr_str = addr_to_string(server_agreement->uaddr.sin_addr);
        port_str = std::to_string(server_agreement->awaiting_port_num);

        auto[success, reason] = receive_file_over_tcp(uaddr_str.c_str(),
                                                      port_str.c_str(),
                                                      out);

        if (!success)
        {
            failed = true;
            fail_reason = std::move(reason);
        }
    }

    if (failed)
    {
        logger.println("File %s downloading failed (%s:%s) %s",
                       filename.c_str(),
                       uaddr_str.c_str(),
                       port_str.c_str(),
                       fail_reason.c_str());
    }
    else
    {
        logger.println("File %s downloaded (%s:%d)",
                       filename.c_str(),
                       addr_to_string(server_agreement->uaddr.sin_addr).c_str(),
                       server_agreement->awaiting_port_num);
    }
}

client_options parse_args(int argc, char** argv)
{
    client_options retval{};
    for (int i = 1; i < argc; ++i)
    {
        uint32 arg_hashed = strhash(argv[i]);

        if (i == argc - 1)
            logger.fatal("Invalid arguments");

        // The constexpr trick will speed up string lookups, as we don't have to
        // invoke string compare.
        switch (arg_hashed)
        {
            case strhash("-g"): { // MCAST_ADDR
                ++i;
                retval.mcast_addr = std::string{argv[i]};
            } break;

            case strhash("-p"): { // CMD_PORT
                ++i;
                int32 port = std::stoi(argv[i]);
                retval.cmd_port = port;
            } break;

            case strhash("-o"): { // OUT_FLDR
                ++i;
                retval.out_fldr = std::string{argv[i]};
            } break;

            case strhash("-t"): { // TIMEOUT
                ++i;
                int32 timeout = std::min(std::stoi(argv[i]), 300);
                retval.timeout = timeout;
            } break;

            default: {
                logger.fatal("Invalid arguments");
            } break;
        }
    }

    // If any of the fields is null, a required field was not set, so we exit.
    if (!retval.mcast_addr || !retval.out_fldr || !retval.cmd_port || !retval.timeout)
    {
        logger.fatal("Missing required arguments");
    }

    return retval;
}

int
main(int argc, char** argv)
{
    co = parse_args(argc, argv);
    logger.trace("OPTIONS:");
    logger.trace("  MCAST_ADDR = %s", co.mcast_addr->c_str());
    logger.trace("  CMD_PORT = %d", *co.cmd_port);
    logger.trace("  OUT_FLDR = %s", co.out_fldr->c_str());
    logger.trace("  TIMEOUT = %d", *co.timeout);

    // zmienne i struktury opisujące gniazda
    int sock, optval;
    //  struct sockaddr_in local_address;
    sockaddr_in remote_address, local_address;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        logger.syserr("socket");

    optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void*)&optval, sizeof optval) < 0)
        logger.syserr("setsockopt broadcast");

    optval = TTL_VALUE;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void*)&optval, sizeof optval) < 0)
        logger.syserr("setsockopt multicast ttl");

#if 0
    optval = 0;
    if (setsockopt(sock, SOL_IP, IP_MULTICAST_LOOP, (void*)&optval, sizeof optval) < 0)
        syserr("setsockopt loop");
#endif

    // bind to local address
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(0);
    if (bind(sock, (sockaddr*)&local_address, sizeof local_address) < 0)
        logger.syserr("bind");

    auto parsed_addr = string_to_addr(co.mcast_addr->c_str());
    if (!parsed_addr)
        logger.fatal("Specified address is invalid");
    remote_address.sin_family = AF_INET;
    remote_address.sin_port = htons(* co.cmd_port);
    remote_address.sin_addr = *parsed_addr;

    timeval tv = chrono_to_posix(chrono::seconds{*co.timeout});
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));

    // HACK: We can't really use signalfd as we used in the server to stop the
    // threads, because in this case we have two; one awaiting packets, and one
    // responding to user commands. To stop the packet thread, we use pipe,
    // which it polls along with the udp socket. If anything is written to the
    // pipe, this means that the user has entered exit command, and this thread
    // will terminate. That way we avoid messing with thread kills and signals.
    int fields[2];
    if (pipe (fields) < 0)
        logger.syserr("pipe");

    std::vector<std::thread> workers{};
    std::thread packet_handler{packets_thread, sock, fields[0]};

    for (;;)
    {
        std::string input_line = get_input_line();
        std::string_view command{};
        std::string_view param{};

        size_t space_occur = input_line.find(" ");
        if (space_occur == std::string::npos)
        {
            command = std::string_view{input_line};
        }
        else
        {
            command = std::string_view{input_line.c_str(), space_occur};
            param = std::string_view{input_line.c_str() + space_occur + 1};
        }

        logger.trace("command is: '%.*s', param is: '%.*s'",
                     static_cast<int>(command.size()), command.data(),
                     static_cast<int>(param.size()), param.data());

        if (command == "exit")
        {
            // Writing to pipe, means to packet hndler that he must die now.
            if (write(fields[1], "0", 1) < 0)
                logger.syserr("write");
            packet_handler.join();
            logger.trace("Joined packet handler!");

            // Abort all work in the work queue.
            {
                std::lock_guard<std::mutex> m{awaitng_packets_mutex};
                for (auto&& it : awaiting_packets)
                    it.second->abort();
            }

            // Now we can join workers.
            for (auto&& th : workers)
                th.join();

            break;
        }
        else if (command == "discover")
        {
            uint64 packet_id = cmd_seq_counter++;
            hello_packet_handler ph{packet_id};

            auto[request, size] = command::make_simpl("HELLO", packet_id, 0, 0);
            logger.trace_packet("Sending to", send_packet{request, remote_address}, cmd_type::simpl);
            send_dgram(sock, remote_address, request.bytes, size);

            // TODO: VALIDATE DATA!?

            std::vector<available_server> available_servers{};
            available_servers = ph.receive_packets(packet_id);
            if (ph.aborted)
                continue;

            for (auto&& i : available_servers)
            {
                std::string uaddr = addr_to_string(i.uaddr.sin_addr);
                std::string maddr = addr_to_string(i.maddr);

                logger.println("Found %s (%s) with free space %lu", uaddr.c_str(), maddr.c_str(), i.free_space);
            }
        }
        else if (command == "search")
        {
            uint64 packet_id = cmd_seq_counter++;
            list_packet_handler ph{packet_id};

            auto[request, size] = command::make_simpl("LIST", packet_id, (uint8 const*)param.data(), param.size());
            logger.trace_packet("Sending to", send_packet{request, remote_address}, cmd_type::simpl);
            send_dgram(sock, remote_address, request.bytes, size);

            // This will block the main thread.
            last_search_result.clear();
            last_search_result = ph.receive_packets(packet_id);
#if 0
            if (ph.aborted) {
                logger.trace("packet handling aborted!");
                return;
            }
#endif

            for (auto&& i : last_search_result)
            {
                logger.println("%s (%s)", i.filename.c_str(), addr_to_string(i.server_uaddr.sin_addr).c_str());
            }
        }
        else if (command == "remove")
        {
            if (param == "")
            {
                logger.trace("Cannot remove because of the empty param!");
                continue;
            }

            uint64 packet_id = cmd_seq_counter++;
            auto[request, size] = command::make_simpl("DEL", packet_id, (uint8 const*)param.data(), param.size());
            logger.trace_packet("Sending to", send_packet{request, remote_address}, cmd_type::simpl);
            send_dgram(sock, remote_address, request.bytes, size);
        }
        else if (command == "fetch")
        {
            if (param == "")
            {
                logger.trace("Cannot upload because of the empty param!");
                continue;
            }

            auto it = std::find_if(
                last_search_result.begin(),
                last_search_result.end(),
                [&](auto x) {
                    return x.filename == param;
                });

            if (it == last_search_result.end())
            {
                logger.println("%.*s does not exists in the previous search",
                               param.size(), param.data());
                continue;
            }

            workers.push_back(std::thread{try_receive_file, sock, *it, std::string(param)});
        }
        else if (command == "upload")
        {
            if (param == "")
            {
                logger.trace("Cannot upload because of the empty param!");
                continue;
            }

            fs::path upload_file_path{param};
            std::string filename{upload_file_path.filename()};

            // We load the whole file into memory to avoid races.
            auto[exists, data] = load_file_if_exists(upload_file_path);
            if (exists)
            {
                logger.trace("File %s(%s) exists, and has %lu bytes",
                             upload_file_path.c_str(), filename.c_str(), data.size());

                workers.push_back(std::thread{try_upload_file,
                                              sock,
                                              remote_address,
                                              std::move(filename),
                                              std::move(data)});
            }
            else
                logger.println("File %s does not exist", upload_file_path.c_str());
        }
    }

    // koniec
    safe_close(sock);
}
