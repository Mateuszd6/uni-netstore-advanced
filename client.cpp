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

#define TTL_VALUE 4

// We could use iostreams here, but lets not do this, just for consistency.
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
            exit(0); // TODO: Save exit.
        }
        else
            logger.syserr("getline");
    }

    std::string retval{lineptr};
    while(!retval.empty() && retval.back() == '\n')
        retval.pop_back();

    if (lineptr)
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

struct search_entry
{
    std::string filename;
    in_addr server_unicast_addr;
};

struct available_server
{
    sockaddr_in uaddr;
    in_addr maddr;
    size_t free_space;
};

static std::atomic_uint64_t cmd_seq_counter{0};
static std::vector<search_entry> last_search_result{};
static std::vector<available_server> available_servers{};

void send_file_over_tcp(char const* addr,
                        char const* port,
                        std::vector<uint8> data)
{
    logger.trace("Sending %lu bytes to %s:%s", data.size(), addr, port);

    int sock;
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;

    int err, seq_no = 0, number;

    // 'converting' host/port in string to struct addrinfo
    memset(&addr_hints, 0, sizeof(addrinfo));
    addr_hints.ai_family = AF_INET; // IPv4
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;
    err = getaddrinfo(addr, port, &addr_hints, &addr_result);
    if (err == EAI_SYSTEM) // system error
        logger.syserr("getaddrinfo");
    else if (err != 0) // other error (host not found, etc.)
        logger.fatal("getaddrinfo");

    // initialize socket according to getaddrinfo results
    sock = socket(addr_result->ai_family, addr_result->ai_socktype, addr_result->ai_protocol);
    if (sock < 0)
        logger.syserr("socket");

    // connect socket to the server
    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) < 0)
    {
        logger.syserr("connect");
    }

    freeaddrinfo(addr_result);

#if 1
    // TODO: Use write_well
    if (write(sock, data.data(), data.size()) != data.size())
        logger.syserr("partial / failed write");
#else
    sleep(20);
#endif

    if (close(sock) < 0) // socket would be closed anyway when the program ends
        logger.syserr("close");
}

// TODO: There is a copy in the server libs!
void send_dgram(int sock, sockaddr_in remote_addr, uint8* data, size_t size)
{
    if (sendto(sock, data, size, 0, (sockaddr*)&remote_addr, sizeof(remote_addr)) != size)
    {
        logger.syserr("sendto");
    }
}

static void handle_response_hello(send_packet const& packet)
{
    logger.trace_packet("Received from", packet, cmd_type::cmplx);

    // TODO: Data sent _can_ be incorrect!!! dont syserr
    in_addr mcast_addr;
    if (inet_aton((char const*)packet.cmd.cmplx.get_data(), &mcast_addr) == 0)
    {
        logger.syserr("inet_aton");
    }

    available_servers.emplace_back(
        available_server{packet.from_addr, mcast_addr, packet.cmd.cmplx.get_param()});
}

std::mutex awaitng_packets_mutex{};
std::unordered_map<uint64, std::unique_ptr<work_queue<send_packet>>> awaiting_packets{};

struct basic_packet_handler
{
    // This fucntion is done every time packet is received. If it returns true,
    // then no more packets will be consumed.
    virtual bool on_packet_receive(send_packet const& packet) { return false; }

    // This is done after last packet was processed (either on_packet_receive
    // returned true, or timeout has been reached).
    virtual void on_exit() {}

    void receive_packets(uint64 cmd_seq) {
        for (;;) {
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
        size_t erased = awaiting_packets.erase(cmd_seq);
        logger.trace("Erasing: %lu", erased);
        on_exit();
    }
};

struct hello_packet_handler : basic_packet_handler
{
    std::promise<std::vector<available_server>> prom;
    std::vector<available_server> servers;

    hello_packet_handler(std::promise<std::vector<available_server>> promise) {
        prom = std::move(promise);
    }

    bool on_packet_receive(send_packet const& packet) override {
        logger.trace_packet("Received from", packet, cmd_type::cmplx);

        // TODO: Data sent _can_ be incorrect!!! dont syserr
        in_addr mcast_addr;
        if (inet_aton((char const*)packet.cmd.cmplx.get_data(), &mcast_addr) == 0)
            logger.syserr("inet_aton");

        servers.emplace_back(
            available_server{packet.from_addr, mcast_addr, packet.cmd.cmplx.get_param()});

        return false;
    }

    void on_exit() override {
        prom.set_value(std::move(servers));
    }
};

struct list_packet_handler : basic_packet_handler
{
    std::promise<std::vector<search_entry>> prom;
    std::vector<search_entry> search_res;

    list_packet_handler(std::promise<std::vector<search_entry>> promise) {
        prom = std::move(promise);
    }

    bool on_packet_receive(send_packet const& packet) override {
        logger.trace_packet("Received from", packet, cmd_type::simpl);

        // TODO: Watch out for more than one \n in a row.
        uint8 const* str = &packet.cmd.simpl.data[0];
        while (*str)
        {
            uint8 const* p = str;
            while (*p && *p != '\n')
                ++p;

            search_res.emplace_back(
                search_entry{std::string{(char const*)str, (size_t)(p - str)},
                             packet.from_addr.sin_addr});

            if (*p == '\n')
                ++p;
            str = p;
        }

        return false;
    }

    void on_exit() override {
        prom.set_value(std::move(search_res));
    }
};

static void handle_response_list(send_packet const& packet)
{
    logger.trace_packet("Received from", packet, cmd_type::simpl);

    // TODO: Watch out for more than one \n in a row.
    uint8 const* str = &packet.cmd.simpl.data[0];
    while (*str)
    {
        uint8 const* p = str;
        while (*p && *p != '\n')
            ++p;

        last_search_result.emplace_back(
            search_entry{std::string{(char const*)str, (size_t)(p - str)},
                         packet.from_addr.sin_addr});

        if (*p == '\n')
            ++p;
        str = p;
    }
}

// This adds a work queue to the awaiting_packets map. For now every arriving
// packet with the seq_cmd equal to one specified will go to the created work
// queue. Returns a pointer to the work queue.
work_queue<send_packet>* subscribe_for_packets(uint64 cmd_seq)
{
    std::lock_guard<std::mutex> m{awaitng_packets_mutex};

    // TODO: Don't do it, or if it happens, change the packed seq num
    assert(awaiting_packets.count(cmd_seq) == 0);
    awaiting_packets.emplace(
        cmd_seq,
        std::make_unique<work_queue<send_packet>>(chrono::system_clock::now() + 2s));

    return awaiting_packets[cmd_seq].get();
}

template<typename FUNC>
void receive_packets(uint64 cmd_seq, FUNC functor)
{
    for (;;)
    {
        std::optional<send_packet> c = awaiting_packets[cmd_seq]->consume();
        if (!c.has_value())
        {
            logger.trace("No more [%lu] packets", cmd_seq);
            break;
        }

        functor(c.value());
    }

    {
        std::lock_guard<std::mutex> m{awaitng_packets_mutex};

        size_t erased = awaiting_packets.erase(cmd_seq);;
        logger.trace("Erasing: %lu", erased);
    }
}

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
            close(sock);
            exit(1);
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
            {
                logger.trace("-> SOMEONE IS AWAITING PACKET %lu", response.cmd.get_cmd_seq());
                awaiting_packets[response.cmd.get_cmd_seq()]->push(response);
            }
            else
            {
                logger.pckg_error(response.from_addr, nullptr);
                logger.trace("-> UNEXPECTED cmd_seq: %lu", response.cmd.get_cmd_seq());
            }
        }
    }
}

bool try_upload_file(int sock,
                     sockaddr_in remote_address,
                     std::string filename,
                     std::vector<uint8> file_data)
{
    logger.trace("Fetching the list");
    uint64 fetch_packet_id = cmd_seq_counter++;
    subscribe_for_packets(fetch_packet_id);
    auto[request, size] = cmd::make_simpl("HELLO", fetch_packet_id, 0, 0);
    logger.trace_packet("Sending to", send_packet{request, remote_address}, cmd_type::simpl);
    send_dgram(sock, remote_address, request.bytes, size);

    std::promise<std::vector<available_server>> promise;
    std::future<std::vector<available_server>> future = promise.get_future();
    hello_packet_handler ph{std::move(promise)};
    ph.receive_packets(fetch_packet_id);

    future.wait();
    available_servers.clear();
    std::vector<available_server> servers{std::move(future.get())};
    std::sort(servers.begin(), servers.end(),
              [](auto const& x, auto const& y) {
                  return x.free_space > y.free_space;
              });

    logger.trace("Got %lu servers. Querying...", servers.size());
    bool server_agreed = false;
    sockaddr_in agreed_server_uaddr;
    uint64 agreed_server_port_num;
    for(auto&& serv : servers)
    {
        uint64 packet_id = cmd_seq_counter++;
        auto[request, size] = cmd::make_cmplx(
            "ADD", packet_id, file_data.size(), (uint8 const*)filename.c_str(), filename.size());

        subscribe_for_packets(packet_id);
        logger.trace_packet("Sending to", send_packet{request, serv.uaddr}, cmd_type::cmplx);
        send_dgram(sock, serv.uaddr, request.bytes, size);

        receive_packets(
            packet_id,
            [&](send_packet const& packet) {
                if (packet.cmd.check_header("CAN_ADD"))
                {
                    logger.trace_packet("Received", packet, cmd_type::cmplx);

                    server_agreed = true;
                    agreed_server_uaddr = serv.uaddr;
                    agreed_server_port_num = packet.cmd.cmplx.get_param();
                }
                else if (packet.cmd.check_header("NO_WAY"))
                {
                    logger.trace_packet("Received", packet, cmd_type::simpl);
                }
            });

        if (server_agreed)
        {
            logger.trace("Found server that agreeded to store a file");
            break;
        }
    }

    if (server_agreed)
    {
        char port_buffer[32];
        sprintf(port_buffer, "%lu", agreed_server_port_num);
        logger.trace("Starting TCP conn at port %s", port_buffer);
        send_file_over_tcp(inet_ntoa(agreed_server_uaddr.sin_addr), port_buffer, file_data);
        return true; // TODO: TCP CAN FAIL!
    }
    else
    {
        logger.trace("None of the servers agreeded");
        return false;
    }
}

int
main(int argc, char** argv)
{
    // argumenty wywołania programu
    char* remote_dotted_address;
    in_port_t remote_port;

    // zmienne i struktury opisujące gniazda
    int sock, optval;
    //  struct sockaddr_in local_address;
    sockaddr_in remote_address, local_address;
    unsigned int remote_len;

    // zmienne obsługujące komunikację
    size_t length;
    int i;

    // parsowanie argumentów programu
    if (argc != 3)
        logger.fatal("Usage: %s remote_address remote_port", argv[0]);

    remote_dotted_address = argv[1];
    remote_port = (in_port_t)atoi(argv[2]);

    // otworzenie gniazda
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        logger.syserr("socket");

    // uaktywnienie rozgłaszania (ang. broadcast)
    optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void*)&optval, sizeof optval) < 0)
        logger.syserr("setsockopt broadcast");

    // ustawienie TTL dla datagramów rozsyłanych do grupy
    optval = TTL_VALUE;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void*)&optval, sizeof optval) < 0)
        logger.syserr("setsockopt multicast ttl");

    // zablokowanie rozsyłania grupowego do siebie
#if 0
    optval = 0;
    if (setsockopt(sock, SOL_IP, IP_MULTICAST_LOOP, (void*)&optval, sizeof optval) < 0)
        syserr("setsockopt loop");
#endif

    // podpięcie się pod lokalny adres i port
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(0);
    if (bind(sock, (sockaddr*)&local_address, sizeof local_address) < 0)
        logger.syserr("bind");

    // ustawienie adresu i portu odbiorcy
    remote_address.sin_family = AF_INET;
    remote_address.sin_port = htons(remote_port);
    if (inet_aton(remote_dotted_address, &remote_address.sin_addr) == 0)
        logger.syserr("inet_aton");

    // ustawienie timeoutu
    timeval tv = chrono_to_posix(5s);
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

            // Now we can join workers.
            for (auto&& th : workers)
                th.join();

            break;
        }
        else if (command == "discover")
        {
            uint64 packet_id = cmd_seq_counter++;
            subscribe_for_packets(packet_id);
            auto[request, size] = cmd::make_simpl("HELLO", packet_id, 0, 0);
            logger.trace_packet("Sending to", send_packet{request, remote_address}, cmd_type::simpl);
            send_dgram(sock, remote_address, request.bytes, size);

            std::promise<std::vector<available_server>> promise;
            std::future<std::vector<available_server>> future = promise.get_future();
            hello_packet_handler ph{std::move(promise)};

            // This will block the main thread.
            ph.receive_packets(packet_id);

            future.wait();
            available_servers.clear();
            available_servers = future.get();
            for (auto&& i : available_servers)
            {
                std::string uaddr = inet_ntoa(i.uaddr.sin_addr); // TODO: Handle the case, when these fail!
                std::string maddr = inet_ntoa(i.maddr);

                logger.println("Found %s (%s) with free space %lu", uaddr.c_str(), maddr.c_str(), i.free_space);
            }
        }
        else if (command == "search")
        {
            uint64 packet_id = cmd_seq_counter++;
            subscribe_for_packets(packet_id);

            auto[request, size] = cmd::make_simpl("LIST", packet_id, (uint8 const*)param.data(), param.size());
            logger.trace_packet("Sending to", send_packet{request, remote_address}, cmd_type::simpl);
            send_dgram(sock, remote_address, request.bytes, size);

            std::promise<std::vector<search_entry>> promise;
            std::future<std::vector<search_entry>> future = promise.get_future();
            list_packet_handler ph{std::move(promise)};

            // This will block the main thread.
            ph.receive_packets(packet_id);

            last_search_result.clear();
            last_search_result = future.get();
            for (auto&& i : last_search_result)
            {
                logger.println("%s (%s)", i.filename.c_str(), inet_ntoa(i.server_unicast_addr));
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
            auto[request, size] = cmd::make_simpl("DEL", packet_id, (uint8 const*)param.data(), param.size());
            logger.trace_packet("Sending to", send_packet{request, remote_address}, cmd_type::simpl);
            send_dgram(sock, remote_address, request.bytes, size);
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

                workers.push_back(
                    std::thread{try_upload_file, sock, remote_address,
                                std::move(filename), std::move(data)});
            }
            else
                logger.trace("File %s does not exist", upload_file_path.c_str());
        }
    }

    // koniec
    close(sock);
}
