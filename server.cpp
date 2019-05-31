#include <cassert>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <poll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <algorithm>
#include <thread>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
namespace fs = std::filesystem;
namespace chrono = std::chrono;
using namespace std::chrono_literals;

#include "common.hpp"
#include "cmd.hpp"
#include "logger.hpp"
#include "connection.hpp"

struct server_options
{
    std::optional<std::string> mcast_addr = {};
    std::optional<std::string> shrd_fldr = {};
    std::optional<int64> max_space = 52428800;
    std::optional<int32> cmd_port = {};
    std::optional<int32> timeout = 5;
};

// we will use this mutex to make sure, that only one thread is accessing the
// folder, modifiying the capacity size, etc.
static std::mutex fs_mutex{};
static fs::path current_folder;
static ssize_t current_space = 0;

// global server options.
static server_options so;

// TODO: This should throw invalid value and report error by usage msg.
server_options parse_args(int argc, char const** argv)
{
    server_options retval{};
    for (int i = 1; i < argc; ++i)
    {
        uint32 arg_hashed = strhash(argv[i]);

        if (i == argc - 1) {
            // As every switch arg takes one followup, we know that the
            // arguments are ill-formed. TODO?
            break;
        }

        // The constexpr trick will speed up string lookups, as we don't have to
        // invoke string compare.
        switch (arg_hashed)
        {
            case strhash("-g"): // MCAST_ADDR
            {
                ++i;
                retval.mcast_addr = std::string{argv[i]};
            } break;

            case strhash("-p"): // CMD_PORT
            {
                ++i;
                int32 port = std::stoi(argv[i]); // TODO: Validate value?
                retval.cmd_port = port;
            } break;

            case strhash("-b"): // MAX_SPACE
            {
                ++i;
                int64 space_limit = std::stoi(argv[i]);  // TODO: Validate value?
                retval.max_space = space_limit;
            } break;

            case strhash("-f"): // SHRD_FLDR
            {
                ++i;
                retval.shrd_fldr = std::string{argv[i]};
            } break;

            case strhash("-t"): // TIMEOUT
            {
                ++i;
                int32 timeout = std::stoi(argv[i]); // TODO: Validate value?
                retval.timeout = timeout;
            } break;

            default:
                break;
                // TODO: How to treat unscpecified arguments?
        }
    }

    // If any of the fields is null, a required field was not set, so we exit.
    if (!retval.mcast_addr || !retval.shrd_fldr || !retval.max_space || !retval.cmd_port || !retval.timeout)
    {
        logger.trace("Nope");
        exit(1);
    }

    return retval;
}

static std::vector<std::thread> workers{};

// Valid path is one that does not contain '/' and has size > 0. we also
// blacklist .. which might be tricky on some systems.
bool sanitize_requested_path(std::string_view filename)
{
    return (filename.size() > 0 &&
            filename.find('/') == std::string_view::npos &&
            filename.find('\0') == std::string_view::npos &&
            filename != "..");
}

void index_files(int64 max_space)
{
    // TODO: We dont really need a mutex here...
    std::lock_guard<std::mutex> m{fs_mutex};

    current_space = max_space;
    int64 total_size = 0;
    for (auto&& entry : fs::directory_iterator(current_folder))
        if (entry.is_regular_file())
        {
            logger.trace("%s -> %ld", entry.path().c_str(), entry.file_size());
            total_size += entry.file_size();
        }

    current_space -= total_size;
    logger.trace("Total size: %ld", total_size);
    logger.trace("Space left: %ld", current_space);
}

// This function will not split the filenames so that they do not exceed udp msg
// size. The reason is because it runs under the mutex, so we don't want it to
// waste more time.
std::string make_filenames_list(std::string const& pattern)
{
    std::lock_guard<std::mutex> m{fs_mutex};

    // TODO: Decide what happend when pattern is like: "A\0B"
    std::string filenames{}; // TODO: Figure out how many bytes its good to reserve
    for (auto&& entry : fs::directory_iterator(so.shrd_fldr.value()))
        if (entry.is_regular_file())
        {
            std::string filename = entry.path().filename();
            if (pattern.size() > 0 &&
                std::search(filename.begin(), filename.end(),
                            pattern.begin(), pattern.end()) == filename.end())
            {
                // We _didn't_ find patter, so we skip.
                continue;
            }

            logger.trace("%s -> %ld", entry.path().c_str(), entry.file_size());

            // If there were some entries before, split them with \n.
            if (filenames.size() > 0)
                filenames.append("\n");
            filenames.append(filename.c_str());
        }

    return filenames;
}

// If file exists this will load its contents into the vector and return (true,
// contents) pair, otherwise (false, _) is returned, where _ could be anything.
std::pair<bool, std::vector<uint8>>
load_file_if_exists(fs::path file_path)
{
    std::vector<uint8> contents{};

    std::lock_guard<std::mutex> m{fs_mutex};
    if (fs::exists(file_path))
    {
        constexpr static size_t buffer_size = 4096;
        std::ifstream file{file_path};
        char buffer[buffer_size];

        assert(file.is_open()); // TODO: Dont assert!
        while (!(file.eof() || file.fail())) {
            file.read(buffer, buffer_size);
            contents.reserve(contents.size() + file.gcount());
            contents.insert(contents.end(), buffer, buffer + file.gcount());
        }

        return {true, contents};
    }

    return {false, contents};
}

// This assumes that the filename is valid.
bool try_alloc_file(fs::path file_path, ssize_t size)
{
    std::lock_guard<std::mutex> m{fs_mutex};

    if (current_space < size)
    {
        logger.trace("ERROR: File tooo big!!!");
        return false;
    }

    if (fs::exists(file_path))
    {
        logger.trace("ERROR: File exists!");
        return false;
    }

    current_space -= size;

    return true;
}

// TODO: Should we remember files we've saved, or should we just just filesystem
//       to do that?
// This assumes that the file name is sanitized.
bool try_delete_file(fs::path const& file_path)
{
    std::lock_guard<std::mutex> m{fs_mutex};

    if (fs::exists(file_path) && fs::is_regular_file(file_path))
    {
        size_t filesize = fs::file_size(file_path);
        fs::remove(file_path);
        current_space += filesize;
        return true;
    }

    logger.trace("ERROR: File does not exists!");
    return false;
}

void tcp_read_file(int sock, fs::path file_path, size_t expected_size)
{
    timeval tv = chrono_to_posix(chrono::seconds{* so.timeout});
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));

    int msg_sock;
    sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    bool stream_error = false;

    // get client connection from the socket
    msg_sock = accept(sock, (sockaddr *)(&client_addr), &client_addr_len);
    if (msg_sock < 0)
    {
        if (errno == EAGAIN)
        {
            logger.trace("timeout while waiting for client to connect");
            stream_error = true;
        }
        else
            logger.syserr("accept");
    }

    std::vector<uint8> file_content{};
    if (!stream_error)
    {
        // Now we have to set read timeout independently.
        setsockopt(msg_sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));

        uint8 buffer[1024];
        ssize_t len;
        while ((len = read(msg_sock, buffer, 1024)) > 0 &&
               file_content.size() <= expected_size)
        {
            std::copy(buffer, buffer + len, std::back_inserter(file_content));
        }

        if (len < 0)
        {
            if (errno == EAGAIN)
            {
                logger.trace("timeout while reading the file.");
                stream_error = true;
            }
            else
                logger.syserr("reading from client socket");
        }

        if (!stream_error && file_content.size() != expected_size) {
            logger.trace("Sent file does not match the expected size!");
            stream_error = true;
        }

        safe_close(msg_sock);
    }

    safe_close(sock);
    if (!stream_error)
    {
        std::lock_guard<std::mutex> m{fs_mutex};

        logger.trace("Writing %lu bytes the file: %s", file_content.size(), file_path.c_str());

        // As we succeeded we must subscrat the file size from the server pool.
        std::ofstream output_file{file_path};
        if (output_file.fail())
        {
            logger.trace("ERROR: Could not create a file!");
            stream_error = true;
        }
        else
        {
            output_file.write((char const*)file_content.data(), file_content.size());
            output_file.close();
            logger.trace("File saved successfully");
        }
    }

    if (stream_error)
    {
        logger.trace("Streaming error. File has not been saved");
        current_space += expected_size;
    }
}

void send_file_tcp(int sock, std::vector<uint8> data)
{
    // TODO: Copypaste
    timeval tv = chrono_to_posix(chrono::seconds{* so.timeout});
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));

    int msg_sock;
    sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    bool stream_error = false;

    // get client connection from the socket
    msg_sock = accept(sock, (sockaddr *)(&client_addr), &client_addr_len);
    if (msg_sock < 0)
    {
        if (errno == EAGAIN)
        {
            logger.trace("timeout while waiting for client to connect");
            stream_error = true;
        }
        else
            logger.syserr("accept");
    }

    logger.trace("Accepted. Sending the data");
    if (!stream_error)
    {
        ssize_t sent = send_stream(msg_sock, data.data(), data.size());
        if (sent != data.size())
            stream_error = true;
    }

    if (stream_error)
        logger.trace("An error has occured. File wasn't sent correctly");
    else
        logger.trace("File sent.");

    if (msg_sock > 0)
        safe_close(msg_sock);
    safe_close(sock);
}

static void handle_request_hello(int sock, send_packet const& packet, ssize_t msg_len)
{
    logger.trace_packet("Got", packet, cmd_type::simpl);

    if (!packet.cmd.contains_required_fields(cmd_type::simpl, msg_len)) {
        logger.pckg_error(packet.from_addr, "HELLO request too short");
        return;
    }

    if (packet.cmd.contains_data(cmd_type::simpl, msg_len)) {
        logger.pckg_error(packet.from_addr, "HELLO should not contain data");
        return;
    }

    auto[response, size] = command::make_cmplx(
        "GOOD_DAY",
        packet.cmd.get_cmd_seq(),
        current_space < 0 ? 0 : current_space, // Handle the case when no space.
        (uint8 const*)(so.mcast_addr.value().c_str()),
        strlen(so.mcast_addr.value().c_str()));

    logger.trace_packet("Responding to", send_packet{response, packet.from_addr}, cmd_type::cmplx);
    send_dgram(sock, packet.from_addr, response.bytes, size);
}

static void handle_request_list(int sock, send_packet const& packet, ssize_t msg_len)
{
    logger.trace_packet("Got", packet, cmd_type::simpl);

    if (!packet.cmd.contains_required_fields(cmd_type::simpl, msg_len)) {
        logger.pckg_error(packet.from_addr, "LIST request too short");
        return;
    }

    std::string filenames = make_filenames_list((char const*)packet.cmd.simpl.data);

    // Don't respond if none of the files matches the criteria.
    if (filenames.size() == 0)
        return;

    // Split the filenames, so that they do not exceed the max upd msg size.
    std::vector<std::string> fnames_splited{};
    char const* delim = "\n";
    auto prev = filenames.begin();
    do {
        auto find = std::search(prev, filenames.end(), delim, delim + 1);
        size_t entry_len = find - prev;

        if (fnames_splited.empty() ||
            fnames_splited.back().size() + 1 + entry_len > sizeof(command::simpl.data))
        {
            fnames_splited.emplace_back(prev, find);
        }
        else
        {
            fnames_splited.back().push_back('\n');
            std::copy(prev, find, std::back_inserter(fnames_splited.back()));
        }

        prev = find;
    } while (prev++ != filenames.end());

#if 0
    logger.trace("FNAMES, CHOPPED:");
    for (auto&& i : fnames_splited)
        logger.trace("{%s}", i.c_str());
    logger.trace("Which is %lu packets", fnames_splited.size());
#endif

    for (auto&& fnames_chunk : fnames_splited)
    {
        auto[response, size] = command::make_simpl(
            "MY_LIST",
            packet.cmd.get_cmd_seq(),
            (uint8 const*)(fnames_chunk.c_str()),
            fnames_chunk.size());

        logger.trace_packet("Responding to",
                            send_packet{response, packet.from_addr},
                            cmd_type::simpl);
        send_dgram(sock, packet.from_addr, response.bytes, size);
    }
}

static void handle_request_get(int sock, send_packet const& packet, ssize_t msg_len)
{
    logger.trace_packet("Got",packet, cmd_type::simpl);
    if (!packet.cmd.contains_required_fields(cmd_type::simpl, msg_len)) {
        logger.pckg_error(packet.from_addr, "GET request too short");
        return;
    }

    if (!packet.cmd.contains_data(cmd_type::simpl, msg_len)) {
        logger.pckg_error(packet.from_addr, "GET request must contain a filename");
        return;
    }

    std::string_view filename_sv{
        (char const*)packet.cmd.simpl.data,
        msg_len - command::simpl_head_size
    };

    if (!sanitize_requested_path(filename_sv)) {
        logger.pckg_error(packet.from_addr, "Invalid filename");
        return;
    }

    fs::path file_path{current_folder / filename_sv};
    auto[exists, content] = load_file_if_exists(file_path);
    if (exists)
    {
        auto[socket, port] = init_stream_conn();

        auto[response, size] = command::make_cmplx(
            "CONNECT_ME",
            packet.cmd.get_cmd_seq(),
            ntohs(port),
            (uint8 const*)filename_sv.data(),
            filename_sv.size());

        workers.push_back(std::thread{send_file_tcp, socket, content});

        logger.trace_packet("Responding to", send_packet{response, packet.from_addr}, cmd_type::cmplx);
        send_dgram(sock, packet.from_addr, response.bytes, size);
    }
    else
    {
        // TODO: HOW DO I REPORT THIS ERROR?
        logger.trace("I dont have file: %s\n", file_path.filename().c_str());
    }

     // TODO: Watch closely for strlen.
}

static void handle_request_add(int sock, send_packet const& packet, ssize_t msg_len)
{
    logger.trace_packet("Got", packet, cmd_type::cmplx);
    if (!packet.cmd.contains_required_fields(cmd_type::cmplx, msg_len)) {
        logger.pckg_error(packet.from_addr, "ADD request too short");
        return;
    }

    if (!packet.cmd.contains_data(cmd_type::cmplx, msg_len)) {
        logger.pckg_error(packet.from_addr, "ADD request must contain a filename");
        return;
    }

    std::string_view filename_sv{
        (char const*)packet.cmd.cmplx.data,
        msg_len - command::cmplx_head_size
    };

    if (!sanitize_requested_path(filename_sv)) {
        logger.pckg_error(packet.from_addr, "Invalid filename");
        return;
    }

    logger.trace("Adding a file: %s", filename_sv.data());

    fs::path file_path{current_folder / filename_sv};
    if (try_alloc_file(file_path, (ssize_t)packet.cmd.cmplx.get_param()))
    {
        // The init happens in the main thread so that we know the port
        // id. Then we start a new thread giving it a created socket.
        auto[socket, port] = init_stream_conn();

        logger.trace("Listening on port %hu", ntohs(port));
        workers.push_back(std::thread{tcp_read_file, socket, file_path, packet.cmd.cmplx.get_param()});

        auto[response, size] = command::make_cmplx(
            "CAN_ADD",
            packet.cmd.get_cmd_seq(),
            ntohs(port),
            (uint8 const*)filename_sv.data(),
            filename_sv.size());

        logger.trace_packet("Responding to", send_packet{response, packet.from_addr}, cmd_type::cmplx);
        send_dgram(sock, packet.from_addr, response.bytes, size);
    }
    else
    {
        logger.trace("Could not add a file");

        auto[response, size] = command::make_simpl(
            "NO_WAY",
            packet.cmd.get_cmd_seq(),
            (uint8 const*)filename_sv.data(),
            filename_sv.size());

        logger.trace_packet("Responding to", send_packet{response, packet.from_addr}, cmd_type::simpl);
        send_dgram(sock, packet.from_addr, response.bytes, size);
    }
}

static void handle_request_del(int sock, send_packet const& packet, ssize_t msg_len)
{
    logger.trace_packet("Got", packet, cmd_type::simpl);
    if (!packet.cmd.contains_required_fields(cmd_type::simpl, msg_len)) {
        logger.pckg_error(packet.from_addr, "DEL request too short");
        return;
    }

    if (!packet.cmd.contains_data(cmd_type::simpl, msg_len)) {
        logger.pckg_error(packet.from_addr, "DEL request must contain a filename");
        return;
    }

    std::string_view filename_sv{
        (char const*)packet.cmd.simpl.data,
        msg_len - command::simpl_head_size
    };

    if (!sanitize_requested_path(filename_sv)) {
        logger.pckg_error(packet.from_addr, "Invalid filename");
        return;
    }

    logger.trace("Removing file %s", packet.cmd.simpl.data);

    fs::path file_path = current_folder / filename_sv;
    try_delete_file(file_path);
}

int main(int argc, char const** argv)
{
    so = parse_args(argc, argv);
    logger.trace("OPTIONS:");
    logger.trace("  MCAST_ADDR = %s", so.mcast_addr->c_str());
    logger.trace("  CMD_PORT = %d", *so.cmd_port);
    logger.trace("  MAX_SPACE = %ld", *so.max_space);
    logger.trace("  SHRD_FLDR = %s", so.shrd_fldr->c_str());
    logger.trace("  TIMEOUT = %d", *so.timeout);

    // Create a folder if it does not exists already.
    // TODO: Check the output and fail miserably on error.
    fs::create_directories(so.shrd_fldr.value().c_str());
    current_folder = fs::path{so.shrd_fldr.value()};

    index_files(so.max_space.value());

    // SERVER STUFF: (TODO: Move away!)
    // argumenty wywołania programu
    char const* multicast_dotted_address; // TODO: Dont use, we have a string for that in so.
    in_port_t local_port;

    // zmienne i struktury opisujące gniazda
    int sock;
    sockaddr_in local_address, remote_address;
    ip_mreq ip_mreq;
    unsigned int remote_len = sizeof(remote_address);

    // zmienne obsługujące komunikację
    ssize_t rcv_len;
    int i;

    multicast_dotted_address = so.mcast_addr.value().c_str();
    local_port = (in_port_t)(so.cmd_port.value());

    // otworzenie gniazda
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        logger.syserr("socket");

    // podpięcie się do grupy rozsyłania (ang. multicast)
    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(multicast_dotted_address, &ip_mreq.imr_multiaddr) == 0)
        logger.syserr("inet_aton");
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&ip_mreq, sizeof(ip_mreq)) < 0)
        logger.syserr("setsockopt");

    // podpięcie się pod lokalny adres i port
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(local_port);
    if (bind(sock, (sockaddr*)&local_address, sizeof(local_address)) < 0)
        logger.syserr("bind");

    // TODO: Dont use asserts, just syserr's
    // Create a sigset of all the signals that we're interested in
    sigset_t sigset;
    int err = sigemptyset(&sigset);
    assert(err == 0);
    err = sigaddset(&sigset, SIGINT);
    assert(err == 0);

    // We must block the signals in order for signalfd to receive them
    err = sigprocmask(SIG_BLOCK, &sigset, NULL);
    assert(err == 0);

    // Create the signalfd
    int sigfd = signalfd(-1, &sigset, 0);
    assert(sigfd != -1);

    struct pollfd pfd[2];
    pfd[0].fd = sigfd;
    pfd[0].events = POLLIN | POLLERR | POLLHUP;
    pfd[1].fd = sock;
    pfd[1].events = POLLIN | POLLERR | POLLHUP;;

    // czytanie tego, co odebrano
    for (;;)
    {
        logger.trace("Sleeping on poll...");

        send_packet response{};
        int ret = poll(pfd, 2, -1);

        if (pfd[0].revents & POLLIN)
        {
            logger.trace("Got interrupt signal. I'm gonna die now!");
            break;
        }

        if (pfd[1].revents & POLLIN)
        {
            logger.trace("Got client");
            rcv_len = recvfrom(sock, response.cmd.bytes, sizeof(response.cmd.bytes), 0,
                               (sockaddr*)&response.from_addr, &response.from_addr_len);
        }

        if (rcv_len < 0)
        {
            logger.syserr("recvfrom");
        }
        else
        {
            logger.trace("read %zd bytes: %.*s", rcv_len, (int)rcv_len, response.cmd.bytes);

            if (response.cmd.check_header("HELLO"))
                handle_request_hello(sock, response, rcv_len);
            else if (response.cmd.check_header("LIST"))
                handle_request_list(sock, response, rcv_len);
            else if (response.cmd.check_header("GET"))
                handle_request_get(sock, response, rcv_len);
            else if (response.cmd.check_header("ADD"))
                handle_request_add(sock, response, rcv_len);
            else if (response.cmd.check_header("DEL"))
                handle_request_del(sock, response, rcv_len);
            else
                logger.pckg_error(response.from_addr, nullptr);
        }
    }

    for (auto&& th : workers)
        th.join();

    if (setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void*)&ip_mreq, sizeof ip_mreq) < 0)
        logger.syserr("setsockopt");

    safe_close(sock);

    return 0;
}
