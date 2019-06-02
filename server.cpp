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

#include <atomic>
#include <algorithm>
#include <thread>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>

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
    std::optional<bool> synchronized = false;
};

struct stored_file
{
    fs::path file_path;
    size_t file_size;
};

static std::mutex fs_mutex{};

static fs::path current_folder;
static ssize_t current_space = 0;
static int mcast_socket;

// global server options.
static server_options so;
static int signal_fd;
static std::vector<std::thread> workers{};
static std::atomic_uint64_t cmd_seq_counter{0};

static server_options parse_args(int argc, char const** argv)
{
    server_options retval{};
    for (int i = 1; i < argc; ++i) {
        uint32 arg_hashed = strhash(argv[i]);

        // Every arg has a pair.
        if (i == argc - 1)
            logger.fatal("Invalid arguments");

        switch (arg_hashed) {
            case strhash("-g"): { // MCAST_ADDR
                ++i;
                retval.mcast_addr = std::string{argv[i]};
            } break;

            case strhash("-p"): { // CMD_PORT
                ++i;
                retval.cmd_port = std::atoi(argv[i]);
            } break;

            case strhash("-b"): { // MAX_SPACE
                ++i;
                retval.max_space = std::atoll(argv[i]);
            } break;

            case strhash("-f"): { // SHRD_FLDR
                ++i;
                retval.shrd_fldr = std::string{argv[i]};
            } break;

            case strhash("-t"): { // TIMEOUT
                ++i;
                retval.timeout = std::atoi(argv[i]);
            } break;

            case strhash("-s"): { // SYNCHRONIZED
                ++i;
                retval.synchronized = (bool)(std::atoi(argv[i]));
            } break;

            default:
                logger.fatal("Invalid arguments");
        }
    }

    // If any of the fields is null, a required field was not set, so we exit.
    if (!retval.mcast_addr || !retval.shrd_fldr || !retval.max_space || !retval.cmd_port
        || !retval.timeout || !retval.synchronized)
        logger.fatal("Missing required arguments");

    if (*retval.timeout < 0 || *retval.timeout > 300)
        logger.fatal("Invalid timeout");

    if (*retval.cmd_port < 0 || *retval.cmd_port > 65535)
        logger.fatal("Invalid port");

    return retval;
}

// Valid path is one that does not contain '/' and has size > 0. we also
// blacklist .. which might be tricky on some systems.
static bool sanitize_requested_path(std::string_view filename)
{
    return (filename.size() > 0 &&
            filename.find('/') == std::string_view::npos &&
            filename.find('\0') == std::string_view::npos &&
            filename != "..");
}

static void index_files(int64 max_space)
{
    std::lock_guard<std::mutex> m{fs_mutex};

    current_space = max_space;
    int64 total_size = 0;
    for (auto&& entry : fs::directory_iterator(current_folder))
        if (fs::is_regular_file(entry.path()))
        {
            logger.trace("%s -> %ld", entry.path().c_str(), fs::file_size(entry.path()));
            total_size += fs::file_size(entry.path());
        }

    current_space -= total_size;
    logger.trace("Total size: %ld", total_size);
    logger.trace("Space left: %ld", current_space);
}

// This function will not split the filenames so that they do not exceed udp msg
// size. The reason is because it runs under the mutex, so we don't want it to
// waste more time.
static std::string make_filenames_list(std::string const& pattern)
{
    std::lock_guard<std::mutex> m{fs_mutex};

    std::string filenames{};
    for (auto&& entry : fs::directory_iterator(* so.shrd_fldr))
        if (fs::is_regular_file(entry.path()))
        {
            std::string filename = entry.path().filename().string();
            if (pattern.size() > 0 &&
                std::search(filename.begin(), filename.end(),
                            pattern.begin(), pattern.end()) == filename.end())
            {
                // We _didn't_ find patter, so we skip.
                continue;
            }

            logger.trace("%s -> %ld", entry.path().c_str(), fs::file_size(entry.path()));

            // If there were some entries before, split them with \n.
            if (filenames.size() > 0)
                filenames.append("\n");
            filenames.append(filename.c_str());
        }

    return filenames;
}

// This assumes that the filename is valid.
static bool try_alloc_file(fs::path file_path, ssize_t size)
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

// This assumes that the file name is sanitized.
static bool try_delete_file(fs::path const& file_path)
{
    std::lock_guard<std::mutex> m{fs_mutex};

    if (fs::exists(file_path) && fs::is_regular_file(file_path))
    {
        size_t filesize = fs::file_size(file_path);
        fs::remove(file_path);
        current_space += filesize;
        return true;
    }

    logger.trace("File %s does not exists!", file_path.c_str());
    return false;
}

static bool try_read_file_stream(int msg_sock, fs::path file_path, size_t expected_size)
{
    auto[succeess, reason] = recv_file_stream(msg_sock, file_path, expected_size, signal_fd);
    if (!succeess)
    {
        logger.trace("Error downloading the file: %s", reason.c_str());
        fs::remove(file_path); // Remove the destination, whetever was there.
        return false;
    }

    logger.trace("File %s saved successfully", file_path.c_str());
    return true;
}

static void sync_tell_other_to_delete(int sock, std::string filename);

// This function is what will be called asyncly and is responsible for closing
// the given socket.
static void receive_file(int sock, fs::path file_path, size_t expected_size)
{
    int msg_sock = accept_client_stream(sock, chrono::seconds{* so.timeout});
    bool success = false;

    if (msg_sock > 0)
    {
        success = try_read_file_stream(msg_sock, file_path, expected_size);
        safe_close(msg_sock);
    }
    safe_close(sock);

    if (success)
    {
        if (*so.synchronized)
        {
            std::string filename = file_path.filename().string();

            sync_tell_other_to_delete(mcast_socket, filename);
        }
    }
    else {
        // If failed whatever reason, bring the memory back to the pool.
        std::lock_guard<std::mutex> m{fs_mutex};
        current_space += expected_size;
    }
}

// Same as above, this fucntion closes sock.
static void send_file(int sock, fs::path file_path)
{
    int msg_sock = accept_client_stream(sock, chrono::seconds{* so.timeout});
    if (msg_sock > 0)
    {
        auto[success, reason] = stream_file(msg_sock, file_path, signal_fd);
        if (!success)
            logger.trace("Error while streaming file %s. Reason: %s",
                         file_path.string().c_str(), reason.c_str());

        safe_close(msg_sock);
    }
    else
        logger.trace("Client didn't connect to download %s", file_path.string().c_str());

    safe_close(sock);
}

static void sync_tell_other_to_delete(int sock, std::string filename)
{
    uint64 packet_id = cmd_seq_counter++;
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr = *string_to_addr(so.mcast_addr->c_str());
    addr.sin_port = htons((in_port_t)(* so.cmd_port));

    auto del_packet = packet::make_simpl(
        "DEL", packet_id,
        (uint8 const*)(filename.c_str()), filename.size(), addr);
    send_dgram(sock, del_packet);
}

static void sync_sendfile_to_other(std::string addr_str, std::string port_str,
                                   fs::path file_path, int dummy_signal_fd)
{
    logger.trace("Starting TCP conn at port %s", port_str.c_str());
    int stream_sock = connect_to_stream(addr_str.c_str(), port_str.c_str(),
                                        chrono::seconds{*so.timeout});

    timeval tv = chrono_to_posix(chrono::seconds{*so.timeout});
    setsockopt(stream_sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));
    setsockopt(stream_sock, SOL_SOCKET, SO_SNDTIMEO, (timeval*)&tv, sizeof(timeval));

    if (stream_sock > 0)
    {
        logger.trace("Sending file: %s", file_path.c_str());
        if (stream_file(stream_sock, file_path, dummy_signal_fd).first)
        {
            logger.trace("File %s saved", file_path.filename().string().c_str());
            try_delete_file(file_path);
        }

        safe_close(stream_sock);
    }
    else
        logger.trace("Connection error");
}

static void
sync_save_files(int sock, in_addr mcast_addr)
{
    // We used singalfd to make a fd that will be filled when thread should
    // abort reading/writing to the socket. But now we want to supress that, and
    // the easiets method is just to create a new, always empty descriptor and
    // set it as a signal_fd.
    int fields[2];
    if (pipe (fields) < 0)
        logger.syserr("pipe");
    signal_fd = fields[0];

    std::unordered_map<int, fs::path> cmdseq_to_filepath{};
    std::vector<stored_file> stored_files{};

    for (auto&& entry : fs::directory_iterator(current_folder))
        if (fs::is_regular_file(entry.path()))
            stored_files.push_back(stored_file{entry.path(), fs::file_size(entry)});

    // Sort the files, so that we start sending from the largest one.
    std::sort(stored_files.begin(), stored_files.end(),
              [](auto x, auto y) {
                  return x.file_size > y.file_size;
              });

    for (auto&& file : stored_files)
    {
        std::string filename = file.file_path.filename().string();
        uint64 packet_id = cmd_seq_counter++;

        logger.trace("Trying to save: %s (%lu)", file.file_path.c_str(), file.file_size);

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr = mcast_addr;
        addr.sin_port = htons((in_port_t)(* so.cmd_port));

        auto save_my_file_packet = packet::make_cmplx(
            "ADD", packet_id, file.file_size,
            (uint8 const*)(filename.c_str()), filename.size(), addr);

        cmdseq_to_filepath[packet_id] = file.file_path;

        send_dgram(sock, save_my_file_packet);
    }

    pollfd pfd[1];
    pfd[0].fd = sock;
    pfd[0].events = POLLIN | POLLERR | POLLHUP;

    // For now we will only respond to CAN_ADD messages. And we will try to send
    // as many files as possible.
    auto exit_time = chrono::steady_clock::now() + chrono::seconds{*so.timeout};
    for (;;)
    {
        auto time_left = chrono::duration_cast<chrono::milliseconds>(exit_time - chrono::steady_clock::now());
        if (time_left <= 0ms)
            break;
        logger.trace("Time left: %ldms", time_left.count());

        poll(pfd, 1, time_left.count());
        packet response{};

        if (pfd[0].revents & POLLIN)
        {
            response = recv_dgram(sock);
            logger.trace_packet("Got a response:", response, cmd_type::cmplx);

            if (cmdseq_to_filepath.count(response.cmd.get_cmd_seq()) &&
                response.cmd.check_header("CAN_ADD"))
            {

                logger.trace("Server agreed to store file: %s",
                             cmdseq_to_filepath[response.cmd.get_cmd_seq()].c_str());

                fs::path file_path{cmdseq_to_filepath[response.cmd.get_cmd_seq()]};
                cmdseq_to_filepath.erase(response.cmd.get_cmd_seq());

                std::string addr_str = addr_to_string(response.addr.sin_addr);
                std::string port_str = std::to_string(response.cmd.cmplx.get_param());

                workers.push_back(std::thread{sync_sendfile_to_other, addr_str, port_str, file_path, fields[0]});
            }
        }
    }
}

static void handle_request_hello(int sock, packet const& recv_packet)
{
    logger.trace_packet("Got", recv_packet, cmd_type::simpl);

    if (!recv_packet.cmd.contains_required_fields(cmd_type::simpl, recv_packet.msg_len)) {
        logger.pckg_error(recv_packet.addr, "HELLO request too short");
        return;
    }

    if (recv_packet.cmd.contains_data(cmd_type::simpl, recv_packet.msg_len)) {
        logger.pckg_error(recv_packet.addr, "HELLO should not contain data");
        return;
    }

    ssize_t av_space = 0;

    // Need fs mutex to get current_space safetly.
    {
        std::lock_guard<std::mutex> m{fs_mutex};
        av_space = current_space;
    }

    packet send = packet::make_cmplx(
        "GOOD_DAY",
        recv_packet.cmd.get_cmd_seq(),
        av_space < 0 ? 0 : av_space, // Handle the case when no space.
        (uint8 const*)(so.mcast_addr->c_str()),
        so.mcast_addr->size(),
        recv_packet.addr);

    logger.trace_packet("Responding to", send, cmd_type::cmplx);
    send_dgram(sock, send);
}

static void handle_request_list(int sock, packet const& recv_packet)
{
    logger.trace_packet("Got", recv_packet, cmd_type::simpl);

    if (!recv_packet.cmd.contains_required_fields(cmd_type::simpl, recv_packet.msg_len)) {
        logger.pckg_error(recv_packet.addr, "LIST request too short");
        return;
    }

    std::string filenames = make_filenames_list((char const*)recv_packet.cmd.simpl.data);

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

    for (auto&& fnames_chunk : fnames_splited)
    {
        packet send = packet::make_simpl(
            "MY_LIST",
            recv_packet.cmd.get_cmd_seq(),
            (uint8 const*)(fnames_chunk.c_str()),
            fnames_chunk.size(),
            recv_packet.addr);

        logger.trace_packet("Responding", send, cmd_type::simpl);
        send_dgram(sock, send);
    }
}

static void handle_request_get(int sock, packet const& recv_packet)
{
    logger.trace_packet("Got",recv_packet, cmd_type::simpl);
    if (!recv_packet.cmd.contains_required_fields(cmd_type::simpl, recv_packet.msg_len)) {
        logger.pckg_error(recv_packet.addr, "GET request too short");
        return;
    }

    if (!recv_packet.cmd.contains_data(cmd_type::simpl, recv_packet.msg_len)) {
        logger.pckg_error(recv_packet.addr, "GET request must contain a filename");
        return;
    }

    std::string_view filename_sv = recv_packet.data_as_sv(cmd_type::simpl);

    if (!sanitize_requested_path(filename_sv)) {
        logger.pckg_error(recv_packet.addr, "Invalid filename");
        return;
    }

    fs::path file_path{current_folder / std::string{filename_sv}};
    if (fs::exists(file_path))
    {
        auto[socket, port] = init_stream_conn(chrono::seconds{*so.timeout});
        packet send = packet::make_cmplx(
            "CONNECT_ME",
            recv_packet.cmd.get_cmd_seq(),
            ntohs(port),
            (uint8 const*)filename_sv.data(),
            filename_sv.size(),
            recv_packet.addr);

        workers.push_back(std::thread{send_file, socket, std::move(file_path)});
        logger.trace_packet("Responding to", send, cmd_type::cmplx);
        send_dgram(sock, send);
    }
    else
    {
        logger.pckg_error(recv_packet.addr, "File does not exists");
    }
}

static void handle_request_add(int sock, packet const& recv_packet)
{
    logger.trace_packet("Got", recv_packet, cmd_type::cmplx);
    if (!recv_packet.cmd.contains_required_fields(cmd_type::cmplx, recv_packet.msg_len)) {
        logger.pckg_error(recv_packet.addr, "ADD request too short");
        return;
    }

    if (!recv_packet.cmd.contains_data(cmd_type::cmplx, recv_packet.msg_len)) {
        logger.pckg_error(recv_packet.addr, "ADD request must contain a filename");
        return;
    }

    std::string_view filename_sv = recv_packet.data_as_sv(cmd_type::cmplx);

    ssize_t file_size = (ssize_t)recv_packet.cmd.cmplx.get_param();
    if (file_size < 0) {
        logger.pckg_error(recv_packet.addr, "Invalid file size");
        return;
    }

    if (!sanitize_requested_path(filename_sv)) {
        logger.pckg_error(recv_packet.addr, "Invalid filename");
        return;
    }

    logger.trace("Adding a file: %s", filename_sv.data());

    fs::path file_path{current_folder};
    file_path /= std::string{filename_sv};

    bool is_space = try_alloc_file(file_path, file_size);
    if (is_space)
    {
        auto[socket, port] = init_stream_conn(chrono::seconds{*so.timeout});
        workers.push_back(std::thread{receive_file, socket, std::move(file_path), (size_t)file_size});

        packet send = packet::make_cmplx(
            "CAN_ADD",
            recv_packet.cmd.get_cmd_seq(),
            ntohs(port),
            0, 0,
            recv_packet.addr);

        logger.trace_packet("Responding to", send, cmd_type::cmplx);
        send_dgram(sock, send);
    }
    else
    {
        logger.trace("Could not add a file");
        packet send = packet::make_simpl(
            "NO_WAY",
            recv_packet.cmd.get_cmd_seq(),
            (uint8 const*)filename_sv.data(),
            filename_sv.size(),
            recv_packet.addr);

        logger.trace_packet("Responding to", send, cmd_type::simpl);
        send_dgram(sock, send);
    }
}

static void handle_request_del(int sock, packet const& recv_packet)
{
    (void(sock));

    logger.trace_packet("Got", recv_packet, cmd_type::simpl);
    if (!recv_packet.cmd.contains_required_fields(cmd_type::simpl, recv_packet.msg_len)) {
        logger.pckg_error(recv_packet.addr, "DEL request too short");
        return;
    }

    if (!recv_packet.cmd.contains_data(cmd_type::simpl, recv_packet.msg_len)) {
        logger.pckg_error(recv_packet.addr, "DEL request must contain a filename");
        return;
    }

    std::string_view filename_sv = recv_packet.data_as_sv(cmd_type::simpl);

    if (!sanitize_requested_path(filename_sv)) {
        logger.pckg_error(recv_packet.addr, "Invalid filename");
        return;
    }

    logger.trace("Removing file %s", recv_packet.cmd.simpl.data);

    fs::path file_path = current_folder;
    file_path /= std::string{filename_sv};
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
    logger.trace("  SYNCHRONIZED = %s", *so.synchronized ? "true" : "false");

    // This does nothing if the directory already exists.
    try { fs::create_directories(so.shrd_fldr->c_str()); }
    catch (...) {}
    current_folder = fs::path{* so.shrd_fldr};

    index_files(* so.max_space);

    int sock;
    sockaddr_in local_address;
    ip_mreq ip_mreq;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        logger.syserr("socket");
    mcast_socket = sock;

    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(so.mcast_addr->c_str(), &ip_mreq.imr_multiaddr) == 0)
        logger.syserr("inet_aton");
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)(&ip_mreq), sizeof(ip_mreq)) < 0)
        logger.syserr("setsockopt");

    // bind to local address
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons((in_port_t)(* so.cmd_port));
    if (bind(sock, (sockaddr*)&local_address, sizeof(local_address)) < 0)
        logger.syserr("bind");

    int optval = 0;
    if (setsockopt(sock, SOL_IP, IP_MULTICAST_LOOP, (void*)&optval, sizeof(optval)) < 0)
        logger.syserr("setsockopt loop");

    // Create a sigset of all the signals that we're interested in. Also block
    // the signals in order for signalfd to receive them
    sigset_t sigset;
    if (sigemptyset(&sigset) != 0)
        logger.syserr("sigemptyset");
    if (sigaddset(&sigset, SIGINT) != 0)
        logger.syserr("sigaddset");
    if (sigprocmask(SIG_BLOCK, &sigset, nullptr) != 0)
        logger.syserr("sigprocmask");

    if (*so.synchronized)
    {
        for (auto&& entry : fs::directory_iterator(current_folder))
            if (fs::is_regular_file(entry.path()))
            {
                logger.trace("Reporting that I have %s", entry.path().filename().string().c_str());
                sync_tell_other_to_delete(sock, entry.path().filename().string().c_str());
            }
    }

    // Create the signalfd
    signal_fd = signalfd(-1, &sigset, 0);
    if (signal_fd < 0)
        logger.syserr("signalfd");

    pollfd pfd[2];
    pfd[0].fd = signal_fd;
    pfd[0].events = POLLIN | POLLERR | POLLHUP;
    pfd[1].fd = sock;
    pfd[1].events = POLLIN | POLLERR | POLLHUP;

    for (;;)
    {
        poll(pfd, 2, -1);
        packet response{};

        if (pfd[0].revents & POLLIN)
        {
            logger.trace("Got interrupt signal.");
            break;
        }

        if (pfd[1].revents & POLLIN)
        {
            response = recv_dgram(sock);
        }

        if (response.cmd.check_header("HELLO"))
            handle_request_hello(sock, response);
        else if (response.cmd.check_header("LIST"))
            handle_request_list(sock, response);
        else if (response.cmd.check_header("GET"))
            handle_request_get(sock, response);
        else if (response.cmd.check_header("ADD"))
            handle_request_add(sock, response);
        else if (response.cmd.check_header("DEL"))
            handle_request_del(sock, response);
        else
            logger.pckg_error(response.addr, nullptr);
    }

    if (*so.synchronized)
    {
        logger.println("Trying to save the files");
        sync_save_files(sock, ip_mreq.imr_multiaddr);
    }

    for (auto&& th : workers)
        th.join();

    if (setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void*)&ip_mreq, sizeof ip_mreq) < 0)
        logger.syserr("setsockopt");

    safe_close(sock);

    return 0;
}
