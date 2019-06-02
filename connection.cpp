#include "connection.hpp"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <sys/signalfd.h>

// Since inet_ntoa returns a pointer to the buffer, which content is replaced
// with another call, we must sync the inet_ntoa calls. After the call we copy
// the result and return as std::string.
static std::mutex ntoa_mutex{};

void safe_close(int sock)
{
    if (close(sock) < 0)
        logger.syserr("close");
}

std::optional<in_addr> string_to_addr(std::string const& str)
{
    in_addr retval;
    if (inet_aton(str.c_str(), &retval) == 0)
        return {};

    return retval;
}

std::string addr_to_string(in_addr addr)
{
    std::lock_guard<std::mutex> m{ntoa_mutex};
    std::string retval = inet_ntoa(addr);
    return retval;
}

// Open up TCP socket on a random port.
std::pair<int, in_port_t> init_stream_conn(chrono::seconds timeout)
{
    int sock;
    struct sockaddr_in server_address;
    socklen_t server_address_len = sizeof(server_address);

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        logger.syserr("socket");

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(0);

    if (bind(sock, (sockaddr *)(&server_address), sizeof(server_address)) < 0)
        logger.syserr("bind");

    // As passing 0 to sin_port got us random port, bind does not set this in
    // the server_address struct, and we have to get it manually by getsockname.
    if (getsockname(sock, (sockaddr *)(&server_address), &server_address_len) < 0)
        logger.syserr("getsockname");

    // switch to listening (passive open)
    if (listen(sock, 5) < 0)
        logger.syserr("listen");

    timeval tv = chrono_to_posix(timeout);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (timeval*)&tv, sizeof(timeval));

    logger.trace("Listening on port %hu", ntohs(server_address.sin_port));
    return {sock, server_address.sin_port};
}

int connect_to_stream(std::string const& addr,
                      std::string const& port,
                      chrono::microseconds timeout)
{
    int sock;
    addrinfo addr_hints;
    addrinfo *addr_result;

    // 'converting' host/port in string to struct addrinfo
    memset(&addr_hints, 0, sizeof(addrinfo));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(addr.c_str(), port.c_str(), &addr_hints, &addr_result) != 0)
        return -1;

    // initialize socket according to getaddrinfo results
    sock = socket(addr_result->ai_family, addr_result->ai_socktype, addr_result->ai_protocol);
    if (sock < 0)
    {
        logger.trace("creating a socket failed");
        freeaddrinfo(addr_result);
        return -1;
    }

    timeval tv = chrono_to_posix(timeout);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (timeval*)&tv, sizeof(timeval));

    // connect socket to the server
    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) < 0)
    {
        logger.trace("connect failed");
        freeaddrinfo(addr_result);
        safe_close(sock);
        return -1;
    }

    freeaddrinfo(addr_result);
    return sock;
}

int accept_client_stream(int sock, chrono::seconds timeout)
{
    int msg_sock;
    sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // get client connection from the socket
    msg_sock = accept(sock, (sockaddr *)(&client_addr), &client_addr_len);
    if (msg_sock < 0)
    {
        if (errno == EAGAIN)
            logger.trace("Timeout while waiting for client to connect");
        else
            logger.syserr("accept");

        return -1;
    }

    // Now we have to set read timeout independently from the sock timeout.
    timeval tv = chrono_to_posix(timeout);
    setsockopt(msg_sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));
    setsockopt(msg_sock, SOL_SOCKET, SO_SNDTIMEO, (timeval*)&tv, sizeof(timeval));
    return msg_sock;
}

// Sends count bytes over tcp socket. Returns -1 on error.
ssize_t send_stream(int sock, uint8* buffer, size_t count, int signal_fd) {
    for (size_t i = 0; i < count;) {
        pollfd pfd[2];
        pfd[0].fd = signal_fd;
        pfd[0].events = POLLIN | POLLERR | POLLHUP;
        pfd[1].fd = sock;
        pfd[1].events = POLLOUT | POLLERR | POLLHUP;

        poll(pfd, 2, -1);
        if (pfd[0].revents & POLLIN)
        {
            errno = ECONNABORTED;
            return -1;
        }

        if (pfd[1].revents & POLLOUT)
        {
            ssize_t chunk_len = i + send_block_size > count ? count - i : send_block_size;
            ssize_t send_data = 0;
            send_data = send(sock, buffer + i, chunk_len, MSG_NOSIGNAL); // Dont receive SIGPIPE
            if (send_data == -1) {
                return -1;
            }

            i += send_data;
        }
    }

    return count;
}

// fs_mutex is a mutex that sycns threads access to filesystem. This fucntion
// waits of recv, but if anything is written to singal_fd immediently aborts.
std::pair<bool, std::string>
recv_file_stream(int sock,
                 fs::path out_file_path,
                 std::optional<size_t> expected_size,
                 int signal_fd)
{
    std::vector<uint8> file_content{};
    file_content.reserve(4096);
    uint8 buffer[send_block_size];
    ssize_t len = 0;
    size_t len_total = 0;

    FILE* output_file_hndl;
    if (!(output_file_hndl = fopen(out_file_path.c_str(), "w+")))
    {
        logger.trace("Error opening file %s", out_file_path.c_str());
        return {false, "Could not create a file"};
    }

    pollfd pfd[2];
    pfd[0].fd = signal_fd;
    pfd[0].events = POLLIN | POLLERR | POLLHUP;
    pfd[1].fd = sock;
    pfd[1].events = POLLIN | POLLERR | POLLHUP;

    for (;;)
    {
        poll(pfd, 2, -1);
        if (pfd[0].revents & POLLIN)
            return {false, "Interrupted"};

        if (pfd[1].revents & POLLIN)
            len = recv(sock, buffer, send_block_size, 0);

        if (len <= 0 || (expected_size && len > expected_size))
            break;

        ssize_t write_result = fwrite(buffer, len, 1, output_file_hndl);
        if (write_result <= 0) {
            // A filesystem error. Somebody removed a file or something.
            fclose(output_file_hndl);
            return {false, "Write error"};
        }

        len_total += len;
    }

    fclose(output_file_hndl);

    if (len < 0)
    {
        if (errno == EAGAIN)
            return {false, "Timeout"};
        else
            return {false, "Error while reading the socket"};
    }

    if (expected_size && len_total != *expected_size)
    {
        logger.trace("Invalid size, got: %lu, expected: %lu", len_total, *expected_size);
        return {false, "File size does not match expectation"};
    }

    return {true, ""};
}

void send_dgram(int sock, packet const& packet)
{
    ssize_t sent = sendto(sock, packet.cmd.bytes, packet.msg_len, 0, (sockaddr const*)(&packet.addr), sizeof(packet.addr));
    if (sent != packet.msg_len)
    {
        if (errno == EAGAIN)
            logger.trace("Didn't send packet because of timeout.");
        else
            logger.syserr("sendto");
    }
}

packet recv_dgram(int sock)
{
    packet retval{};
    ssize_t rcv_len = recvfrom(sock, retval.cmd.bytes, sizeof(retval.cmd.bytes), 0,
                               (sockaddr*)&retval.addr, &retval.addr_len);
    retval.msg_len = rcv_len;

    if (rcv_len < 0)
    {
        if (errno == EAGAIN)
            logger.trace("Didn't send packet because of timeout.");
        else
            logger.syserr("sendto");
   }

    return retval;
}

std::pair<bool, std::string> stream_file(int sock, fs::path file_path, int signal_fd)
{
    uint8 buffer[send_block_size];
    FILE* f = fopen(file_path.string().c_str(), "r");
    size_t read;

    while ((read = fread(buffer, 1, send_block_size, f)) > 0)
    {
        ssize_t sent = send_stream(sock, buffer, read, signal_fd);
        if (sent == -1)
        {
            if (errno == EAGAIN)
                return {false, "Tiemout while sending the file"};
            else if (errno == ECONNABORTED)
                return {false, "Connection aborted"};
            else
                return {false, "Error while sending the file"};
        }
    }

    if (errno) // Read error.
        return {false, "Error while sending the file"};

    return {true, ""};
}
