#ifndef CONNECTION_H
#define CONNECTION_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "common.cpp"
#include "logger.hpp"

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

// Since inet_ntoa returns a pointer to the buffer, which content is replaced
// with another call, we must sync the inet_ntoa calls. After the call we copy
// the result and return as std::string.
static std::mutex ntoa_mutex{};

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

constexpr static size_t send_block_size = 4096;

// Sends count bytes over tcp socket. Returns -1 on error.
ssize_t send_stream(int fd, uint8* buffer, size_t count) {
    for (size_t i = 0; i < count;) {
        ssize_t chunk_len = i + send_block_size > count ? count - i : send_block_size;
        ssize_t send_data = 0;
        send_data = send(fd, buffer + i, chunk_len, MSG_NOSIGNAL); // Dont receive SIGPIPE
        if (send_data == -1) {
            return -1;
        }

        i += send_data;
    }

    return count;
}

// fs_mutex is a mutex that sycns threads access to filesystem.
std::pair<bool, std::string>
recv_file_stream(int sock,
                 fs::path out_file_path,
                 std::optional<size_t> expected_size,
                 std::mutex& fs_mutex,
                 int signal_fd)
{
    std::vector<uint8> file_content;
    uint8 buffer[send_block_size];
    ssize_t len;

    struct pollfd pfd[2];
    pfd[0].fd = signal_fd;
    pfd[0].events = POLLIN | POLLERR | POLLHUP;
    pfd[1].fd = sock;
    pfd[1].events = POLLIN | POLLERR | POLLHUP;

    for (;;)
    {
        logger.trace("Doing poll");
        poll(pfd, 2, -1);
        if (pfd[0].revents & POLLIN)
        {
            logger.trace("Thread interrupted.");
            return {false, "Interrupted"};
        }

        if (pfd[1].revents & POLLIN)
        {
            len = recv(sock, buffer, send_block_size, 0);
        }

        if (len <= 0 || (expected_size && len > expected_size))
            break;

        logger.trace("Got %lu bytes", len);
        std::copy(buffer, buffer + len, std::back_inserter(file_content));
    }

    if (len < 0)
    {
        if (errno == EAGAIN)
            return {false, "Timeout"};
        else
            return {false, "Error while reading the socket"};
    }

    if (expected_size && file_content.size() != *expected_size)
        return {false, "File size does not match expectation"};

    std::lock_guard<std::mutex> m{fs_mutex};
    FILE* output_file_hndl;
    if (!(output_file_hndl = fopen(out_file_path.c_str(), "w+")))
        return {false, "Could not create a file"};

    fwrite(file_content.data(), file_content.size(), 1, output_file_hndl);
    fclose(output_file_hndl);
    return {true, ""};
}

void send_dgram(int sock, sockaddr_in remote_addr, uint8* data, size_t size)
{
    if (sendto(sock, data, size, 0, (sockaddr*)&remote_addr, sizeof(remote_addr)) != size)
        logger.trace("failed to send data");
}

// TODO: recv_dgram

#endif // CONNECTION_H
