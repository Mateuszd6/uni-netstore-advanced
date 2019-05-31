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

// Open up TCP socket on a random port.
std::pair<int, in_port_t> init_stream_conn()
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

    return {sock, server_address.sin_port};
}

int connect_to_stream(char const* addr, char const* port, chrono::microseconds timeout)
{
    int sock;
    addrinfo addr_hints;
    addrinfo *addr_result;

    // 'converting' host/port in string to struct addrinfo
    memset(&addr_hints, 0, sizeof(addrinfo));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(addr, port, &addr_hints, &addr_result) != 0)
    {
        return -1;
    }

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

// TODO: rename, coz its used also when receiving.
constexpr static size_t send_block_size = 4096;

// Sends count bytes over tcp socket. Returns -1 on error.
ssize_t send_stream(int fd, uint8* buffer, size_t count) {
    for (size_t i = 0; i < count;) {
        ssize_t chunk_len = i + send_block_size > count ? count - i : send_block_size;
        ssize_t send_data = 0;
        send_data = write(fd, buffer + i, chunk_len);
        if (send_data == -1) {
            return -1;
        }

        i += send_data;
    }

    return count;
}

// Loads count bytes from tcp socket. Returns number of received bytes.
ssize_t recv_stream(int fd, uint8* buffer, size_t count) {
    if (count == 0)
        return 0;

    ssize_t remained = count;
    ssize_t loaded = 0;
    while (remained > 0) {
        // if read failed, return -1, the caller can check errno.
        int bytes_red = read(fd, buffer + loaded, remained);
        if (bytes_red == -1)
            return -1;

        if (bytes_red == 0) {
            return loaded;
        }

        assert(bytes_red <= remained);
        remained -= bytes_red;
        loaded += bytes_red;
    }

    return loaded;
}


void send_dgram(int sock, sockaddr_in remote_addr, uint8* data, size_t size)
{
    if (sendto(sock, data, size, 0, (sockaddr*)&remote_addr, sizeof(remote_addr)) != size)
    {
        logger.syserr("sendto");
    }
}

// TODO: recv_dgram

#endif // CONNECTION_H
