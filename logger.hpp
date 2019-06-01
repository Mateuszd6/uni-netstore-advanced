#ifndef LOGGER_H
#define LOGGER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <mutex>

#include "common.hpp"
#include "cmd.hpp"

struct logger_t {
private:
    std::mutex logger_mutex{};

public:
    void trace(char const* fmt, ...);

    void trace_packet(char const* description, packet const& packet, cmd_type type);

    void println(char const* fmt, ...);

    [[noreturn]]
    void syserr(char const* fmt, ...);

    [[noreturn]]
    void fatal(char const* fmt, ...);

    void pckg_error(sockaddr_in const& addr, char const* reason);
};

extern logger_t logger;

#endif // LOGGER_H
