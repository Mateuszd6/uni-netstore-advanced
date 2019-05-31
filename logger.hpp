#ifndef LOGGER_H
#define LOGGER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <mutex>

#include "common.hpp"
#include "cmd.hpp"

static struct {
private:
    std::mutex logger_mutex{};

public:
    void trace(char const* fmt, ...) {
        std::lock_guard<std::mutex> m{logger_mutex};

        va_list args;
        va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        va_end(args);
        fprintf(stdout, "\n");
    }

    void trace_packet(char const* description, send_packet const& packet, cmd_type type) {
        std::lock_guard<std::mutex> m{logger_mutex};

        fprintf(stdout, "%s %s:%d: [%s] ",
                description,
                inet_ntoa(packet.from_addr.sin_addr),
                htons(packet.from_addr.sin_port),
                type == cmd_type::simpl ? "SIMPL" : "CMPLX");

        if (type == cmd_type::simpl)
        {
            fprintf(stdout, "{%.*s %lu \"%s\"}\n",
                    10, packet.cmd.head,
                    packet.cmd.get_cmd_seq(),
                    packet.cmd.simpl.get_data());
        }
        else
        {
            fprintf(stdout, "{%.*s %lu %lu \"%s\"}\n",
                    10, packet.cmd.head,
                    packet.cmd.get_cmd_seq(),
                    packet.cmd.cmplx.get_param(),
                    packet.cmd.cmplx.get_data());
        }
    }

    void println(char const* fmt, ...) {
        std::lock_guard<std::mutex> m{logger_mutex};

        va_list args;
        fprintf(stdout, "\033[1;35m");
        va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        va_end(args);
        fprintf(stdout, "\033[0m");
        fprintf(stdout, "\n");
    }

    void syserr(char const* fmt, ...) {
        std::lock_guard<std::mutex> m{logger_mutex};

        va_list args;
        fprintf(stderr, "\033[1;31m");
        fprintf(stderr, "ERROR: ");
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);

        if (errno != 0)
            fprintf(stderr, " Errno: %d(%s)", errno, strerror(errno));
        fprintf(stderr, "\033[0m");
        fprintf(stderr, "\n");

        exit(2); // TODO: Use safe exit function!
    }

    void fatal(char const* fmt, ...) {
        std::lock_guard<std::mutex> m{logger_mutex};

        va_list args;
        fprintf(stderr, "\033[1;31m");
        fprintf(stderr, "ERROR: ");
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, "\033[0m");
        fprintf(stderr, "\n");

        exit(1); // TODO: Use safe exit function!
    }

    void pckg_error(sockaddr_in const& addr, char const* reason) {
        std::lock_guard<std::mutex> m{logger_mutex};

        std::string sender_ip{inet_ntoa(addr.sin_addr)}; // TODO: THIS CAN FAIL!
        uint32 sender_port = htons(addr.sin_port);
        fprintf(stderr, "\033[1;31m");
        fprintf(stderr, "[PCKG ERROR] Skipping invalid package from %s:%u. %s",
                sender_ip.c_str(),
                sender_port,
                reason ? reason : "");
        fprintf(stderr, "\033[0m");
        fprintf(stderr, "\n");
    }
} logger;

#endif // LOGGER_H
