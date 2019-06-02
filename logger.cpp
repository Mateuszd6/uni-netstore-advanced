#include "logger.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

void logger_t::trace(char const* fmt, ...) {
    (void(fmt));
#ifdef TRACE
    std::lock_guard<std::mutex> m{logger_mutex};

    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
#endif
}

void logger_t::trace_packet(char const* description,
                            packet const& packet,
                            cmd_type type)
{
    (void(description));
    (void(packet));
    (void(type));

#ifdef TRACE
    std::lock_guard<std::mutex> m{logger_mutex};

    fprintf(stdout, "%s %s:%d: [%s] ",
            description,
            inet_ntoa(packet.addr.sin_addr),
            htons(packet.addr.sin_port),
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
#endif
}

void logger_t::println(char const* fmt, ...)
{
    std::lock_guard<std::mutex> m{logger_mutex};

    va_list args;
    // fprintf(stdout, "\033[1;35m");
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    // fprintf(stdout, "\033[0m");
    fprintf(stdout, "\n");
}

[[noreturn]]
void logger_t::syserr(char const* fmt, ...)
{
    std::lock_guard<std::mutex> m{logger_mutex};

    va_list args;
    // fprintf(stderr, "\033[1;31m");
    fprintf(stderr, "ERROR: ");
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    if (errno != 0)
        fprintf(stderr, " Errno: %d(%s)", errno, strerror(errno));
    // fprintf(stderr, "\033[0m");
    fprintf(stderr, "\n");

    exit(2);
}

[[noreturn]]
void logger_t::fatal(char const* fmt, ...)
{
    std::lock_guard<std::mutex> m{logger_mutex};

    va_list args;
    // fprintf(stderr, "\033[1;31m");
    fprintf(stderr, "ERROR: ");
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    // fprintf(stderr, "\033[0m");
    fprintf(stderr, "\n");

    exit(1);
}

void logger_t::pckg_error(sockaddr_in const& addr, char const* reason)
{
    std::lock_guard<std::mutex> m{logger_mutex};

    std::string sender_ip{inet_ntoa(addr.sin_addr)}; // TODO: THIS CAN FAIL!
    uint32 sender_port = htons(addr.sin_port);
    // fprintf(stderr, "\033[1;31m");
    fprintf(stderr, "[PCKG ERROR] Skipping invalid package from %s:%u. %s",
            sender_ip.c_str(),
            sender_port,
            reason ? reason : "");
    // fprintf(stderr, "\033[0m");
    fprintf(stderr, "\n");
}

logger_t logger;
