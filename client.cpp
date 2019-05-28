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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <vector>
#include <random>
#include <string>
#include <thread>
#include <chrono>
namespace chrono = std::chrono;
using namespace std::chrono_literals;

#include "common.hpp"
#include "cmd.hpp"

#define TTL_VALUE 4

// TODO: Decide whether or not this stays. TODO: Templetize with duration.

template<typename DUR>
timeval chrono_to_posix(DUR duration)
{
    chrono::microseconds usec = duration;
    timeval retval;
    if (usec <= chrono::microseconds(0))
    {
        retval.tv_sec = retval.tv_usec = 0;
    }
    else
    {
        retval.tv_sec = usec.count() / 1000000;
        retval.tv_usec = usec.count() % 1000000;
    }

    return retval;
}

struct search_entry
{
    std::string filename;
    in_addr server_unicast_addr;
};

struct available_server
{
    in_addr uaddr;
    in_addr maddr;
    size_t free_space;
};

std::mt19937_64 rngen{std::random_device()()};


static std::vector<search_entry> last_search_result{};
static std::vector<available_server> available_servers{};

void send_file_over_tcp(char const* addr, char const* port)
{
    int sock;
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;

    int err, seq_no = 0, number;

    // 'converting' host/port in string to struct addrinfo
    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = AF_INET; // IPv4
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;
    err = getaddrinfo(addr, port, &addr_hints, &addr_result);
    if (err == EAI_SYSTEM) // system error
        syserr("getaddrinfo");
    else if (err != 0) // other error (host not found, etc.)
        fatal("getaddrinfo");

    // initialize socket according to getaddrinfo results
    sock = socket(addr_result->ai_family, addr_result->ai_socktype, addr_result->ai_protocol);
    if (sock < 0)
        syserr("socket");

    // connect socket to the server
    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) < 0)
        syserr("connect");

    freeaddrinfo(addr_result);

    // we send numbers in network byte order
    char buffer[1024];
    ssize_t len = sizeof("Hello darkness my old friend") - 1;
    bzero(buffer, 1024);
    memcpy(buffer, "Hello darkness my old friend", len);

    if (write(sock, &buffer, len) != len)
        syserr("partial / failed write");

    if (close(sock) < 0) // socket would be closed anyway when the program ends
        syserr("close");
}

static void send_request_hello(int sock, sockaddr remote_addr, size_t remote_addr_len)
{
    auto[request, size] = cmd::make_simpl("HELLO", rngen(), nullptr, 0);
    if (sendto(sock, request.bytes, size, 0,
               (sockaddr*)&remote_addr, remote_addr_len) != size)
    {
        syserr("sendto");
    }
}

static void send_request_list(int sock,
                              sockaddr remote_addr,
                              size_t remote_addr_len,
                              std::string const& filter)
{
    auto[request, size] = cmd::make_simpl("LIST",
                                          rngen(),
                                          (uint8 const*)filter.c_str(),
                                          filter.size());

    if (sendto(sock, request.bytes, size, 0,
               (sockaddr*)&remote_addr, remote_addr_len) != size)
    {
        syserr("sendto");
    }
}

static void handle_response_hello(int sock,
                                  cmd const& response,
                                  sockaddr_in from_addr,
                                  size_t from_addr_len)
{
    printf("_ Received [CMPLX] (from %s:%d): %lu %.*s {%s}\n",
           inet_ntoa(from_addr.sin_addr),
           htons(from_addr.sin_port),
           response.cmplx.get_param(),
           10, response.head,
           response.cmplx.get_data());

    in_addr mcast_addr;
    if (inet_aton((char const*)response.cmplx.get_data(), &mcast_addr) == 0)
    {
        syserr("inet_aton");
    }

    available_servers.emplace_back(
        available_server{from_addr.sin_addr,
                         mcast_addr,
                         response.cmplx.get_param()});
}

static void handle_response_list(int sock,
                                  cmd const& response,
                                  sockaddr_in from_addr,
                                  size_t from_addr_len)
{
    printf("_ Received [SIMPL] (from %s:%d): %.*s {%s}\n",
           inet_ntoa(from_addr.sin_addr),
           htons(from_addr.sin_port),
           10, response.head,
           response.simpl.get_data());

    // TODO: Watch out for more than one \n in a row.
    uint8 const* str = &response.simpl.data[0];
    while (*str)
    {
        uint8 const* p = str;
        while (*p && *p != '\n')
            ++p;

        last_search_result.emplace_back(
            search_entry{std::string{(char const*)str, (size_t)(p - str)},
                         from_addr.sin_addr});

        if (*p == '\n')
            ++p;
        str = p;
    }
}

// functor is executed every time we've got a packet. The only arg is the cmd
// strucutre for the packet. Packets with different cmd_seq or different head
// than specified will be ignored and reported.
template<typename FUNC>
static void await_responses(int sock,
                            char const* expected_head,
                            uint64_t expected_cmd_seq,
                            FUNC functor)
{
    // TODO: If timeout should errno be set to ETIMEDOUT..? It returns EAGAIN!!!
    auto timeout = 2s;
    auto timestamp = chrono::steady_clock::now();
    for (;;)
    {
        cmd response{};
        struct sockaddr_in from_addr;
        uint32 from_addr_len = sizeof(from_addr);

        // TODO: This way of doing this is probably very bad and inaccurate
        chrono::microseconds time_left =
            timeout - chrono::duration_cast<chrono::microseconds>(chrono::steady_clock::now() - timestamp);
        printf("Time left: %ld\n", time_left.count());
        if (time_left < 0us)
            break;

        // Set the timeout to whatever its left.
        timeval tv = chrono_to_posix(time_left);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));

        ssize_t rcv_len = recvfrom(sock, response.bytes, sizeof(response.bytes), 0,
                                   (sockaddr*)&from_addr, &from_addr_len);

        auto time_diff = chrono::duration_cast<chrono::microseconds>(
            chrono::steady_clock::now() - timestamp);

        // If there was an error:
        if (rcv_len < 0 && errno != EAGAIN)
        {
            printf("Error: %s(%d)\n", strerror(errno), errno);
            printf("Closing!\n");
            close(sock);
            exit(1);
        }
        else if (rcv_len == 0) // TODO: Socket has been closed (How do we
                               // even get here when mutlicasting)?
        {
            printf("NO IDEA WHAT IS HAPPENING!!!!\n");
            exit(1);
        }
        else if (rcv_len > 0 &&
                 (!response.check_header(expected_head) || response.get_cmd_seq() != expected_cmd_seq))
        {
            // We've received packed, that we were not expecting.
            printf("Unexpected packet received\n");
        }
        else if (rcv_len > 0)
        {
            printf("Time difference: %lu\n", time_diff.count());
            functor(sock, response, from_addr, from_addr_len);
        }
        else if (time_diff > timeout)
        {
            printf("Timeout has been reached. Ending...\n");
            break;
        }
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
        fatal("Usage: %s remote_address remote_port\n", argv[0]);

    remote_dotted_address = argv[1];
    remote_port = (in_port_t)atoi(argv[2]);

    // otworzenie gniazda
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        syserr("socket");

    // uaktywnienie rozgłaszania (ang. broadcast)
    optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void*)&optval, sizeof optval) < 0)
        syserr("setsockopt broadcast");

    // ustawienie TTL dla datagramów rozsyłanych do grupy
    optval = TTL_VALUE;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void*)&optval, sizeof optval) < 0)
        syserr("setsockopt multicast ttl");

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
        syserr("bind");

    // ustawienie adresu i portu odbiorcy
    remote_address.sin_family = AF_INET;
    remote_address.sin_port = htons(remote_port);
    if (inet_aton(remote_dotted_address, &remote_address.sin_addr) == 0)
        syserr("inet_aton");

    // ustawienie timeoutu
    timeval tv = chrono_to_posix(5s);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));

    // --
    {
        auto[request, size] = cmd::make_simpl("HELLO", 2, 0, 0);
        printf("Sending request...\n");
        if (sendto(sock, request.bytes, size, 0, (sockaddr*)&remote_address, sizeof(remote_address)) != size)
        {
            syserr("sendto");
        }
        available_servers.clear();
        await_responses(sock, "GOOD_DAY", 2, handle_response_hello);
        for (auto&& i : available_servers)
        {
            printf("\033[1;32m");
            std::string uaddr = inet_ntoa(i.uaddr);
            std::string maddr = inet_ntoa(i.maddr);
            printf("Found %s (%s) with free space %lu\n", uaddr.c_str(), maddr.c_str(), i.free_space);
            printf("\033[0m");
        }
    }
    // --

    // --
    {
        char const* filter = ".o";
        auto[request, size] = cmd::make_simpl("LIST", 3, (uint8*)filter, strlen(filter));
        printf("Sending request...\n");
        if (sendto(sock, request.bytes, size, 0, (sockaddr*)&remote_address, sizeof(remote_address)) != size)
        {
            syserr("sendto");
        }
        last_search_result.clear();
        await_responses(sock, "MY_LIST", 3, handle_response_list);

        printf("\033[1;32m");
        for (auto&& i : last_search_result)
            printf("%s (%s)\n", i.filename.c_str(), inet_ntoa(i.server_unicast_addr));
        printf("\033[0m");
    }
    // --


#if 0
    // TODO: If timeout should errno be set to ETIMEDOUT..? It returns EAGAIN!!!

    chrono::steady_clock::time_point begin = chrono::steady_clock::now();
    ssize_t rcv_len;
    auto timeout = 2s;
    auto timestamp = chrono::steady_clock::now();
    for (;;)
    {
        cmd response{};

        struct sockaddr_in from_address;
        uint32 from_len = sizeof(struct sockaddr_in);

        // TODO: This way of doing this is probably very bad and inaccurate
        chrono::microseconds time_left =
            timeout - chrono::duration_cast<chrono::microseconds>(chrono::steady_clock::now() - timestamp);
        printf("Time left: %lu\n", time_left.count());
        timeval tv = chrono_to_posix(time_left);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));

        rcv_len = recvfrom(sock, response.bytes, sizeof(response.bytes), 0,
                           (sockaddr*)&from_address, &from_len);

        auto time_diff = chrono::duration_cast<chrono::milliseconds>(
            chrono::steady_clock::now() - timestamp);

        // If there was en error:
        if (rcv_len < 0 && errno != EAGAIN)
        {
            printf("Error: %s(%d)\n", strerror(errno), errno);
            printf("Closing!\n");
            close(sock);
            exit(1);
        }
        else if (rcv_len == 0) // TODO: Socket has been closed (How do we
            // even get here when mutlicasting)?
        {
            exit(1);
        }
        else if (rcv_len > 0)
        {
            printf("Time difference: %lu\n", time_diff.count());
#if 0
            printf("Received [CMPLX] (from %s:%d): %.*s %lu {%s}\n",
                   inet_ntoa(from_address.sin_addr),
                   htons(from_address.sin_port),
                   (int)rcv_len, response.head,
                   response.cmplx.get_param(),
                   response.cmplx.data);

            char port_buffer[32];
            sprintf(port_buffer, "%lu", response.cmplx.get_param());
            printf("Sending to %s:%lu\n", inet_ntoa(from_address.sin_addr), response.cmplx.get_param());
            send_file_over_tcp(inet_ntoa(from_address.sin_addr), port_buffer);

            fprintf(stderr, "Send succeeded\n");
#else
            printf("Received [SIMPL] (from %s:%d): %.*s {%s}\n",
                   inet_ntoa(from_address.sin_addr),
                   htons(from_address.sin_port),
                   (int)rcv_len, response.head,
                   response.simpl.data);

            // TODO: Watch out for more than one \n in a row.
            uint8 const* str = &response.simpl.data[0];
            while (*str)
            {
                uint8 const* p = str;
                while (*p && *p != '\n')
                    ++p;

                last_search_result.emplace_back(
                    search_entry{std::string{(char const*)str, (size_t)(p - str)},
                                 from_address.sin_addr});

                if (*p == '\n')
                    ++p;
                str = p;
            }
#endif
        }
        else if (errno == EAGAIN && time_diff > timeout)
        {
            printf("Timeout has been reached. Ending...\n");
            break;
        }
    }
    printf("\033[1;32m");
    for(auto&& i : last_search_result)
        printf("%s (%s)\n", i.filename.c_str(), inet_ntoa(i.server_unicast_addr));
    printf("\033[0m");

    // TODO: Make sure that the timeout is correct.
    chrono::steady_clock::time_point end = chrono::steady_clock::now();
    printf("Time diff: %lu\n", chrono::duration_cast<chrono::milliseconds>(end - begin).count());
#endif



    // koniec
    close(sock);
    exit(EXIT_SUCCESS);
}
