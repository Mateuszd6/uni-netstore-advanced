#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <vector>
#include <string>
#include <thread>
#include <chrono>
namespace chrono = std::chrono;
using namespace std::chrono_literals;

#include "err.h"

#define BSIZE 256
#define TTL_VALUE 4
#define REPEAT_COUNT 3
#define SLEEP_TIME 5

#define PORT 10001

// TODO: Move to common.
using int8 = int8_t;
using uint8 = uint8_t;
using int16 = int16_t;
using uint16 = uint16_t;
using int32 = int32_t;
using uint32 = uint32_t;
using int64 = int64_t;
using uint64 = uint64_t;

#ifdef DEBUG
#  define TRACE(...) fprintf(stderr, __VA_ARGS__)
#else
#  define TRACE(...) (void)0
#endif

// TODO: Make it legit
#define syserr(WHY)                             \
    do {                                        \
        printf(WHY);                            \
        exit(-1);                               \
    } while (0)

// TODO: Make it legit
#define fatal(...)                              \
    do {                                        \
        printf(__VA_ARGS__);                    \
        exit(-1);                               \
    } while (0)


// TODO: Decide whether or not this stays:
timeval chrono_to_timeval(chrono::microseconds usec)
{
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

// NOTE: The data size limit, imposed by the underlying IPv4 protocol, is 65507
//       bytes (65535 - 8 byte UDP header - 20 byte IP header). ~Wikipedia.
constexpr size_t upd_max_data_size = 65507;
union cmd
{
    struct __attribute__((__packed__))
    {
        char cmd[10];
        uint64 cmd_seq;
        uint8 data[upd_max_data_size - 10 - sizeof(uint64)];
    } simpl;

    struct __attribute__((__packed__))
    {
        char cmd[10];
        uint64 cmd_seq;
        uint64 param;
        uint8 data[upd_max_data_size - 10 - 2 * sizeof(uint64)];

        uint64 get_param()
        {
            return be64toh(param);
        }

        void set_param(uint64 val)
        {
            param = htobe64(val);
        }
    } cmplx;

    uint8 bytes[upd_max_data_size];

    uint64 get_cmd_seq()
    {
        return be64toh(simpl.cmd_seq);
    }

    void set_cmd_seq(uint64 val)
    {
        simpl.cmd_seq = htobe64(val);
    }

    bool check_header(char const* head)
    {
        int32 head_len = strlen(head);

        if (memcmp(simpl.cmd, head, head_len) != 0)
            return false;

        // The rest of the header must be filled with zeros, otherwise reject.
        for (int i = head_len; i < 10; ++i)
            if (simpl.cmd[i] != 0)
                return false;

        return true;
    }

    void clear()
    {
        bzero(&bytes[0], upd_max_data_size);
    }
};

struct search_entry
{
    std::string filename;
    in_addr server_unicast_addr;
};

static std::vector<search_entry> last_search_result{};

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

int
main(int argc, char* argv[])
{
    // argumenty wywołania programu
    char* remote_dotted_address;
    in_port_t remote_port;

    // zmienne i struktury opisujące gniazda
    int sock, optval;
    //  struct sockaddr_in local_address;
    struct sockaddr_in remote_address, local_address;
    unsigned int remote_len;

    // zmienne obsługujące komunikację
    char buffer[BSIZE];
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
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (timeval*)&tv, sizeof(timeval));

    // radosne rozgłaszanie czasu
    ssize_t rcv_len;
    for (i = 0; i < REPEAT_COUNT; ++i)
    {
        printf("Sending request...\n");
        bzero(buffer, BSIZE);
        strncpy(buffer, "GET", BSIZE);
        length = strnlen(buffer, BSIZE);
        if (sendto(sock, buffer, length, 0, (sockaddr*)&remote_address, sizeof(remote_address)) != length)
            syserr("write");

        // TODO: If timeout should errno be set to ETIMEDOUT..? It returns EAGAIN!!!

        chrono::steady_clock::time_point begin = chrono::steady_clock::now();

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
            timeval tv = chrono_to_timeval(time_left);
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
#if 1
                printf("Received [CMPLX] (from %s:%d): %.*s %lu {%s}\n",
                       inet_ntoa(from_address.sin_addr),
                       htons(from_address.sin_port),
                       (int)rcv_len, response.cmplx.cmd,
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
                       (int)rcv_len, response.simpl.cmd,
                       response.simpl.data);

                // TODO: Watch out for more than one \n in a row.
                uint8 const* str = &response.simpl.data[0];
                while (*str)
                {
                    uint8 const* p = str;
                    while (*p && *p != '\n')
                        ++p;

#if 0
                    printf("ENTRY: %.*s\n", p - str, (char const*)(str));
#endif
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

        break;
    }


    // koniec
    close(sock);
    exit(EXIT_SUCCESS);
}
