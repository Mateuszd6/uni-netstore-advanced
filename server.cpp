// TODO: Fix c headers!
#include <assert.h>
#include <arpa/inet.h>
#include <cstdint>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <optional>
namespace fs = std::filesystem;
namespace chrono = std::chrono;
using namespace std::chrono_literals;

// TODO: Move to common.
using int8 = int8_t;
using uint8 = uint8_t;
using int16 = int16_t;
using uint16 = uint16_t;
using int32 = int32_t;
using uint32 = uint32_t;
using int64 = int64_t;
using uint64 = uint64_t;

struct server_options
{
    std::optional<std::string> mcast_addr = {};
    std::optional<std::string> shrd_fldr = {};
    std::optional<int64> max_space = 52428800;
    std::optional<int32> cmd_port = {};
    std::optional<int32> timeout = 5;
};

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

// TODO: Move to utils.
constexpr static uint32 strhash(const char* str, int h = 0)
{
    // In c++17 std::hash is still not constexpr.
    return !str[h] ? 5381 : (strhash(str, h + 1) * 33) ^ str[h];
}

// NOTE: The data size limit, imposed by the underlying IPv4 protocol, is 65507
//       bytes (65535 - 8 byte UDP header - 20 byte IP header). ~Wikipedia.
constexpr size_t upd_max_data_size = 65507;
union cmd
{
    struct __attribute__((__packed__)) simpl
    {
        uint64 cmd_seq;
        char cmd[10];
        uint8 data[upd_max_data_size - 10 - sizeof(uint64)];
    };
    struct __attribute__((__packed__)) cmplx
    {
        uint64 cmd_seq;
        uint64 param;
        char cmd[10];
        uint8 data[upd_max_data_size - 10 - 2 * sizeof(uint64)];
    };
    uint8 bytes[upd_max_data_size];

    void clear()
    {
        bzero(bytes, upd_max_data_size);
    }
};

// Make sure that the cmd union is packed properly.
static_assert(sizeof(cmd::bytes) == upd_max_data_size);
static_assert(sizeof(cmd::bytes) == sizeof(cmd));
static_assert(sizeof(cmd::bytes) == sizeof(cmd::simpl));
static_assert(sizeof(cmd::bytes) == sizeof(cmd::cmplx));

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

    // If _any_ of the fields were not set it means that there is a required
    // field was not set, so we exit.
    if (!retval.mcast_addr.has_value()
        || !retval.shrd_fldr.has_value()
        || !retval.max_space.has_value()
        || !retval.cmd_port.has_value()
        || !retval.timeout.has_value())
    {
        printf("Nope\n");
        exit(1);
    }

    return retval;
}

void handle_interrput(sig_t s){
    TRACE("Got interrupt signal. Exitting safetly...\n");
    exit(1);
}

int main(int argc, char const** argv)
{
#if 1
    // TODO: This is a _TEST_
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = (void (*)(int))(handle_interrput); // TODO: Check this hack!
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);
#endif

    server_options so = parse_args(argc, argv);
    TRACE("OPTIONS:\n");
    TRACE("  MCAST_ADDR = %s\n", so.mcast_addr.value().c_str());
    TRACE("  CMD_PORT = %d\n", so.cmd_port.value());
    TRACE("  MAX_SPACE = %ld\n", so.max_space.value());
    TRACE("  SHRD_FLDR = %s\n", so.shrd_fldr.value().c_str());
    TRACE("  TIMEOUT = %d\n", so.timeout.value());

    // Create a folder if it does not exists already.
    // TODO: Check the output and fail miserably on error.
    fs::create_directories(so.shrd_fldr.value().c_str());

    int64 total_size = 0;
    for (auto&& entry : fs::directory_iterator(so.shrd_fldr.value()))
        if (entry.is_regular_file())
        {
            TRACE("%s -> %ld\n", entry.path().c_str(), entry.file_size());
            total_size += entry.file_size();
        }
    TRACE("Total size: %ld\n", total_size);
    so.max_space.value() -= total_size;
    TRACE("Space left: %ld\n", so.max_space.value());

    // SERVER STUFF: (TODO: Move away!)
    // argumenty wywołania programu
    char const* multicast_dotted_address; // TODO: Dont use, we have a string for that in so.
    in_port_t local_port;

    // zmienne i struktury opisujące gniazda
    int sock;
    struct sockaddr_in local_address, remote_address;
    struct ip_mreq ip_mreq;
    unsigned int remote_len;

    // zmienne obsługujące komunikację
    ssize_t rcv_len;
    int i;

    multicast_dotted_address = so.mcast_addr.value().c_str();
    local_port = (in_port_t)(so.cmd_port.value());

    // otworzenie gniazda
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        syserr("socket");

    // podpięcie się do grupy rozsyłania (ang. multicast)
    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(multicast_dotted_address, &ip_mreq.imr_multiaddr) == 0)
        syserr("inet_aton");
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&ip_mreq, sizeof ip_mreq) < 0)
        syserr("setsockopt");

    // podpięcie się pod lokalny adres i port
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(local_port);
    if (bind(sock, (struct sockaddr*)&local_address, sizeof local_address) < 0)
        syserr("bind");

    cmd c{};

    // czytanie tego, co odebrano
    for (;;)
    {
        c.clear(); // TODO: Probobly unndeeded, becasue of the default construction of cmd.
        rcv_len = recvfrom(sock, c.bytes, sizeof(c), 0, (struct sockaddr*)&remote_address, &remote_len);
        if (rcv_len < 0)
        {
            syserr("read");
        }
        else
        {
            printf("read %zd bytes: %.*s\n", rcv_len, (int)rcv_len, c.bytes);
            if (strcmp(reinterpret_cast<char*>(c.bytes), "GET_TIME") == 0)
            {
                char response_buf[] = "Mateusz says hello!";
                if (sendto(sock, response_buf, sizeof(response_buf), 0, (struct sockaddr*)&remote_address, remote_len) == -1)
                {
                    syserr("sendto");
                }
                else
                {
                    printf("Sent msg: %.*s\n", static_cast<int>(sizeof(response_buf)), response_buf);
                }
            }
            else
            {
                printf("Received unexpected bytes.\n");
            }
        }
    }
    // w taki sposób można odpiąć się od grupy rozsyłania
    if (setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void*)&ip_mreq, sizeof ip_mreq) < 0)
        syserr("setsockopt");

    // koniec
    close(sock);
    exit(EXIT_SUCCESS);

    return 0;
}
