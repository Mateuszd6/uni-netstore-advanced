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
#include <time.h>
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
struct simpl_cmd
{
    union
    {
        struct
        {
            char cmd[10];
            uint64 cmd_seq;
            uint8 data[upd_max_data_size - 10 - sizeof(uint64)];
        };
        uint8 bytes[upd_max_data_size];
    };
};

struct cmplx_cmd
{
    union
    {
        struct
        {
            char cmd[10];
            uint64 cmd_seq;
            uint64 param;
            uint8 data[upd_max_data_size - 10 - 2 * sizeof(uint64)];
        };
        uint8 bytes[upd_max_data_size];
    };
};

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
    TRACE("  MAX_SPACE = %d\n", so.max_space.value());
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

    // zmienne i struktury opisujące gniazda
    int sock;
    struct sockaddr_in local_address;
    struct ip_mreq ip_mreq;
    char buffer[1024];
    ssize_t rcv_len;
    int i;

    // otworzenie gniazda
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        syserr("socket");
    }

    // podpięcie się do grupy rozsyłania (ang. multicast)
    ip_mreq.imr_multiaddr.s_addr = inet_addr(so.mcast_addr.value().c_str());
    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(so.mcast_addr.value().c_str(), &ip_mreq.imr_multiaddr) == 0)
    {
        syserr("inet_aton");
    }

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&ip_mreq, sizeof ip_mreq) < 0)
    {
        syserr("setsockopt");
    }

    TRACE("I'VE REACHED HERE!\n");

    // podpięcie się pod lokalny adres i port
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY); // inet_addr(so.mcast_addr.value().c_str()); // ;
    local_address.sin_port = htons(static_cast<in_port_t>(so.cmd_port.value()));
    if (bind(sock, (struct sockaddr *)&local_address, sizeof local_address) < 0)
    {
        syserr("bind");
    }

    TRACE("I'M BINDED TO: %s:%d!\n", inet_ntoa(local_address.sin_addr), htons(local_address.sin_port));

    // TODO: Here I have a fd (socket) from which i can read the stuff.

    // czytanie tego, co odebrano
    for (;;)
    {
        // TODO: Figure out how this stuff works
        simpl_cmd cmd;
#if 0
        ssize_t rcv_len = read(sock, cmd.bytes, sizeof(simpl_cmd));
#else
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(struct sockaddr_in);
        char buf[1024];
        memset(buf, 0x00, 1024);
        ssize_t rcv_len = recvfrom(sock, cmd.bytes, sizeof(simpl_cmd), 0,
                                   (struct sockaddr *)&from, &fromlen);
#endif
        if (rcv_len < 0)
        {
            syserr("read");
        }
        else
        {
            TRACE("read %zd bytes (from %s:%d) %.*s\n",
                  rcv_len, inet_ntoa(from.sin_addr), from.sin_port, rcv_len, buf);

            char const* msg = "Mateusz___";
	    
            write(sock, msg, 1);
        }
    }

    // w taki sposób można odpiąć się od grupy rozsyłania
    if (setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void*)&ip_mreq, sizeof ip_mreq) < 0)
        syserr("setsockopt");

    return 0;
}
