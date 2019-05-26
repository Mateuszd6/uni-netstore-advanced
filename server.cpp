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
    struct __attribute__((__packed__))
    {
        char head[10];
        uint64 cmd_seq;

        union {
            struct __attribute__((__packed__))
            {
                uint8 data[upd_max_data_size - 10 - sizeof(uint64)];
            } simpl;

            struct __attribute__((__packed__))
            {
                uint64 param;
                uint8 data[upd_max_data_size - 10 - 2 * sizeof(uint64)];

                // Param property is only related to the cmplx part of the cmd,
                // so we have to invoke it explicitly refering to it, so that it
                // minimizes missuse chances.
                uint64 get_param()
                {
                    return be64toh(param);
                }

                void set_param(uint64 val)
                {
                    param = htobe64(val);
                }
            } cmplx;
        };
    };

    uint8 bytes[upd_max_data_size];

    char const* get_head()
    {
        return &(head[0]);
    }

    void set_head(char const* val)
    {
        int32 val_len = strlen(val);
        assert(val_len <= 10);

        bzero(head, 10);
        memcpy(head, val, strlen(val));
    }

    uint64 get_cmd_seq()
    {
        return be64toh(cmd_seq);
    }

    void set_cmd_seq(uint64 val)
    {
        cmd_seq = htobe64(val);
    }

    bool check_header(char const* usr_head)
    {
        int32 usr_head_len = strlen(head);
        assert(usr_head_len <= 10);

        if (memcmp(head, usr_head, usr_head_len) != 0)
            return false;

        // The rest of the header must be filled with zeros, otherwise reject.
        for (int i = usr_head_len; i < 10; ++i)
            if (head[i] != 0)
                return false;

        return true;
    }

    void clear()
    {
        bzero(&bytes[0], upd_max_data_size);
    }
};

// Make sure that the cmd union is packed properly.
#if 1
static_assert(sizeof(cmd::bytes) == upd_max_data_size);
static_assert(sizeof(cmd::bytes) == sizeof(cmd));
static_assert(sizeof(cmd::bytes) == 10 + sizeof(uint64) + sizeof(cmd::simpl));
static_assert(sizeof(cmd::bytes) == 10 + sizeof(uint64) + sizeof(cmd::cmplx));
#endif

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
        c.clear(); // TODO: Probably unndeeded, becasue of the default construction of cmd.
        rcv_len = recvfrom(sock, c.bytes, sizeof(c), 0, (struct sockaddr*)&remote_address, &remote_len);
        if (rcv_len < 0)
        {
            syserr("read");
        }
        else
        {
            printf("read %zd bytes: %.*s\n", rcv_len, (int)rcv_len, c.bytes);

            if (c.check_header("HELLO"))
            {
                // TODO: Make sure that DATA is empty!
                printf("Received msg: HELLO\n");

                cmd response{};
                response.clear(); // TODO: Probably unndeeded, becasue of the default construction of cmd.
                // TODO: Cmd_seq!!!
                response.set_head("GOOD_DAY");
                response.cmplx.set_param(so.max_space.value());
                memcpy(response.cmplx.data, so.mcast_addr.value().c_str(), so.mcast_addr.value().size());

                printf("Responding to: %s:%d\n",
                       inet_ntoa(remote_address.sin_addr),
                       htons(remote_address.sin_port));
                if (sendto(sock, response.bytes, sizeof(response), 0, (struct sockaddr*)&remote_address, remote_len) == -1)
                    syserr("sendto");
                else
                    printf("Sent msg: [%.*s]\n", 10, response.head);
            }
            else if (c.check_header("LIST"))
            {
                // TODO: Make sure that DATA is empty!
                printf("Received msg: LIST\n");
                cmd response{};
                response.clear(); // TODO: Probably unndeeded, becasue of the default construction of cmd.
                // TODO: Cmd_seq!!!
                response.set_head("MY_LIST");

                std::string filenames{}; // TODO: Figure out how many bytes its good to reserve
                for (auto&& entry : fs::directory_iterator(so.shrd_fldr.value()))
                    if (entry.is_regular_file())
                    {
                        TRACE("%s -> %ld\n", entry.path().c_str(), entry.file_size());

                        if (filenames.size() > 0)
                            filenames.append("\n");
                        filenames.append(entry.path().filename().c_str());
                    }

                // TODO: Handle the case, when these are greater.
                assert(filenames.size() <= sizeof(cmd::simpl));
                printf("Filenames: {%s}\n", filenames.c_str());
                memcpy(response.simpl.data, filenames.c_str(), filenames.size());

                printf("Responding to: %s:%d\n",
                       inet_ntoa(remote_address.sin_addr),
                       htons(remote_address.sin_port));

                if (sendto(sock, response.bytes, sizeof(response), 0, (struct sockaddr*)&remote_address, remote_len) == -1)
                    syserr("sendto");
                else
                    printf("Sent msg: [%.*s]\n", 10, response.head);
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
