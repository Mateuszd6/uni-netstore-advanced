// TODO: Fix c headers!
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <thread>
#include <chrono>
#include <filesystem>
#include <optional>
namespace fs = std::filesystem;
namespace chrono = std::chrono;
using namespace std::chrono_literals;

#include "common.hpp"
#include "cmd.hpp"

struct server_options
{
    std::optional<std::string> mcast_addr = {};
    std::optional<std::string> shrd_fldr = {};
    std::optional<int64> max_space = 52428800;
    std::optional<int32> cmd_port = {};
    std::optional<int32> timeout = 5;
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
    std::terminate();
}

// TODO: CHECK macro!
#define CHECK(X) X

std::thread read_thread;
bool read_thread_started = false;

struct __attribute__((__packed__)) DataStructure {
  uint16_t seq_no;
  uint32_t number;
};

std::pair<int, in_port_t> init_tcp_conn()
{
    int sock;
    struct sockaddr_in server_address;
    socklen_t server_address_len = sizeof(server_address);

    sock = socket(PF_INET, SOCK_STREAM, 0); // creating IPv4 TCP socket
    if (sock < 0)
        syserr("socket");

    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // listening on all interfaces
    server_address.sin_port = htons(0); // listening on port PORT_NUM

    // bind the socket to a concrete address
    if (bind(sock, (struct sockaddr *) &server_address, sizeof(server_address)) < 0)
        syserr("bind");

    // As passing 0 to sin_port got us random port, bind does not set this in
    // the server_address struct, and we have to get it manually by getsockname.
    if (getsockname(sock, (sockaddr *)(&server_address), &server_address_len) < 0)
        syserr("getsockname");

    return {sock, server_address.sin_port};
}

void tcp_read_file(int sock)
{
    int msg_sock;
    struct DataStructure data_read;
    struct sockaddr_in client_address;
    socklen_t client_address_len = sizeof(client_address);;

    // switch to listening (passive open)
    if (listen(sock, 5) < 0)
        syserr("listen");


    // get client connection from the socket
    msg_sock = accept(sock, (struct sockaddr *) &client_address, &client_address_len);
    if (msg_sock < 0)
        syserr("accept");

    char buffer[1024];
    ssize_t len;
    while ((len = read(msg_sock, buffer, 1024)) != 0) {
        if (len < 0) {
            syserr("reading from client socket");
        }
        else if (len > 0) {
            printf("read %zd bytes from socket: %.*s\n", len, (int)len, buffer);
        }
    }

    printf("ending connection\n");
    if (close(msg_sock) < 0)
        syserr("close");

    if (close(sock) < 0)
        syserr("close");
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
                printf("Received msg: HELLO\n");

                cmd response{"GOOD_DAY", c.cmd_seq};
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
                cmd response{"MY_LIST", c.cmd_seq};

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
            else if (c.check_header("GET"))
            {
                // TODO: Make sure that DATA is _NOT_ empty -> cannot have an empty filename.
                printf("Received msg: GET\n");
                printf("Adding file: %s\n", c.cmplx.data);

                // TODO: Check if such file exists.

                // The init happens in the main thread so that we know the port
                // id. Then we start a new thread giving it a created socket.
                auto[socket, port] = init_tcp_conn();
                cmd response{"CONNECT_ME", c.cmd_seq};
                response.cmplx.set_param(ntohs(port));
                printf("Listening on port %hu\n", ntohs(port));
                if (read_thread_started)
                    read_thread.join();
                read_thread = std::thread{tcp_read_file, socket};
                read_thread_started = true;

                if (sendto(sock, response.bytes, sizeof(response), 0,
                           (struct sockaddr*)&remote_address, remote_len) == -1)
                {
                    syserr("sendto");
                }
                else
                {
                    printf("Sent msg: [%.*s]\n", 10, response.head);
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
