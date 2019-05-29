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

#include <atomic>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <unordered_map>
namespace fs = std::filesystem;
namespace chrono = std::chrono;
using namespace std::chrono_literals;

#include "common.hpp"
#include "work_queue.hpp"
#include "cmd.hpp"

#define TTL_VALUE 4

// TODO: This is a copypaste of the server function.
// If file exists this will load its contents into the vector and return (true,
// contents) pair, otherwise (false, _) is returned, where _ could be anything.
std::pair<bool, std::vector<uint8>>
load_file_if_exists(fs::path file_path)
{
    std::vector<uint8> contents{};
    if (fs::exists(file_path))
    {
        constexpr static size_t buffer_size = 4096;
        std::ifstream file{file_path};
        char buffer[buffer_size];

        assert(file.is_open());
        while (!(file.eof() || file.fail())) {
            file.read(buffer, buffer_size);
            contents.reserve(contents.size() + file.gcount());
            contents.insert(contents.end(), buffer, buffer + file.gcount());
        }

        return {true, contents};
    }

    return {false, contents};
}

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
    sockaddr_in uaddr;
    in_addr maddr;
    size_t free_space;
};

std::atomic_int cmd_seq_counter{0};

static std::vector<search_entry> last_search_result{};
static std::vector<available_server> available_servers{};

// If reason is null, info is not emmited to the screen.
void report_invalid_pkg(send_packet const& packet, char const* reason)
{
    // TODO: These functions CAN fail!
    fprintf(stderr, "\033[1;31m");
    fprintf(stderr, "[PCKG ERROR]  Skipping invalid package from %s:%d. %s\n",
            inet_ntoa(packet.from_addr.sin_addr),
            htons(packet.from_addr.sin_port),
            reason == nullptr ? "" : reason);
    fprintf(stderr, "\033[0m");
}

void send_file_over_tcp(char const* addr,
                        char const* port,
                        std::vector<uint8> data)
{
    printf("Sending %lu bytes to %s:%s\n", data.size(), addr, port);

    int sock;
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;

    int err, seq_no = 0, number;

    // 'converting' host/port in string to struct addrinfo
    memset(&addr_hints, 0, sizeof(addrinfo));
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
    {
        printf("Error: %s(%d)\n", strerror(errno), errno);
        syserr("connect");
    }

    freeaddrinfo(addr_result);

    // TODO: Use write_well
    if (write(sock, data.data(), data.size()) != data.size())
        syserr("partial / failed write");

    if (close(sock) < 0) // socket would be closed anyway when the program ends
        syserr("close");
}

void send_dgram(int sock, sockaddr_in remote_addr, uint8* data, size_t size)
{

    if (sendto(sock, data, size, 0, (sockaddr*)&remote_addr, sizeof(remote_addr)) != size)
    {
        syserr("sendto");
    }
}

#if 0
static void send_request_hello(int sock, sockaddr remote_addr, size_t remote_addr_len)
{
    auto[request, size] = cmd::make_simpl("HELLO", cmd_seq_counter++, nullptr, 0);
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
                                          cmd_seq_counter++,
                                          (uint8 const*)filter.c_str(),
                                          filter.size());

    if (sendto(sock, request.bytes, size, 0,
               (sockaddr*)&remote_addr, remote_addr_len) != size)
    {
        syserr("sendto");
    }
}
#endif

static void handle_response_hello(send_packet const& packet)
{
    printf("Received [CMPLX] (from %s:%d): %lu %.*s {%s}\n",
           inet_ntoa(packet.from_addr.sin_addr),
           htons(packet.from_addr.sin_port),
           packet.cmd.cmplx.get_param(),
           10, packet.cmd.head,
           packet.cmd.cmplx.get_data());

    // TODO: Data sent _can_ be incorrect!!! dont syserr
    in_addr mcast_addr;
    if (inet_aton((char const*)packet.cmd.cmplx.get_data(), &mcast_addr) == 0)
    {
        syserr("inet_aton");
    }

    available_servers.emplace_back(
        available_server{packet.from_addr,
                         mcast_addr,
                         packet.cmd.cmplx.get_param()});
}

static void handle_response_list(send_packet const& packet)
{
    printf("Received [SIMPL] (from %s:%d): %.*s {%s}\n",
           inet_ntoa(packet.from_addr.sin_addr),
           htons(packet.from_addr.sin_port),
           10, packet.cmd.head,
           packet.cmd.simpl.get_data());

    // TODO: Watch out for more than one \n in a row.
    uint8 const* str = &packet.cmd.simpl.data[0];
    while (*str)
    {
        uint8 const* p = str;
        while (*p && *p != '\n')
            ++p;

        last_search_result.emplace_back(
            search_entry{std::string{(char const*)str, (size_t)(p - str)},
                         packet.from_addr.sin_addr});

        if (*p == '\n')
            ++p;
        str = p;
    }
}

std::mutex awaitng_packets_mutex{};
std::unordered_map<uint64, std::unique_ptr<work_queue<send_packet>>> awaiting_packets{};

// This adds a work queue to the awaiting_packets map. For now every arriving
// packet with the seq_cmd equal to one specified will go to the created work
// queue. Returns a pointer to the work queue.
work_queue<send_packet>* subscribe_for_packets(uint64 cmd_seq)
{
    std::lock_guard<std::mutex> m{awaitng_packets_mutex};

    // TODO: Don't do it, or if it happens, change the packed seq num
    assert(awaiting_packets.count(cmd_seq) == 0);
    awaiting_packets.emplace(
        cmd_seq,
        std::make_unique<work_queue<send_packet>>(std::chrono::system_clock::now() + 2s));

    return awaiting_packets[cmd_seq].get();
}

template<typename FUNC>
void receive_packets(uint64 cmd_seq, FUNC functor)
{
    for (;;)
    {
        std::optional<send_packet> c = awaiting_packets[cmd_seq]->consume();
        if (!c.has_value())
        {
            printf("No more [%lu] packets\n", cmd_seq);
            break;
        }

        functor(c.value());
    }

    {
        std::lock_guard<std::mutex> m{awaitng_packets_mutex};

        size_t erased = awaiting_packets.erase(cmd_seq);;
        printf("Erasing: %lu\n", erased);
    }
}

void packets_thread(int sock)
{
    for (;;)
    {
        send_packet response{};
        ssize_t rcv_len = recvfrom(sock, response.cmd.bytes, sizeof(response.cmd.bytes), 0,
                                   (sockaddr*)&response.from_addr, &response.from_addr_len);

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
        else if (rcv_len > 0)
        {
            std::lock_guard<std::mutex> m{awaitng_packets_mutex};

            if (awaiting_packets.count(response.cmd.get_cmd_seq()))
            {
                printf("-> SOMEONE IS AWAITING PACKET %lu\n", response.cmd.get_cmd_seq());
                awaiting_packets[response.cmd.get_cmd_seq()]->push(response);
            }
            else
            {
                report_invalid_pkg(response, nullptr);
                printf("-> UNEXPECTED cmd_seq: %lu\n", response.cmd.get_cmd_seq());
            }
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

    auto packet_handler = std::thread{packets_thread, sock};

    for (;;)
    {
        std::string input_line;
        std::getline(std::cin, input_line);

        std::string_view command{};
        std::string_view param{};

        size_t space_occur = input_line.find(" ");
        if (space_occur == std::string::npos)
        {
            command = std::string_view{input_line};
        }
        else
        {
            command = std::string_view{input_line.c_str(), space_occur};
            param = std::string_view{input_line.c_str() + space_occur + 1};
        }

        std::cout << "command is: '" << command
                  << "', param is: '" << param << "'\n";

        if (command == "exit")
        {
            std::terminate();
        }
        else if (command == "discover")
        {
            uint64 packet_id = cmd_seq_counter++;
            subscribe_for_packets(packet_id);

            auto[request, size] = cmd::make_simpl("HELLO", packet_id, 0, 0);
            send_dgram(sock, remote_address, request.bytes, size);
            printf("HELLO request sent. Awaiting responses\n");

            available_servers.clear();
            receive_packets(packet_id, handle_response_hello); // TODO: Filter headers and sanitize data!
            for (auto&& i : available_servers)
            {
                printf("\033[1;32m");
                std::string uaddr = inet_ntoa(i.uaddr.sin_addr); // TODO: Handle the case, when these fail!
                std::string maddr = inet_ntoa(i.maddr);
                printf("Found %s (%s) with free space %lu\n", uaddr.c_str(), maddr.c_str(), i.free_space);
                printf("\033[0m");
            }
        }
        else if (command == "search")
        {
            uint64 packet_id = cmd_seq_counter++;
            subscribe_for_packets(packet_id);

            auto[request, size] = cmd::make_simpl("LIST", packet_id, (uint8 const*)param.data(), param.size());
            send_dgram(sock, remote_address, request.bytes, size);
            printf("LIST request sent. Awaiting responses\n");

            last_search_result.clear();
            receive_packets(packet_id, handle_response_list); // TODO: Filter headers and sanitize data!
            for (auto&& i : last_search_result)
            {
                printf("\033[1;32m");
                printf("%s (%s)\n", i.filename.c_str(), inet_ntoa(i.server_unicast_addr));
                printf("\033[0m");
            }
        }
        else if (command == "remove")
        {
            if (param == "")
            {
                printf("Cannot remove because of the empty param!\n");
                continue;
            }

            uint64 packet_id = cmd_seq_counter++;
            auto[request, size] = cmd::make_simpl("DEL", packet_id, (uint8 const*)param.data(), param.size());
            send_dgram(sock, remote_address, request.bytes, size);
            printf("DEL request sent.\n");
        }
        else if (command == "upload")
        {
            if (param == "")
            {
                printf("Cannot upload because of the empty param!\n");
                continue;
            }

            fs::path upload_file_path{param};
            std::string filename{upload_file_path.filename()};

            // We load the whole file into memory to avoid races.
            auto[exists, data] = load_file_if_exists(upload_file_path);
            if (exists)
            {
                size_t file_size = data.size();
                printf("File %s(%s) exists, and has %lu bytes\n",
                       upload_file_path.c_str(), filename.c_str(), file_size);

                // Prepare the request that will be sent to the servers.

                // Make a copy of a server list. TODO: Fetch the list?
                std::vector<available_server> servers{available_servers};
                std::sort(servers.begin(), servers.end(),
                          [](auto const& x, auto const& y) {
                              return x.free_space > y.free_space;
                          });

                printf("Querying the servers!\n");
                bool server_agreed = false;
                sockaddr_in agreed_server_uaddr;
                uint64 port_num; // Used only is server has agreed.
                for(auto&& serv : servers)
                {
                    uint64 packet_id = cmd_seq_counter++;
                    auto[request, size] = cmd::make_cmplx(
                        "ADD", packet_id, file_size, (uint8 const*)filename.c_str(), filename.size());

                    subscribe_for_packets(packet_id);
                    send_dgram(sock, serv.uaddr, request.bytes, size);
                    printf("ADD request sent to: %s...\n", inet_ntoa(serv.uaddr.sin_addr));

                    receive_packets(packet_id,
                                    [&](send_packet const& packet) {
                                        if (packet.cmd.check_header("CAN_ADD"))
                                        {
                                            printf("Received [CMPLX] (from %s:%d): %.*s %lu {%s}\n",
                                                   inet_ntoa(remote_address.sin_addr),
                                                   htons(remote_address.sin_port),
                                                   10, packet.cmd.head,
                                                   packet.cmd.cmplx.get_param(),
                                                   packet.cmd.cmplx.data);

                                            server_agreed = true;
                                            agreed_server_uaddr = serv.uaddr;
                                            port_num = packet.cmd.cmplx.get_param();
                                        }
                                        else if (packet.cmd.check_header("NO_WAY"))
                                        {
                                            printf("Received [SMPL] (from %s:%d): %.*s {%s}\n",
                                                   inet_ntoa(remote_address.sin_addr),
                                                   htons(remote_address.sin_port),
                                                   10, packet.cmd.head,
                                                   packet.cmd.simpl.data);
                                        }
                                    });

                    if (server_agreed)
                    {
                        printf("SERVER AGREED!\n");
                        break;
                    }
                }

                if (server_agreed)
                {
                    char port_buffer[32];
                    sprintf(port_buffer, "%lu", port_num);
                    printf("Starting TCP conn at port %s\n", port_buffer);
                    send_file_over_tcp(inet_ntoa(agreed_server_uaddr.sin_addr), port_buffer, data);
                }
                else
                {
                    printf("None of the servers agreeded :(\n");
                }
            }
            else
                printf("File %s does not exist\n", upload_file_path.c_str());
        }
    }

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
