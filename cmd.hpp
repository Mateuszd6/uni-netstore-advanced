#ifndef CMD_HPP
#define CMD_HPP

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include <cassert>
#include <functional>

#include "common.hpp"

enum struct cmd_type { cmplx, simpl };

// NOTE: The data size limit, imposed by the underlying IPv4 protocol, is 65507
//       bytes (65535 - 8 byte UDP header - 20 byte IP header). ~Wikipedia.
constexpr size_t upd_max_data_size = 65507;
union command
{
    constexpr static size_t common_header_size = 10  + sizeof(uint64);
    constexpr static size_t simpl_head_size = common_header_size;
    constexpr static size_t simpl_max_data = upd_max_data_size - simpl_head_size;
    constexpr static size_t cmplx_head_size = common_header_size + sizeof(uint64);
    constexpr static size_t cmplx_max_data = upd_max_data_size - cmplx_head_size;

    // TODO: Concider changing chars to uint8's.
    // TODO(IMPORTANT): Doing it with strlen is badd, because packets may contains 0s.
    struct __attribute__((__packed__))
    {
        char head[10];
        uint64 cmd_seq;

        union {
            struct __attribute__((__packed__))
            {
                uint8 data[simpl_max_data];

                uint8 const* get_data() const;
                void set_data(uint8 const* val, size_t data_len);
            } simpl;
            struct __attribute__((__packed__))
            {
                uint64 param;
                uint8 data[cmplx_max_data];

                uint8 const* get_data() const;
                void set_data(uint8 const* val, size_t data_len);

                uint64 get_param() const;
                void set_param(uint64 val);
            } cmplx;
        };
    };
    uint8 bytes[upd_max_data_size];

    command();

#if 0
    // These fucntions let us construct the response object and also return
    // their size which is the number of bytes user has to send.
    static std::pair<command, size_t> make_simpl(char const* head, uint64 cmd_seq,
                                                 uint8 const* data, size_t data_len);
    static std::pair<command, size_t> make_cmplx(char const* head, uint64 cmd_seq,
                                             uint64 param, uint8 const* data, size_t data_len);
#endif

    char const* get_head() const;
    void set_head(char const* val);

    uint64 get_cmd_seq() const;
    void set_cmd_seq(uint64 val);

    bool check_header(char const* usr_head) const;

    void clear();

    bool contains_required_fields(cmd_type type, ssize_t msg_size) const;
    bool contains_data(cmd_type type, ssize_t msg_size) const;
};

// Make sure that the cmd union is packed properly.
static_assert(sizeof(command::bytes) == upd_max_data_size);
static_assert(sizeof(command::bytes) == sizeof(command));
static_assert(sizeof(command::bytes) == 10 + sizeof(uint64) + sizeof(command::simpl));
static_assert(sizeof(command::bytes) == 10 + sizeof(uint64) + sizeof(command::cmplx));

struct send_packet
{
    command cmd;
    size_t msg_len;
    sockaddr_in addr;
    socklen_t addr_len;

    send_packet() : cmd{}, addr{} {
        addr_len = sizeof(addr);
    }

    // TODO: Fix naming
    send_packet(command cmd_, size_t msg_len_, sockaddr_in addr_) {
        this->cmd = cmd_;
        this->msg_len = msg_len_;
        this->addr = addr_;
        this->addr_len = sizeof(addr_);
    }

    static send_packet make_simpl(char const* head, uint64 cmd_seq,
                                  uint8 const* data, size_t data_len,
                                  sockaddr_in addr) {
        send_packet retval{};
        retval.addr = addr;
        retval.msg_len = command::simpl_head_size + data_len;

        retval.cmd.set_head(head);
        retval.cmd.set_cmd_seq(cmd_seq);
        if (data != nullptr)
            retval.cmd.simpl.set_data(data, data_len);

        return retval;
    }

    static send_packet make_cmplx(char const* head, uint64 cmd_seq,
                                  uint64 param,
                                  uint8 const* data, size_t data_len,
                                  sockaddr_in addr) {
        send_packet retval{};
        retval.addr = addr;
        retval.msg_len = command::cmplx_head_size + data_len;

        retval.cmd.set_head(head);
        retval.cmd.set_cmd_seq(cmd_seq);
        retval.cmd.cmplx.set_param(param);
        if (data != nullptr)
            retval.cmd.cmplx.set_data(data, data_len);

        return retval;
    }
};

#endif // CMD_HPP
