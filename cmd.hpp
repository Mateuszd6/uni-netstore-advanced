#ifndef CMD_HPP
#define CMD_HPP

#include <functional>

#include "common.hpp"

// NOTE: The data size limit, imposed by the underlying IPv4 protocol, is 65507
//       bytes (65535 - 8 byte UDP header - 20 byte IP header). ~Wikipedia.
constexpr size_t upd_max_data_size = 65507;
union cmd
{
    constexpr static size_t common_header_size = 10  + sizeof(uint64);
    constexpr static size_t simpl_max_data = upd_max_data_size - common_header_size;
    constexpr static size_t cmplx_max_data = upd_max_data_size - common_header_size - sizeof(uint64);

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

    cmd();

    // These fucntions let us construct the response object and also return
    // their size which is the number of bytes user has to send.
    static std::pair<cmd, size_t> make_simpl(char const* head, uint64 cmd_seq,
                                             uint8 const* data, size_t data_len);
    static std::pair<cmd, size_t> make_cmplx(char const* head, uint64 cmd_seq,
                                             uint64 param, uint8 const* data, size_t data_len);

    char const* get_head() const;
    void set_head(char const* val);

    uint64 get_cmd_seq() const;
    void set_cmd_seq(uint64 val);

    bool check_header(char const* usr_head) const;

    void clear();

    // if expect_data is false, we make sure, that the whole data[] array is
    // zeroed. If this func returns false, this means that the packed is ill
    // formed.
    bool validate(char const* expected_header,
                  bool is_cmplx,
                  bool expect_data) const;
};

// Make sure that the cmd union is packed properly.
static_assert(sizeof(cmd::bytes) == upd_max_data_size);
static_assert(sizeof(cmd::bytes) == sizeof(cmd));
static_assert(sizeof(cmd::bytes) == 10 + sizeof(uint64) + sizeof(cmd::simpl));
static_assert(sizeof(cmd::bytes) == 10 + sizeof(uint64) + sizeof(cmd::cmplx));

#endif // CMD_HPP
