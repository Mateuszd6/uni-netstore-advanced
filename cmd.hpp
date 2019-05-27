#ifndef CMD_HPP
#define CMD_HPP

#include "common.hpp"

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
                uint64 get_param();
                void set_param(uint64 val);
            } cmplx;
        };
    };
    uint8 bytes[upd_max_data_size];

    cmd();
    cmd(char const* head_, uint64 cmd_seq_);

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
