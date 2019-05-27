#include <string.h>

#include "cmd.hpp"

cmd::cmd()
{
    clear();
}

cmd::cmd(char const* head_, uint64 cmd_seq_) : cmd()
{
    set_head(head_);
    set_cmd_seq(cmd_seq_);
}

char const* cmd::get_head() const
{
    return &(head[0]);
}

void cmd::set_head(char const* val)
{
    int32 val_len = strlen(val);
    assert(val_len <= 10);

    bzero(head, 10);
    memcpy(head, val, strlen(val));
}

uint64 cmd::get_cmd_seq() const
{
    return be64toh(cmd_seq);
}

void cmd::set_cmd_seq(uint64 val)
{
    cmd_seq = htobe64(val);
}

// We need an alias to define a anonymus struct member func.
using cmd_cmplx_t = decltype(cmd::cmplx);
uint64 cmd_cmplx_t::get_param()
{
    return be64toh(param);
}

void cmd_cmplx_t::set_param(uint64 val)
{
    param = htobe64(val);
}

bool cmd::check_header(char const* usr_head) const
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

void cmd::clear()
{
    bzero(&bytes[0], upd_max_data_size);
}

// if expect_data is false, we make sure, that the whole data[] array is
// zeroed. Otherwise the packet is concidered to be ill formed.
bool cmd::validate(char const* expected_header,
                   bool is_cmplx,
                   bool expect_data) const
{
    int32 exp_head_len = strlen(expected_header);
    assert(exp_head_len <= 10);

    if (memcmp(head, expected_header, exp_head_len) != 0)
        return false;

    // Check if the trailing bytes in the HEAD are set to 0.
    for (int i = exp_head_len; i < 10; ++i)
        if (head[i] != 0)
            return false;

    return true;
}
