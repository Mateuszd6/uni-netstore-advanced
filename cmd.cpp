#include <string.h>

#include "cmd.hpp"

command::command()
{
    clear();
}

#if 0
std::pair<command, size_t>
command::make_simpl(char const* head, uint64 cmd_seq,
                    uint8 const* data, size_t data_len)
{
    command retval{};

    retval.set_head(head);
    retval.set_cmd_seq(cmd_seq);

    if (data != nullptr)
        retval.simpl.set_data(data, data_len);

    return { retval,  common_header_size + data_len };
}

std::pair<command, size_t>
command::make_cmplx(char const* head, uint64 cmd_seq,
                    uint64 param_, uint8 const* data, size_t data_len)
{
    command retval{};

    retval.set_head(head);
    retval.set_cmd_seq(cmd_seq);
    retval.cmplx.set_param(param_);

    if (data != nullptr)
        retval.cmplx.set_data(data, data_len);

    return { retval,  common_header_size + sizeof(uint64) + data_len };
}
#endif

char const* command::get_head() const
{
    return &(head[0]);
}

void command::set_head(char const* val)
{
    int32 val_len = strlen(val);
    assert(val_len <= 10);

    bzero(head, 10);
    memcpy(head, val, strlen(val));
}

uint64 command::get_cmd_seq() const
{
    return be64toh(cmd_seq);
}

void command::set_cmd_seq(uint64 val)
{
    cmd_seq = htobe64(val);
}

// We need an alias to define a anonymus struct member func.
using cmd_cmplx_t = decltype(command::cmplx);
using cmd_simpl_t = decltype(command::simpl);

uint8 const* cmd_simpl_t::get_data() const
{
    return (uint8 const*)data;
}

void cmd_simpl_t::set_data(uint8 const* val, size_t data_len)
{
    // TODO: Test for equal
    assert(data_len <= command::simpl_max_data);
    memcpy(data, val, data_len);

    // TODO: Zero out the rest of the structure?
}

uint8 const* cmd_cmplx_t::get_data() const
{
    return (uint8 const*)data;
}

void cmd_cmplx_t::set_data(uint8 const* val, size_t data_len)
{
    // TODO: Test for equal
    assert(data_len <= command::simpl_max_data);
    memcpy(data, val, data_len);

    // TODO: Zero out the rest of the structure?
}

uint64 cmd_cmplx_t::get_param() const
{
    return be64toh(param);
}

void cmd_cmplx_t::set_param(uint64 val)
{
    param = htobe64(val);
}

bool command::check_header(char const* usr_head) const
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

void command::clear()
{
    bzero(&bytes[0], upd_max_data_size);
}

bool command::contains_required_fields(cmd_type type, ssize_t msg_size) const
{
    if (type == cmd_type::cmplx)
        return msg_size >= command::cmplx_head_size;
    else if (type == cmd_type::simpl)
        return msg_size >= command::simpl_head_size;
    else
        return false;
}

bool command::contains_data(cmd_type type, ssize_t msg_size) const
{
    if (type == cmd_type::cmplx)
        return msg_size > command::cmplx_head_size;
    else if (type == cmd_type::simpl)
        return msg_size > command::simpl_head_size;
    else
        return false;
}
