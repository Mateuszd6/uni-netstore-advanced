#ifndef CMD_HPP
#define CMD_HPP

#include <arpa/inet.h>
#include <cassert>
#include <functional>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include "common.hpp"

enum struct cmd_type { cmplx, simpl };

// NOTE: The data size limit, imposed by the underlying IPv4 protocol, is 65507
//       bytes (65535 - 8 byte UDP header - 20 byte IP header). ~Wikipedia.
constexpr size_t upd_max_data_size = 65507;
union command {
  constexpr static size_t common_header_size = 10 + sizeof(uint64);
  constexpr static size_t simpl_head_size = common_header_size;
  constexpr static size_t simpl_max_data = upd_max_data_size - simpl_head_size;
  constexpr static size_t cmplx_head_size = common_header_size + sizeof(uint64);
  constexpr static size_t cmplx_max_data = upd_max_data_size - cmplx_head_size;

  struct __attribute__((__packed__)) {
    char head[10];
    uint64 cmd_seq;

    union {
      struct __attribute__((__packed__)) {
        uint8 data[simpl_max_data];

        uint8 const *get_data() const;
        void set_data(uint8 const *val, size_t data_len);
      } simpl;
      struct __attribute__((__packed__)) {
        uint64 param;
        uint8 data[cmplx_max_data];

        uint8 const *get_data() const;
        void set_data(uint8 const *val, size_t data_len);

        uint64 get_param() const;
        void set_param(uint64 val);
      } cmplx;
    };
  };
  uint8 bytes[upd_max_data_size];

  command();

  char const *get_head() const;
  void set_head(char const *val);

  uint64 get_cmd_seq() const;
  void set_cmd_seq(uint64 val);

  bool check_header(char const *usr_head) const;

  void clear();

  bool contains_required_fields(cmd_type type, ssize_t msg_size) const;
  bool contains_data(cmd_type type, ssize_t msg_size) const;
};

// Make sure that the cmd union is packed properly.
static_assert(sizeof(command::bytes) == upd_max_data_size);
static_assert(sizeof(command::bytes) == sizeof(command));
static_assert(sizeof(command::bytes) ==
              10 + sizeof(uint64) + sizeof(command::simpl));
static_assert(sizeof(command::bytes) ==
              10 + sizeof(uint64) + sizeof(command::cmplx));

struct packet {
  command cmd;
  size_t msg_len;
  sockaddr_in addr;
  socklen_t addr_len;

  packet();

  packet(command cmd_, size_t msg_len_, sockaddr_in addr_);

  std::string_view data_as_sv(cmd_type type) const;

  static packet make_simpl(char const *head, uint64 cmd_seq, uint8 const *data,
                           size_t data_len, sockaddr_in addr);

  static packet make_cmplx(char const *head, uint64 cmd_seq, uint64 param,
                           uint8 const *data, size_t data_len,
                           sockaddr_in addr);
};

#endif // CMD_HPP
