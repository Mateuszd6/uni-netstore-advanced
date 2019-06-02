#ifndef CONNECTION_HPP
#define CONNECTION_HPP

#include "logger.hpp"

constexpr static size_t send_block_size = 62000;

template <typename DUR> timeval chrono_to_posix(DUR duration) {
  chrono::microseconds usec = duration;
  timeval retval;
  if (usec <= chrono::microseconds(0)) {
    retval.tv_sec = retval.tv_usec = 0;
  } else {
    retval.tv_sec = usec.count() / 1000000;
    retval.tv_usec = usec.count() % 1000000;
  }

  return retval;
}

void safe_close(int sock);

std::optional<in_addr> string_to_addr(std::string const &str);

std::string addr_to_string(in_addr addr);

// Open up TCP socket on a random port.
std::pair<int, in_port_t> init_stream_conn(chrono::seconds timeout);

int connect_to_stream(std::string const &addr, std::string const &port,
                      chrono::microseconds timeout);

int accept_client_stream(int sock, chrono::seconds timeout);

// fs_mutex is a mutex that sycns threads access to filesystem. This fucntion
// waits of recv, but if anything is written to singal_fd immediently aborts.
std::pair<bool, std::string>
recv_file_stream(int sock, fs::path out_file_path,
                 std::optional<size_t> expected_size, int signal_fd);

void send_dgram(int sock, packet const &packet);

packet recv_dgram(int sock);

std::pair<bool, std::string> stream_file(int sock, fs::path file_path,
                                         int signal_fd);

#endif // CONNECTION_HPP
