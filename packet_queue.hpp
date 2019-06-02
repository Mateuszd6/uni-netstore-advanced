#ifndef PACKET_QUEUE_HPP
#define PACKET_QUEUE_HPP

#include <condition_variable>
#include <queue>

#include "cmd.hpp"
#include "common.hpp"
#include "logger.hpp"

// Simple single-thread work queue, with packets awaiting to being processed.
template <typename T> struct packet_queue {
private:
  bool aborted = false;
  bool timeouted = false;
  std::queue<T> awaiting_packets;
  std::condition_variable cv;
  std::mutex mut;
  chrono::time_point<chrono::system_clock> timeout;

public:
  packet_queue(chrono::time_point<chrono::system_clock> timeout_) {
    this->timeout = timeout_;
  }

  std::optional<T> consume() {
    std::unique_lock<std::mutex> m{mut};

    bool q = cv.wait_until(
        m, timeout, [this] { return !awaiting_packets.empty() || aborted; });
    if (!q) {
      timeouted = true;
      return {};
    } else if (aborted) {
      return {};
    } else {
      T head = awaiting_packets.front();
      awaiting_packets.pop();
      return head;
    }
  }

  void push(T c) {
    std::unique_lock<std::mutex> m{mut};

    // Dont do anything we we've already aborted/timeouted.
    if (aborted || timeouted) {
      logger.trace("Queue already finished");
      return;
    }

    awaiting_packets.push(c);
    cv.notify_one();
  }

  void abort() {
    std::unique_lock<std::mutex> m{mut};
    aborted = true;
    cv.notify_all();
  }

  bool was_aborted() { return aborted; }
};

#endif // PACKET_QUEUE_HPP
