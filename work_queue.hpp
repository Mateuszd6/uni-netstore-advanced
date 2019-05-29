#ifndef WORK_QUEUE_HPP
#define WORK_QUEUE_HPP

#include <queue>
#include <condition_variable>

#include "common.hpp"
#include "cmd.hpp"

struct send_packet
{
    cmd cmd;
    sockaddr_in from_addr;
    socklen_t from_addr_len;

    send_packet() : cmd{}, from_addr{} {
        from_addr_len = sizeof(from_addr);
    }
};

template<typename T>
struct work_queue
{
private:
    bool aborted = false;
    bool timeouted = false;
    std::queue<T> packet_queue;
    std::condition_variable cv;
    std::mutex mut;
    chrono::time_point<chrono::system_clock> timeout;

public:
    work_queue(chrono::time_point<chrono::system_clock> timeout_) {
        this->timeout = timeout_;
    }

    std::optional<T> consume() {
        std::unique_lock<std::mutex> m{mut};

        bool q = cv.wait_until(m, timeout, [this]{ return !packet_queue.empty() || aborted; });
        if (!q)
        {
            printf("TIMEOUT!\n");
            timeouted = true;
            return {};
        }
        else if (aborted) // TODO: empty queue check?
        {
            printf("ABORT!\n");
            return {};
        }
        else
        {
            T head = packet_queue.front();
            packet_queue.pop();
            return head;
        }
    }

    void push(T c) {
        std::unique_lock<std::mutex> m{mut};

        // Dont do anything we we've already aborted/timeouted.
        if (aborted || timeouted)
        {
            printf("Queue already finished\n");
            return;
        }

        packet_queue.push(c);
        cv.notify_one();
    }

    void abort() {
        std::unique_lock<std::mutex> m{mut};
        aborted = true;
        cv.notify_all();
    }
};

#endif // WORK_QUEUE_HPP