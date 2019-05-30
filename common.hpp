#ifndef COMMON_HPP
#define COMMON_HPP

#include <chrono>
namespace chrono = std::chrono;
using namespace std::chrono_literals;

using int8 = int8_t;
using uint8 = uint8_t;
using int16 = int16_t;
using uint16 = uint16_t;
using int32 = int32_t;
using uint32 = uint32_t;
using int64 = int64_t;
using uint64 = uint64_t;

// TODO: Make common.cpp implementation for these!

// TODO: Decide whether or not this lives.
constexpr static uint32 strhash(const char* str, int h = 0)
{
    // In c++17 std::hash is still not constexpr.
    return !str[h] ? 5381 : (strhash(str, h + 1) * 33) ^ str[h];
}

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

#endif // COMMON_HPP
