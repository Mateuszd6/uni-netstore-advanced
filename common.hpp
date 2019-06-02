#ifndef COMMON_HPP
#define COMMON_HPP

// Common namespace aliases.
#include <boost/filesystem.hpp>
#include <chrono>
namespace chrono = std::chrono;
using namespace std::chrono_literals;
namespace fs = boost::filesystem;

using int8 = int8_t;
using uint8 = uint8_t;
using int16 = int16_t;
using uint16 = uint16_t;
using int32 = int32_t;
using uint32 = uint32_t;
using int64 = int64_t;
using uint64 = uint64_t;

constexpr static uint32 strhash(const char *str, int h = 0) {
  // In c++17 std::hash is still not constexpr.
  return !str[h] ? 5381 : (strhash(str, h + 1) * 33) ^ str[h];
}

#endif // COMMON_HPP
