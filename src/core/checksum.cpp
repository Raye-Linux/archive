// SPDX-License-Identifier: GPL-3.0-or-later
#include "checksum.h"

#include <array>
#include <cstring>
#include <zlib.h>

#if defined(__x86_64__)
#include <nmmintrin.h>
#endif

namespace raye::archive::detail {

std::uint32_t crc32(std::uint32_t crc, const void *data, std::size_t n)
{
    const auto *p = static_cast<const Bytef *>(data);
    while (n) { // zlib takes uInt lengths
        const uInt chunk = n > (1u << 30) ? (1u << 30) : uInt(n);
        crc = std::uint32_t(::crc32_z(crc, p, chunk));
        p += chunk;
        n -= chunk;
    }
    return crc;
}

std::uint32_t crc32_combine(std::uint32_t a, std::uint32_t b, std::uint64_t len_b)
{
    return std::uint32_t(::crc32_combine64(a, b, z_off64_t(len_b)));
}

namespace {

constexpr std::uint32_t kPoly32c = 0x82F63B78u;

struct Table32c {
    std::array<std::array<std::uint32_t, 256>, 8> t{};
    constexpr Table32c()
    {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = c & 1 ? (c >> 1) ^ kPoly32c : c >> 1;
            t[0][i] = c;
        }
        for (std::uint32_t i = 0; i < 256; ++i)
            for (int s = 1; s < 8; ++s) t[s][i] = (t[s - 1][i] >> 8) ^ t[0][t[s - 1][i] & 0xff];
    }
};
constexpr Table32c kT32c;

std::uint32_t crc32c_soft(std::uint32_t c, const std::uint8_t *p, std::size_t n)
{
    const auto &t = kT32c.t;
    while (n >= 8) {
        std::uint32_t lo, hi;
        std::memcpy(&lo, p, 4);
        std::memcpy(&hi, p + 4, 4);
        lo ^= c;
        c = t[7][lo & 0xff] ^ t[6][(lo >> 8) & 0xff] ^ t[5][(lo >> 16) & 0xff] ^ t[4][lo >> 24] ^
            t[3][hi & 0xff] ^ t[2][(hi >> 8) & 0xff] ^ t[1][(hi >> 16) & 0xff] ^ t[0][hi >> 24];
        p += 8;
        n -= 8;
    }
    while (n--) c = (c >> 8) ^ t[0][(c ^ *p++) & 0xff];
    return c;
}

#if defined(__x86_64__)
__attribute__((target("sse4.2"))) std::uint32_t crc32c_hw(std::uint32_t c, const std::uint8_t *p, std::size_t n)
{
    std::uint64_t c64 = c;
    while (n >= 8) {
        std::uint64_t v;
        std::memcpy(&v, p, 8);
        c64 = _mm_crc32_u64(c64, v);
        p += 8;
        n -= 8;
    }
    c = std::uint32_t(c64);
    while (n--) c = _mm_crc32_u8(c, *p++);
    return c;
}
#endif

} // namespace

std::uint32_t crc32c(std::uint32_t crc, const void *data, std::size_t n)
{
    const auto *p = static_cast<const std::uint8_t *>(data);
    std::uint32_t c = ~crc;
#if defined(__x86_64__)
    static const bool hw = __builtin_cpu_supports("sse4.2");
    c = hw ? crc32c_hw(c, p, n) : crc32c_soft(c, p, n);
#else
    c = crc32c_soft(c, p, n);
#endif
    return ~c;
}

} // namespace raye::archive::detail
