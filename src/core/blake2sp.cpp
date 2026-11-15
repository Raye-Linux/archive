// SPDX-License-Identifier: GPL-3.0-or-later
// BLAKE2sp (RFC 7693 BLAKE2s, 8 leaves in a tree of depth 2), the file
// hash of RAR 5. Input goes to the leaves in 64-byte blocks, round robin.
#include "checksum.h"

#include <cstring>

namespace raye::archive::detail {

namespace {

constexpr std::uint32_t kIv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

constexpr std::uint8_t kSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

inline std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline std::uint32_t load32(const std::uint8_t *p) { std::uint32_t v; std::memcpy(&v, p, 4); return v; } // LE hosts only

struct Blake2s {
    std::uint32_t h[8];
    std::uint32_t t0 = 0, t1 = 0;
    std::uint8_t buf[64];
    std::size_t buflen = 0;
    bool last_node = false;

    void init(std::uint64_t node_offset, std::uint8_t node_depth, bool last)
    {
        // Parameter block: digest 32, no key, fanout 8, depth 2, inner length 32.
        std::uint8_t p[32] = {};
        p[0] = 32; p[2] = 8; p[3] = 2;
        for (int i = 0; i < 6; ++i) p[8 + i] = std::uint8_t(node_offset >> (8 * i));
        p[14] = node_depth;
        p[15] = 32;
        for (int i = 0; i < 8; ++i) h[i] = kIv[i] ^ load32(p + 4 * i);
        last_node = last;
    }

    void compress(const std::uint8_t *block, bool final)
    {
        std::uint32_t m[16], v[16];
        for (int i = 0; i < 16; ++i) m[i] = load32(block + 4 * i);
        for (int i = 0; i < 8; ++i) { v[i] = h[i]; v[i + 8] = kIv[i]; }
        v[12] ^= t0;
        v[13] ^= t1;
        if (final) {
            v[14] = ~v[14];
            if (last_node) v[15] = ~v[15];
        }
#define G(a, b, c, d, x, y)                                         \
    v[a] = v[a] + v[b] + (x); v[d] = rotr(v[d] ^ v[a], 16);         \
    v[c] = v[c] + v[d];       v[b] = rotr(v[b] ^ v[c], 12);         \
    v[a] = v[a] + v[b] + (y); v[d] = rotr(v[d] ^ v[a], 8);          \
    v[c] = v[c] + v[d];       v[b] = rotr(v[b] ^ v[c], 7);
        for (const auto &s : kSigma) {
            G(0, 4, 8, 12, m[s[0]], m[s[1]]);
            G(1, 5, 9, 13, m[s[2]], m[s[3]]);
            G(2, 6, 10, 14, m[s[4]], m[s[5]]);
            G(3, 7, 11, 15, m[s[6]], m[s[7]]);
            G(0, 5, 10, 15, m[s[8]], m[s[9]]);
            G(1, 6, 11, 12, m[s[10]], m[s[11]]);
            G(2, 7, 8, 13, m[s[12]], m[s[13]]);
            G(3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
#undef G
        for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
    }

    void add_counter(std::uint32_t n)
    {
        t0 += n;
        if (t0 < n) ++t1;
    }

    // The last block is held back: it is compressed with the final flag.
    void update(const std::uint8_t *in, std::size_t n)
    {
        while (n > 0) {
            if (buflen == 64) {
                add_counter(64);
                compress(buf, false);
                buflen = 0;
            }
            const std::size_t take = std::min(n, 64 - buflen);
            std::memcpy(buf + buflen, in, take);
            buflen += take;
            in += take;
            n -= take;
        }
    }

    void final(std::uint8_t out[32])
    {
        add_counter(std::uint32_t(buflen));
        std::memset(buf + buflen, 0, 64 - buflen);
        compress(buf, true);
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 4; ++j) out[4 * i + j] = std::uint8_t(h[i] >> (8 * j));
    }
};

} // namespace

struct Blake2sp::State {
    Blake2s leaf[8];
    std::uint8_t block[64];
    std::size_t blen = 0;
    std::uint64_t blocks = 0;
};

Blake2sp::Blake2sp() : s_(std::make_unique<State>())
{
    for (int i = 0; i < 8; ++i) s_->leaf[i].init(std::uint64_t(i), 0, i == 7);
}

Blake2sp::~Blake2sp() = default;

void Blake2sp::update(const void *data, std::size_t n)
{
    auto *in = static_cast<const std::uint8_t *>(data);
    State &s = *s_;
    if (s.blen) {
        const std::size_t take = std::min(n, 64 - s.blen);
        std::memcpy(s.block + s.blen, in, take);
        s.blen += take;
        in += take;
        n -= take;
        if (s.blen < 64) return;
        s.leaf[s.blocks++ & 7].update(s.block, 64);
        s.blen = 0;
    }
    // Whole blocks go straight in: each leaf holds back its own last block.
    while (n >= 64) {
        s.leaf[s.blocks++ & 7].update(in, 64);
        in += 64;
        n -= 64;
    }
    std::memcpy(s.block, in, n);
    s.blen = n;
}

std::array<std::uint8_t, 32> Blake2sp::final()
{
    State &s = *s_;
    if (s.blen) s.leaf[s.blocks & 7].update(s.block, s.blen);
    Blake2s root;
    root.init(0, 1, true);
    std::uint8_t d[32];
    for (auto &l : s.leaf) {
        l.final(d);
        root.update(d, 32);
    }
    std::array<std::uint8_t, 32> out{};
    root.final(out.data());
    return out;
}

} // namespace raye::archive::detail
