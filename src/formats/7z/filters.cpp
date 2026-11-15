// SPDX-License-Identifier: GPL-3.0-or-later
#include "filters.h"

#include "../../core/bytes.h"

#include <raye/archive/error.h>

#include <algorithm>
#include <cstring>

namespace raye::archive::detail::filters {

namespace {

bool x86_ms_byte(std::uint8_t b) { return b == 0 || b == 0xFF; }

class X86 final : public Filter {
public:
    X86(bool enc, std::uint32_t start) : enc_(enc), ip_(start), last_(start - 5) {}
    std::size_t run(std::uint8_t *b, std::size_t n) override
    {
        static constexpr bool kAllowed[8] = {true, true, true, false, true, false, false, false};
        static constexpr int kByteOf[8] = {0, 1, 2, 2, 3, 3, 3, 3};
        if (n < 5) return 0;
        if (ip_ - last_ > 5) last_ = ip_ - 5;
        std::size_t i = 0;
        while (i + 5 <= n) {
            if ((b[i] & 0xFE) != 0xE8) { ++i; continue; }
            const std::uint32_t here = ip_ + std::uint32_t(i);
            const std::uint32_t gap = here - last_;
            last_ = here;
            if (gap > 5) {
                mask_ = 0;
            } else {
                for (std::uint32_t k = 0; k < gap; ++k) mask_ = (mask_ & 0x77) << 1;
            }
            std::uint8_t hi = b[i + 4];
            if (x86_ms_byte(hi) && kAllowed[(mask_ >> 1) & 7] && (mask_ >> 1) < 0x10) {
                std::uint32_t v = le32(b + i + 1), out;
                for (;;) {
                    out = enc_ ? v + (here + 5) : v - (here + 5);
                    if (mask_ == 0) break;
                    const int k = kByteOf[mask_ >> 1];
                    if (!x86_ms_byte(std::uint8_t(out >> (24 - 8 * k)))) break;
                    v = out ^ ((1u << (32 - 8 * k)) - 1);
                }
                out = (out & 0x00FFFFFF) | (((out >> 24) & 1) ? 0xFF000000u : 0);
                put_le32(b + i + 1, out);
                i += 5;
                mask_ = 0;
            } else {
                ++i;
                mask_ |= 1;
                if (x86_ms_byte(hi)) mask_ |= 0x10;
            }
        }
        ip_ += std::uint32_t(i);
        return i;
    }

private:
    bool enc_;
    std::uint32_t ip_, last_, mask_ = 0;
};

// Filters over fixed-size instructions: run() walks whole steps and lets
// convert() look at each one.
class Fixed : public Filter {
public:
    Fixed(bool enc, std::uint32_t start, std::size_t step, std::size_t width)
        : enc_(enc), ip_(start), step_(step), width_(width) {}
    std::size_t run(std::uint8_t *b, std::size_t n) override
    {
        std::size_t i = 0;
        while (i + width_ <= n) i += convert(b + i, ip_ + std::uint32_t(i));
        ip_ += std::uint32_t(i);
        return i;
    }

protected:
    // Returns how far to move (a multiple of the alignment).
    virtual std::size_t convert(std::uint8_t *p, std::uint32_t pc) = 0;
    std::uint32_t rel(std::uint32_t v, std::uint32_t pc) const { return enc_ ? v + pc : v - pc; }
    bool enc_;
    std::uint32_t ip_;
    std::size_t step_, width_;
};

class Arm final : public Fixed {
public:
    Arm(bool e, std::uint32_t s) : Fixed(e, s, 4, 4) {}
    std::size_t convert(std::uint8_t *p, std::uint32_t pc) override
    {
        if (p[3] == 0xEB) {
            std::uint32_t v = (std::uint32_t(p[2]) << 16 | std::uint32_t(p[1]) << 8 | p[0]) << 2;
            v = rel(v, pc + 8) >> 2;
            p[0] = std::uint8_t(v);
            p[1] = std::uint8_t(v >> 8);
            p[2] = std::uint8_t(v >> 16);
        }
        return 4;
    }
};

class Armt final : public Fixed {
public:
    Armt(bool e, std::uint32_t s) : Fixed(e, s, 2, 4) {}
    std::size_t convert(std::uint8_t *p, std::uint32_t pc) override
    {
        if ((p[1] & 0xF8) != 0xF0 || (p[3] & 0xF8) != 0xF8) return 2;
        std::uint32_t v = ((std::uint32_t(p[1] & 7) << 19) | std::uint32_t(p[0]) << 11 |
                           std::uint32_t(p[3] & 7) << 8 | p[2]) << 1;
        v = rel(v, pc + 4) >> 1;
        p[1] = std::uint8_t(0xF0 | ((v >> 19) & 7));
        p[0] = std::uint8_t(v >> 11);
        p[3] = std::uint8_t(0xF8 | ((v >> 8) & 7));
        p[2] = std::uint8_t(v);
        return 4;
    }
};

class Arm64 final : public Fixed {
public:
    Arm64(bool e, std::uint32_t s) : Fixed(e, s, 4, 4) {}
    std::size_t convert(std::uint8_t *p, std::uint32_t pc) override
    {
        std::uint32_t ins = le32(p);
        if ((ins >> 26) == 0x25) { // BL
            const std::uint32_t off = enc_ ? pc >> 2 : 0u - (pc >> 2);
            put_le32(p, 0x94000000u | ((ins + off) & 0x03FFFFFF));
        } else if ((ins & 0x9F000000u) == 0x90000000u) { // ADRP
            const std::uint32_t v = ((ins >> 29) & 3) | ((ins >> 3) & 0x001FFFFC);
            if ((v + 0x00020000) & 0x001C0000) return 4; // only targets within +-512 MiB
            const std::uint32_t off = enc_ ? pc >> 12 : 0u - (pc >> 12);
            const std::uint32_t d = v + off;
            ins &= 0x9000001Fu;
            ins |= (d & 3) << 29;
            ins |= (d & 0x0003FFFC) << 3;
            ins |= (0u - (d & 0x00020000)) & 0x00E00000;
            put_le32(p, ins);
        }
        return 4;
    }
};

class Ppc final : public Fixed {
public:
    Ppc(bool e, std::uint32_t s) : Fixed(e, s, 4, 4) {}
    std::size_t convert(std::uint8_t *p, std::uint32_t pc) override
    {
        if ((p[0] >> 2) == 0x12 && (p[3] & 3) == 1) {
            std::uint32_t v = std::uint32_t(p[0] & 3) << 24 | std::uint32_t(p[1]) << 16 | std::uint32_t(p[2]) << 8 |
                              (p[3] & ~3u);
            v = rel(v, pc);
            p[0] = std::uint8_t(0x48 | ((v >> 24) & 3));
            p[1] = std::uint8_t(v >> 16);
            p[2] = std::uint8_t(v >> 8);
            p[3] = std::uint8_t((p[3] & 3) | (v & ~3u));
        }
        return 4;
    }
};

class Sparc final : public Fixed {
public:
    Sparc(bool e, std::uint32_t s) : Fixed(e, s, 4, 4) {}
    std::size_t convert(std::uint8_t *p, std::uint32_t pc) override
    {
        if ((p[0] == 0x40 && (p[1] & 0xC0) == 0) || (p[0] == 0x7F && (p[1] & 0xC0) == 0xC0)) {
            std::uint32_t v = rel(be32(p) << 2, pc) >> 2;
            v = (((0u - ((v >> 22) & 1)) << 22) & 0x3FFFFFFF) | (v & 0x3FFFFF) | 0x40000000;
            p[0] = std::uint8_t(v >> 24);
            p[1] = std::uint8_t(v >> 16);
            p[2] = std::uint8_t(v >> 8);
            p[3] = std::uint8_t(v);
        }
        return 4;
    }
};

class Ia64 final : public Fixed {
public:
    Ia64(bool e, std::uint32_t s) : Fixed(e, s, 16, 16) {}
    std::size_t convert(std::uint8_t *p, std::uint32_t pc) override
    {
        // Which of the three 41-bit slots of a bundle hold a branch, by template.
        static constexpr std::uint8_t kSlots[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                    4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0};
        const unsigned mask = kSlots[p[0] & 0x1F];
        for (unsigned slot = 0, bit = 5; slot < 3; ++slot, bit += 41) {
            if (!((mask >> slot) & 1)) continue;
            const unsigned at = bit >> 3, shift = bit & 7;
            std::uint64_t raw = 0;
            for (unsigned j = 0; j < 6; ++j) raw |= std::uint64_t(p[at + j]) << (8 * j);
            std::uint64_t ins = raw >> shift;
            if (((ins >> 37) & 0xF) != 0x5 || ((ins >> 9) & 7) != 0) continue;
            std::uint32_t v = std::uint32_t((ins >> 13) & 0xFFFFF) | std::uint32_t((ins >> 36) & 1) << 20;
            v = rel(v << 4, pc) >> 4;
            ins &= ~(std::uint64_t(0x8FFFFF) << 13);
            ins |= std::uint64_t(v & 0xFFFFF) << 13;
            ins |= std::uint64_t(v & 0x100000) << (36 - 20);
            raw = (raw & ((std::uint64_t(1) << shift) - 1)) | ins << shift;
            for (unsigned j = 0; j < 6; ++j) p[at + j] = std::uint8_t(raw >> (8 * j));
        }
        return 16;
    }
};

class Delta final : public Filter {
public:
    Delta(bool enc, unsigned dist) : enc_(enc), dist_(dist) { std::memset(hist_, 0, sizeof hist_); }
    std::size_t run(std::uint8_t *b, std::size_t n) override
    {
        for (std::size_t i = 0; i < n; ++i) {
            std::uint8_t &prev = hist_[std::uint8_t(pos_ - dist_)];
            if (enc_) {
                const std::uint8_t orig = b[i];
                b[i] = std::uint8_t(orig - prev);
                hist_[pos_] = orig;
            } else {
                b[i] = std::uint8_t(b[i] + prev);
                hist_[pos_] = b[i];
            }
            ++pos_;
        }
        return n;
    }

private:
    bool enc_;
    unsigned dist_;
    std::uint8_t hist_[256];
    std::uint8_t pos_ = 0;
};

constexpr std::uint32_t kTop = 1u << 24;
constexpr int kProbBits = 11, kMoveBits = 5;

bool is_jump(std::uint8_t prev, std::uint8_t b) { return (b & 0xFE) == 0xE8 || (prev == 0x0F && (b & 0xF0) == 0x80); }

std::uint16_t &prob_for(std::uint16_t *probs, std::uint8_t prev, std::uint8_t b)
{
    return b == 0xE8 ? probs[prev] : b == 0xE9 ? probs[256] : probs[257];
}

} // namespace

std::unique_ptr<Filter> make_filter(Kind k, bool enc, std::uint32_t start, unsigned dist)
{
    switch (k) {
    case Kind::X86: return std::make_unique<X86>(enc, start);
    case Kind::Arm: return std::make_unique<Arm>(enc, start);
    case Kind::Armt: return std::make_unique<Armt>(enc, start);
    case Kind::Arm64: return std::make_unique<Arm64>(enc, start);
    case Kind::Ppc: return std::make_unique<Ppc>(enc, start);
    case Kind::Sparc: return std::make_unique<Sparc>(enc, start);
    case Kind::Ia64: return std::make_unique<Ia64>(enc, start);
    case Kind::Delta: return std::make_unique<Delta>(enc, std::clamp(dist, 1u, 256u));
    case Kind::RiscV: break;
    }
    fail(ErrorCode::UnsupportedMethod, "this branch filter is not supported");
}

// ---- BCJ2 decoder

Bcj2Decoder::Bcj2Decoder(Pull pull, void *ctx, std::uint64_t out_size) : pull_(pull), ctx_(ctx), left_(out_size)
{
    std::fill(std::begin(probs_), std::end(probs_), std::uint16_t(1 << (kProbBits - 1)));
}

int Bcj2Decoder::byte(int s)
{
    if (at_[s] == have_[s]) {
        have_[s] = pull_(ctx_, s, buf_[s], sizeof buf_[s]);
        at_[s] = 0;
        if (have_[s] == 0) return -1;
    }
    return buf_[s][at_[s]++];
}

bool Bcj2Decoder::bit(std::uint16_t &prob)
{
    if (!rc_started_) {
        for (int i = 0; i < 5; ++i) {
            const int c = byte(3);
            if (c < 0) fail(ErrorCode::Truncated, "BCJ2 data ends early");
            code_ = code_ << 8 | std::uint32_t(c);
        }
        rc_started_ = true;
    }
    const std::uint32_t bound = (range_ >> kProbBits) * prob;
    bool one;
    if (code_ < bound) {
        range_ = bound;
        prob = std::uint16_t(prob + (((1 << kProbBits) - prob) >> kMoveBits));
        one = false;
    } else {
        range_ -= bound;
        code_ -= bound;
        prob = std::uint16_t(prob - (prob >> kMoveBits));
        one = true;
    }
    if (range_ < kTop) {
        const int c = byte(3);
        if (c < 0) fail(ErrorCode::Truncated, "BCJ2 data ends early");
        range_ <<= 8;
        code_ = code_ << 8 | std::uint32_t(c);
    }
    return one;
}

std::size_t Bcj2Decoder::read(std::uint8_t *out, std::size_t n)
{
    std::size_t done = 0;
    while (done < n && left_ > 0) {
        if (ipending_ < npending_) {
            out[done++] = pending_[ipending_++];
            ++pos_;
            --left_;
            continue;
        }
        const int c = byte(0);
        if (c < 0) fail(ErrorCode::Truncated, "BCJ2 main stream ends early");
        const auto b = std::uint8_t(c);
        out[done++] = b;
        ++pos_;
        --left_;
        if (!is_jump(prev_, b) || left_ == 0) {
            prev_ = b;
            continue;
        }
        if (!bit(prob_for(probs_, prev_, b))) {
            prev_ = b;
            continue;
        }
        const int s = b == 0xE8 ? 1 : 2;
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            const int x = byte(s);
            if (x < 0) fail(ErrorCode::Truncated, "BCJ2 call stream ends early");
            v = v << 8 | std::uint32_t(x);
        }
        const std::uint32_t d = v - std::uint32_t(pos_ + 4);
        put_le32(pending_, d);
        npending_ = 4;
        ipending_ = 0;
        prev_ = std::uint8_t(d >> 24);
    }
    return done;
}

// ---- BCJ2 encoder

Bcj2Encoder::Bcj2Encoder(std::uint64_t size) : size_(size)
{
    std::fill(std::begin(probs_), std::end(probs_), std::uint16_t(1 << (kProbBits - 1)));
}

void Bcj2Encoder::shift_low()
{
    if (std::uint32_t(low_) < 0xFF000000u || (low_ >> 32) != 0) {
        std::uint8_t carry = std::uint8_t(low_ >> 32);
        std::uint8_t c = cache_;
        do {
            rc.push_back(std::uint8_t(c + carry));
            c = 0xFF;
        } while (--cache_size_ != 0);
        cache_ = std::uint8_t(std::uint32_t(low_) >> 24);
    }
    ++cache_size_;
    low_ = (low_ & 0x00FFFFFFu) << 8;
}

void Bcj2Encoder::encode_bit(std::uint16_t &prob, int bit)
{
    const std::uint32_t bound = (range_ >> kProbBits) * prob;
    if (!bit) {
        range_ = bound;
        prob = std::uint16_t(prob + (((1 << kProbBits) - prob) >> kMoveBits));
    } else {
        low_ += bound;
        range_ -= bound;
        prob = std::uint16_t(prob - (prob >> kMoveBits));
    }
    while (range_ < kTop) {
        range_ <<= 8;
        shift_low();
    }
}

void Bcj2Encoder::write(const std::uint8_t *data, std::size_t n)
{
    pend_.insert(pend_.end(), data, data + n);
    if (pend_.size() >= (1 << 20)) process(false);
}

void Bcj2Encoder::process(bool last)
{
    std::size_t i = 0;
    const std::size_t n = pend_.size();
    while (i < n) {
        if (!last && i + 5 > n) break; // need the 4 bytes after an opcode
        const std::uint8_t b = pend_[i];
        main.push_back(b);
        ++i;
        if (!is_jump(prev_, b)) { prev_ = b; continue; }
        if (last && i == n) break; // final byte: the decoder reads no bit for it
        auto &prob = prob_for(probs_, prev_, b);
        if (i + 4 > n) { encode_bit(prob, 0); prev_ = b; continue; }
        const std::uint32_t at = std::uint32_t(pos_ + i); // position after the opcode
        const std::uint32_t abs = le32(&pend_[i]) + at + 4;
        if (abs < size_) {
            encode_bit(prob, 1);
            auto &dst = b == 0xE8 ? call : jump;
            for (int k = 3; k >= 0; --k) dst.push_back(std::uint8_t(abs >> (8 * k)));
            prev_ = pend_[i + 3];
            i += 4;
        } else {
            encode_bit(prob, 0);
            prev_ = b;
        }
    }
    pos_ += i;
    pend_.erase(pend_.begin(), pend_.begin() + std::ptrdiff_t(i));
}

void Bcj2Encoder::finish()
{
    process(true);
    for (int i = 0; i < 5; ++i) shift_low();
}

} // namespace raye::archive::detail::filters
