// SPDX-License-Identifier: GPL-3.0-or-later
// Deflate64 ("enhanced deflate", PKWARE method 9): deflate with a 64 KiB
// window, length code 285 carrying 16 extra bits and distance codes 30-31.
//
// Push decoder: input is buffered and a symbol is only started when enough
// bits are there for the worst case, so no state has to survive halfway
// through a symbol. Output goes through a history buffer the caller drains.
#include "zip.h"

#include <algorithm>
#include <cstring>

namespace raye::archive::detail::zip {

namespace {

constexpr std::size_t kWindow = 65536;
constexpr std::size_t kMargin = 1024;       // bytes: worst block header is ~570
constexpr std::size_t kMaxPending = 256 << 10;
constexpr int kFastBits = 9;

[[noreturn]] void corrupt(const char *what) { fail(ErrorCode::Corrupt, std::string("Deflate64 data is damaged (") + what + ")"); }

constexpr std::uint16_t kLenBase[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27,
                                        31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 3};
constexpr std::uint8_t kLenExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                        2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16};
constexpr std::uint32_t kDistBase[32] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
                                         257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
                                         8193, 12289, 16385, 24577, 32769, 49153};
constexpr std::uint8_t kDistExtra[32] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
                                         7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14};
constexpr std::uint8_t kOrder[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

// Canonical Huffman code: a 9-bit lookup for short codes, bit-by-bit walk
// over (count, symbols) for the rest.
struct Huffman {
    std::uint16_t count[16]{};
    std::vector<std::uint16_t> symbols;
    std::uint16_t fast[1 << kFastBits]{}; // (symbol << 4) | length, 0 = slow path

    void build(const std::uint8_t *lengths, std::size_t n)
    {
        std::fill(std::begin(count), std::end(count), std::uint16_t(0));
        for (std::size_t i = 0; i < n; ++i) ++count[lengths[i]];
        count[0] = 0;
        int left = 1;
        for (int len = 1; len < 16; ++len) {
            left <<= 1;
            left -= count[len];
            if (left < 0) corrupt("over-subscribed code");
        }
        std::uint16_t offs[16]{};
        for (int len = 1; len < 15; ++len) offs[len + 1] = std::uint16_t(offs[len] + count[len]);
        symbols.assign(n, 0);
        for (std::size_t i = 0; i < n; ++i)
            if (lengths[i]) symbols[offs[lengths[i]]++] = std::uint16_t(i);
        std::fill(std::begin(fast), std::end(fast), std::uint16_t(0));
        // Walk the canonical codes in order and fill the reversed-bit table.
        std::uint32_t code = 0;
        std::size_t idx = 0;
        for (int len = 1; len <= kFastBits; ++len) {
            for (int k = 0; k < count[len]; ++k, ++code, ++idx) {
                std::uint32_t rev = 0;
                for (int b = 0; b < len; ++b) rev |= ((code >> b) & 1) << (len - 1 - b);
                for (std::uint32_t r = rev; r < (1u << kFastBits); r += 1u << len)
                    fast[r] = std::uint16_t(symbols[idx] << 4 | len);
            }
            code <<= 1;
        }
    }
};

class Inflate64 final : public Coder {
public:
    CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) override
    {
        CodeStep s;
        if (ipos_ > (64 << 10)) {
            in_.erase(in_.begin(), in_.begin() + std::ptrdiff_t(ipos_));
            ipos_ = 0;
        }
        const std::size_t room = in_.size() - ipos_ < kMaxPending ? kMaxPending - (in_.size() - ipos_) : 0;
        s.consumed = std::min(room, in.size());
        in_.insert(in_.end(), in.begin(), in.begin() + std::ptrdiff_t(s.consumed));
        last_ = finish && s.consumed == in.size();

        decode();

        const std::size_t n = std::min(out.size(), buf_.size() - emit_);
        if (n) std::memcpy(out.data(), buf_.data() + emit_, n);
        emit_ += n;
        s.produced = n;
        // Keep 64 KiB of history behind the write position.
        if (emit_ > (1 << 20) + kWindow && buf_.size() > kWindow) {
            const std::size_t cut = std::min(emit_, buf_.size() - kWindow);
            buf_.erase(buf_.begin(), buf_.begin() + std::ptrdiff_t(cut));
            emit_ -= cut;
        }
        s.done = state_ == State::Done && emit_ == buf_.size();
        return s;
    }

private:
    enum class State { Header, Stored, Codes, Done };

    std::size_t avail_bits() const { return (in_.size() - ipos_) * 8 + std::size_t(nbits_); }
    bool enough() const { return last_ || avail_bits() >= kMargin * 8; }

    void need(int n)
    {
        while (nbits_ < n) {
            if (ipos_ >= in_.size()) fail(ErrorCode::Truncated, "Deflate64 data ends early");
            bits_ |= std::uint64_t(in_[ipos_++]) << nbits_;
            nbits_ += 8;
        }
    }
    std::uint32_t get(int n)
    {
        if (n == 0) return 0;
        need(n);
        const auto v = std::uint32_t(bits_ & ((std::uint64_t(1) << n) - 1));
        bits_ >>= n;
        nbits_ -= n;
        return v;
    }
    // Peeks up to n bits without failing at the very end of the stream.
    std::uint32_t peek(int n)
    {
        while (nbits_ < n && ipos_ < in_.size()) {
            bits_ |= std::uint64_t(in_[ipos_++]) << nbits_;
            nbits_ += 8;
        }
        return std::uint32_t(bits_ & ((std::uint64_t(1) << n) - 1));
    }

    int symbol(const Huffman &h)
    {
        const std::uint16_t f = h.fast[peek(kFastBits)];
        if (f) {
            const int len = f & 15;
            if (len > nbits_) fail(ErrorCode::Truncated, "Deflate64 data ends early");
            bits_ >>= len;
            nbits_ -= len;
            return f >> 4;
        }
        int code = 0, first = 0, index = 0;
        for (int len = 1; len < 16; ++len) {
            code |= int(get(1));
            const int count = h.count[len];
            if (code - first < count) return h.symbols[std::size_t(index + code - first)];
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        corrupt("bad code");
    }

    void header()
    {
        final_ = get(1);
        const auto type = get(2);
        if (type == 0) {
            bits_ >>= nbits_ % 8;
            nbits_ -= nbits_ % 8;
            const auto len = get(16), nlen = get(16);
            if ((len ^ 0xffff) != nlen) corrupt("stored block length");
            stored_ = len;
            state_ = State::Stored;
        } else if (type == 1) {
            std::uint8_t l[320];
            std::fill(l, l + 144, 8);
            std::fill(l + 144, l + 256, 9);
            std::fill(l + 256, l + 280, 7);
            std::fill(l + 280, l + 288, 8);
            lit_.build(l, 288);
            std::fill(l, l + 32, 5);
            dist_.build(l, 32);
            state_ = State::Codes;
        } else if (type == 2) {
            dynamic();
            state_ = State::Codes;
        } else {
            corrupt("block type 3");
        }
    }

    void dynamic()
    {
        const unsigned nlit = get(5) + 257, ndist = get(5) + 1, ncode = get(4) + 4;
        if (nlit > 286) corrupt("too many length codes");
        std::uint8_t cl[19]{};
        for (unsigned i = 0; i < ncode; ++i) cl[kOrder[i]] = std::uint8_t(get(3));
        Huffman ch;
        ch.build(cl, 19);
        std::uint8_t l[320]{};
        unsigned i = 0;
        while (i < nlit + ndist) {
            const int sym = symbol(ch);
            if (sym < 16) { l[i++] = std::uint8_t(sym); continue; }
            unsigned rep;
            std::uint8_t v = 0;
            if (sym == 16) {
                if (i == 0) corrupt("repeat with nothing before");
                v = l[i - 1];
                rep = 3 + get(2);
            } else if (sym == 17) {
                rep = 3 + get(3);
            } else {
                rep = 11 + get(7);
            }
            if (i + rep > nlit + ndist) corrupt("too many code lengths");
            std::fill(l + i, l + i + rep, v);
            i += rep;
        }
        if (l[256] == 0) corrupt("no end-of-block code");
        lit_.build(l, nlit);
        dist_.build(l + nlit, ndist);
    }

    void put(std::uint8_t b)
    {
        buf_.push_back(b);
        ++total_;
    }

    void decode()
    {
        while (state_ != State::Done && buf_.size() - emit_ < kMaxPending) {
            if (state_ == State::Header) {
                if (!enough()) return;
                header();
            } else if (state_ == State::Stored) {
                // Whole bytes still in the bit buffer go first.
                while (stored_ && nbits_ >= 8) {
                    put(std::uint8_t(bits_));
                    bits_ >>= 8;
                    nbits_ -= 8;
                    --stored_;
                }
                const std::size_t n = std::min<std::size_t>({stored_, in_.size() - ipos_, kMaxPending});
                buf_.insert(buf_.end(), in_.begin() + std::ptrdiff_t(ipos_), in_.begin() + std::ptrdiff_t(ipos_ + n));
                ipos_ += n;
                total_ += n;
                stored_ -= std::uint32_t(n);
                if (stored_) {
                    if (last_ && ipos_ == in_.size()) fail(ErrorCode::Truncated, "Deflate64 data ends early");
                    return;
                }
                state_ = final_ ? State::Done : State::Header;
            } else {
                for (int k = 0; k < 4096 && state_ == State::Codes; ++k) {
                    if (!enough()) return;
                    const int sym = symbol(lit_);
                    if (sym < 256) {
                        put(std::uint8_t(sym));
                    } else if (sym == 256) {
                        state_ = final_ ? State::Done : State::Header;
                    } else {
                        if (sym > 285) corrupt("bad length code");
                        const std::uint32_t len = kLenBase[sym - 257] + get(kLenExtra[sym - 257]);
                        const int dsym = symbol(dist_);
                        if (dsym > 31) corrupt("bad distance code");
                        const std::uint32_t dist = kDistBase[dsym] + get(kDistExtra[dsym]);
                        if (dist > total_ || dist > kWindow) corrupt("distance too far back");
                        std::size_t from = buf_.size() - dist;
                        for (std::uint32_t j = 0; j < len; ++j) buf_.push_back(buf_[from + j]);
                        total_ += len;
                    }
                }
            }
        }
    }

    std::vector<std::uint8_t> in_, buf_;
    std::size_t ipos_ = 0, emit_ = 0;
    std::uint64_t bits_ = 0, total_ = 0;
    int nbits_ = 0;
    bool last_ = false;
    std::uint32_t final_ = 0, stored_ = 0;
    State state_ = State::Header;
    Huffman lit_, dist_;
};

} // namespace

std::unique_ptr<Coder> make_deflate64_decoder() { return std::make_unique<Inflate64>(); }

} // namespace raye::archive::detail::zip
