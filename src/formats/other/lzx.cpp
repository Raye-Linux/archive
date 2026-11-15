// SPDX-License-Identifier: GPL-3.0-or-later
#include "lzx.h"

#include "../../core/bytes.h"

#include <algorithm>

namespace raye::archive::detail {

namespace {
[[noreturn]] void damaged() { fail(ErrorCode::Corrupt, "LZX data is damaged"); }
}

void LzxDecoder::Tree::build()
{
    unsigned count[17] = {};
    for (auto l : len) {
        if (l > 16) damaged();
        ++count[l];
    }
    count[0] = 0;
    unsigned code = 0, next[17] = {};
    long room = 1;
    for (int b = 1; b <= 16; ++b) {
        room = room * 2 - count[b];
        if (room < 0) damaged(); // more codes than the lengths allow
        code = (code + count[b - 1]) << 1;
        next[b] = code;
    }
    table.assign(1u << 16, 0);
    for (std::size_t s = 0; s < len.size(); ++s) {
        const unsigned l = len[s];
        if (!l) continue;
        const unsigned c = next[l]++;
        const unsigned lo = c << (16 - l), hi = (c + 1) << (16 - l);
        std::fill(table.begin() + lo, table.begin() + hi, std::uint32_t(s) << 8 | l);
    }
}

LzxDecoder::LzxDecoder(unsigned wbits)
{
    if (wbits < 15 || wbits > 21) fail(ErrorCode::UnsupportedMethod, "LZX window size is not supported");
    wsize_ = 1u << wbits;
    window_.assign(wsize_, 0);
    static const unsigned slots[] = {30, 32, 34, 36, 38, 42, 50};
    slots_ = slots[wbits - 15];
    extra_.resize(slots_);
    base_.resize(slots_);
    std::uint32_t b = 0;
    for (unsigned i = 0; i < slots_; ++i) {
        extra_[i] = std::uint8_t(i < 4 ? 0 : std::min<unsigned>(i / 2 - 1, 17));
        base_[i] = b;
        b += 1u << extra_[i];
    }
    main_.len.assign(256 + slots_ * 8, 0);
    length_.len.assign(249, 0);
    aligned_.len.assign(8, 0);
    pre_.len.assign(20, 0);
}

void LzxDecoder::need(unsigned n)
{
    while (left_ < n) {
        std::uint32_t w = 0;
        if (*pos_ + 1 < in_.size()) w = std::uint32_t(in_[*pos_]) | std::uint32_t(in_[*pos_ + 1]) << 8;
        else if (++pad_ > 64) fail(ErrorCode::Truncated, "LZX data ends early");
        *pos_ += 2;
        buf_ |= w << (16 - left_);
        left_ += 16;
    }
}

unsigned LzxDecoder::peek(unsigned n) { return n ? buf_ >> (32 - n) : 0; }
void LzxDecoder::drop(unsigned n) { buf_ = n >= 32 ? 0 : buf_ << n; left_ -= n; }
unsigned LzxDecoder::bits(unsigned n)
{
    need(n);
    const unsigned v = peek(n);
    drop(n);
    return v;
}

unsigned LzxDecoder::sym(const Tree &t)
{
    need(16);
    const std::uint32_t v = t.table[peek(16)];
    if (!v) damaged();
    drop(v & 0xff);
    return v >> 8;
}

void LzxDecoder::read_lens(Tree &t, std::size_t first, std::size_t last)
{
    for (auto &l : pre_.len) l = std::uint8_t(bits(4));
    pre_.build();
    std::size_t x = first;
    while (x < last) {
        unsigned z = sym(pre_);
        if (z == 17 || z == 18) {
            unsigned run = z == 17 ? bits(4) + 4 : bits(5) + 20;
            if (x + run > last) damaged();
            while (run--) t.len[x++] = 0;
        } else if (z == 19) {
            unsigned run = bits(1) + 4;
            z = sym(pre_);
            if (z > 16 || x + run > last) damaged();
            const std::uint8_t v = std::uint8_t((t.len[x] + 17 - z) % 17);
            while (run--) t.len[x++] = v;
        } else {
            t.len[x] = std::uint8_t((t.len[x] + 17 - z) % 17);
            ++x;
        }
    }
}

void LzxDecoder::header()
{
    type_ = int(bits(3));
    const unsigned hi = bits(16), lo = bits(8);
    block_len_ = block_left_ = hi << 8 | lo;
    switch (type_) {
    case 2: // aligned offsets: an extra 8-symbol tree, then as verbatim
        for (auto &l : aligned_.len) l = std::uint8_t(bits(3));
        aligned_.build();
        [[fallthrough]];
    case 1:
        read_lens(main_, 0, 256);
        read_lens(main_, 256, main_.len.size());
        main_.build();
        read_lens(length_, 0, 249);
        length_.build();
        break;
    case 3: // stored: realign to bytes, then R0 R1 R2
        if (left_ == 0) need(16);
        left_ = 0;
        buf_ = 0;
        if (*pos_ + 12 > in_.size()) fail(ErrorCode::Truncated, "LZX data ends early");
        for (int i = 0; i < 3; ++i) r_[i] = le32(&in_[*pos_ + std::size_t(i) * 4]);
        *pos_ += 12;
        break;
    default: damaged();
    }
}

void LzxDecoder::frame(std::span<const std::uint8_t> in, std::size_t &pos, std::span<std::uint8_t> out)
{
    in_ = in;
    pos_ = &pos;
    pad_ = 0;
    if (!header_read_) {
        if (bits(1)) {
            const unsigned hi = bits(16), lo = bits(16);
            intel_size_ = hi << 16 | lo;
        }
        header_read_ = true;
    }
    const std::uint64_t frame_start = produced_, frame_end = produced_ + out.size();
    if (out.size() > 32768 || (frame_start % wsize_) + out.size() > wsize_) damaged();
    while (produced_ < frame_end) {
        if (block_left_ == 0) {
            if (type_ == 3) {
                if (block_len_ & 1) ++*pos_; // stored blocks are padded to an even size
                left_ = 0;
                buf_ = 0;
            }
            header();
            if (block_len_ == 0) damaged();
        }
        if (type_ == 3) {
            const std::size_t k = std::size_t(std::min<std::uint64_t>(block_left_, frame_end - produced_));
            if (*pos_ + k > in_.size()) fail(ErrorCode::Truncated, "LZX data ends early");
            std::copy_n(&in_[*pos_], k, &window_[wpos_]);
            *pos_ += k;
            wpos_ = (wpos_ + std::uint32_t(k)) & (wsize_ - 1);
            produced_ += k;
            block_left_ -= std::uint32_t(k);
            continue;
        }
        while (block_left_ && produced_ < frame_end) {
            const unsigned m = sym(main_);
            if (m < 256) {
                window_[wpos_] = std::uint8_t(m);
                wpos_ = (wpos_ + 1) & (wsize_ - 1);
                ++produced_;
                --block_left_;
                continue;
            }
            const unsigned me = m - 256;
            std::uint32_t len = me & 7;
            if (len == 7) len += sym(length_);
            len += 2;
            const unsigned slot = me >> 3;
            std::uint32_t off;
            if (slot > 2) {
                const unsigned ex = extra_[slot];
                off = base_[slot] - 2;
                if (type_ == 2 && ex >= 3) {
                    if (ex > 3) off += bits(ex - 3) << 3;
                    off += sym(aligned_);
                } else if (ex) {
                    off += bits(ex);
                }
                r_[2] = r_[1];
                r_[1] = r_[0];
                r_[0] = off;
            } else if (slot == 0) {
                off = r_[0];
            } else {
                off = r_[slot];
                r_[slot] = r_[0];
                r_[0] = off;
            }
            if (len > block_left_ || wpos_ + len > wsize_ || off == 0 || off > wsize_) damaged();
            std::uint32_t src = (wpos_ + wsize_ - off) & (wsize_ - 1);
            for (std::uint32_t i = 0; i < len; ++i) {
                window_[wpos_ + i] = window_[src];
                src = (src + 1) & (wsize_ - 1);
            }
            wpos_ = (wpos_ + len) & (wsize_ - 1);
            produced_ += len;
            block_left_ -= len;
        }
    }
    std::copy_n(&window_[frame_start % wsize_], out.size(), out.data());
    // E8 fixup: CALL targets were made absolute by the compressor.
    if (intel_size_ && frame_no_ < 32768 && out.size() > 10) {
        std::int64_t cur = std::int64_t(frame_start);
        for (std::size_t i = 0; i < out.size() - 10;) {
            if (out[i] != 0xe8) { ++i; ++cur; continue; }
            const std::int32_t abs = std::int32_t(le32(&out[i + 1]));
            if (abs >= -cur && abs < std::int64_t(intel_size_)) {
                const std::int32_t rel = abs >= 0 ? std::int32_t(abs - cur) : std::int32_t(abs + std::int64_t(intel_size_));
                put_le32(&out[i + 1], std::uint32_t(rel));
            }
            i += 5;
            cur += 5;
        }
    }
    ++frame_no_;
    // Frames start on a 16-bit boundary of the input.
    if (left_ > 0) need(16);
    if (left_ & 15) drop(left_ & 15);
}

} // namespace raye::archive::detail
