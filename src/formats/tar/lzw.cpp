// SPDX-License-Identifier: GPL-3.0-or-later
#include "lzw.h"

#include <raye/archive/error.h>

namespace raye::archive::detail {

LzwDecoder::LzwDecoder(std::uint8_t flags)
    : prefix_(1 << 16), suffix_(1 << 16), stack_((1 << 16) + 1), maxbits_(flags & 0x1f), block_(flags & 0x80)
{
    if (maxbits_ < 9 || maxbits_ > 16 || (flags & 0x60))
        fail(ErrorCode::UnsupportedMethod, ".Z file uses " + std::to_string(maxbits_) + "-bit codes");
    maxmax_ = 1u << maxbits_;
    top_ = stack_.size();
    free_ = block_ ? 257 : 256;
    for (unsigned i = 0; i < 256; ++i) suffix_[i] = std::uint8_t(i);
}

void LzwDecoder::reset_section(unsigned width)
{
    width_ = width;
    section_bytes_ = 0;
    section_end_ = width_ == maxbits_ ? maxmax_ - 1 : (1u << width_) - 1;
}

bool LzwDecoder::getbits(std::span<const std::uint8_t> in, std::size_t &used, unsigned width, unsigned &code)
{
    while (avail_ < width) {
        if (used >= in.size()) return false;
        bitbuf_ |= std::uint32_t(in[used++]) << avail_;
        avail_ += 8;
        ++section_bytes_;
    }
    code = bitbuf_ & ((1u << width) - 1);
    bitbuf_ >>= width;
    avail_ -= width;
    return true;
}

std::size_t LzwDecoder::decode(std::span<const std::uint8_t> in, std::size_t &used, std::uint8_t *out, std::size_t n, bool eof)
{
    std::size_t got = 0;
    used = 0;
    for (;;) {
        while (top_ < stack_.size() && got < n) out[got++] = stack_[top_++];
        if (got == n) return got;
        // After a clear code, compress padded the rest of its group of codes.
        while (skip_) {
            if (used >= in.size()) return got;
            ++used;
            --skip_;
        }
        unsigned code;
        if (!getbits(in, used, width_, code)) return got; // need more input, or the end
        if (code == 256 && block_) {
            skip_ = (width_ - section_bytes_ % width_) % width_;
            bitbuf_ = 0;
            avail_ = 0;
            reset_section(9);
            free_ = 257;
            old_ = -1;
            continue;
        }
        if (old_ < 0) {
            if (code >= 256) fail(ErrorCode::Corrupt, ".Z data is damaged");
            old_ = int(code);
            fin_ = std::uint8_t(code);
            stack_[--top_] = fin_;
            continue;
        }
        const unsigned incode = code;
        if (code >= free_) {
            if (code > free_) fail(ErrorCode::Corrupt, ".Z data is damaged");
            stack_[--top_] = fin_;
            code = unsigned(old_);
        }
        while (code >= 256) {
            stack_[--top_] = suffix_[code];
            code = prefix_[code];
        }
        fin_ = std::uint8_t(code);
        stack_[--top_] = fin_;
        if (free_ < maxmax_) {
            prefix_[free_] = std::uint16_t(old_);
            suffix_[free_] = fin_;
            ++free_;
        }
        old_ = int(incode);
        if (free_ > section_end_ && width_ < maxbits_) reset_section(width_ + 1);
    }
    (void)eof;
}

} // namespace raye::archive::detail
