// SPDX-License-Identifier: GPL-3.0-or-later
// Unix compress (.Z): LZW with 9 to 16 bit codes.
#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace raye::archive::detail {

class LzwDecoder {
public:
    explicit LzwDecoder(std::uint8_t flags); // third header byte
    // Decodes from in (sets used) into out; returns bytes written. eof: in is
    // all there is. Returns 0 with eof once the data is over.
    std::size_t decode(std::span<const std::uint8_t> in, std::size_t &used, std::uint8_t *out, std::size_t n, bool eof);

private:
    bool getbits(std::span<const std::uint8_t> in, std::size_t &used, unsigned width, unsigned &code);
    void reset_section(unsigned width);

    std::vector<std::uint16_t> prefix_;
    std::vector<std::uint8_t> suffix_, stack_;
    std::size_t top_ = 0; // stack_[top_..] is output still to hand out
    std::uint32_t bitbuf_ = 0;
    unsigned avail_ = 0, width_ = 9, maxbits_, section_bytes_ = 0, skip_ = 0;
    unsigned free_ = 257, section_end_ = 511, maxmax_;
    int old_ = -1;
    std::uint8_t fin_ = 0;
    bool block_;
};

} // namespace raye::archive::detail
