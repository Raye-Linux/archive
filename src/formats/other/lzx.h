// SPDX-License-Identifier: GPL-3.0-or-later
// LZX as used in Microsoft cabinets: 32 KiB frames, Huffman trees carried
// over between blocks, three repeated offsets and the Intel E8 call fixup.
#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace raye::archive::detail {

class LzxDecoder {
public:
    explicit LzxDecoder(unsigned window_bits); // 15..21
    // Decodes one frame (out.size() bytes, 32768 except the last) from the
    // folder's compressed bytes, which are fed through more() when needed.
    // Input bytes are taken from in at pos, which advances.
    void frame(std::span<const std::uint8_t> in, std::size_t &pos, std::span<std::uint8_t> out);

private:
    struct Tree {
        std::vector<std::uint8_t> len;
        std::vector<std::uint32_t> table; // (symbol << 8) | length, indexed by 16 peeked bits
        void build();
    };
    void need(unsigned n);
    unsigned peek(unsigned n);
    void drop(unsigned n);
    unsigned bits(unsigned n);
    unsigned sym(const Tree &t);
    void read_lens(Tree &t, std::size_t first, std::size_t last);
    void header();
    void align16();

    std::span<const std::uint8_t> in_;
    std::size_t *pos_ = nullptr;
    std::uint32_t buf_ = 0;
    unsigned left_ = 0;

    std::vector<std::uint8_t> window_;
    std::uint32_t wsize_, wpos_ = 0, slots_;
    std::uint32_t r_[3] = {1, 1, 1};
    Tree main_, length_, aligned_, pre_;
    int type_ = 0;
    std::uint32_t block_len_ = 0, block_left_ = 0;
    bool header_read_ = false;
    unsigned pad_ = 0; // zero words read past the end
    std::uint32_t intel_size_ = 0;
    std::uint64_t frame_no_ = 0, produced_ = 0;
    std::vector<std::uint32_t> base_;
    std::vector<std::uint8_t> extra_;
};

} // namespace raye::archive::detail
