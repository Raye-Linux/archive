// SPDX-License-Identifier: GPL-3.0-or-later
// PPMd variant H as RAR 2.9-4.x uses it: Shkarin's model with its
// carry-less range coder, model memory kept across solid files.
#pragma once

#include "rar.h"

#include <cstdint>
#include <vector>

namespace raye::archive::detail::rar {

class Ppmd {
public:
    // Reads the block parameters; esc may change. False on bad data.
    bool init(BitIn &in, int &esc);
    // Next byte, or -1 when the data is damaged.
    int decode_char();
    void reset() { heap_.clear(); ready_ = false; }

private:
    using Ref = std::uint32_t; // offset in heap_, 0 = null

    struct See {
        std::uint16_t summ;
        std::uint8_t shift, count;
        void init(unsigned v) { shift = 7 - 4; summ = std::uint16_t(v << shift); count = 4; }
        unsigned mean()
        {
            const unsigned r = unsigned(summ) >> shift;
            summ = std::uint16_t(summ - r);
            return r + (r == 0);
        }
        void update()
        {
            if (shift < 7 && --count == 0) {
                summ = std::uint16_t(summ + summ);
                count = std::uint8_t(3 << shift++);
            }
        }
    };

    // heap accessors
    std::uint8_t &b8(Ref r) { return heap_[r]; }
    std::uint16_t g16(Ref r) const { std::uint16_t v; std::memcpy(&v, &heap_[r], 2); return v; }
    void s16(Ref r, std::uint16_t v) { std::memcpy(&heap_[r], &v, 2); }
    Ref g32(Ref r) const { Ref v; std::memcpy(&v, &heap_[r], 4); return v; }
    void s32(Ref r, Ref v) { std::memcpy(&heap_[r], &v, 4); }
    // context: NumStats@0, SummFreq@2, Stats@4, Suffix@8; one state at @2
    std::uint16_t ns(Ref c) const { return g16(c); }
    Ref stats(Ref c) const { return g32(c + 4); }
    Ref suffix(Ref c) const { return g32(c + 8); }
    std::uint16_t summ(Ref c) const { return g16(c + 2); }
    // state: Symbol@0, Freq@1, Successor@2 (6 bytes)
    static Ref st(Ref base, unsigned i) { return base + 6 * i; }
    std::uint8_t sym(Ref s) const { return heap_[s]; }
    std::uint8_t &freq(Ref s) { return heap_[s + 1]; }
    std::uint8_t freqv(Ref s) const { return heap_[s + 1]; }
    Ref succ(Ref s) const { return g32(s + 2); }
    void set_succ(Ref s, Ref v) { s32(s + 2, v); }
    void swap_states(Ref a, Ref b)
    {
        std::uint8_t t[6];
        std::memcpy(t, &heap_[a], 6);
        std::memmove(&heap_[a], &heap_[b], 6);
        std::memcpy(&heap_[b], t, 6);
    }

    // sub-allocator
    void start_alloc(std::uint32_t mb);
    void init_alloc();
    void insert_node(Ref p, int indx);
    Ref remove_node(int indx);
    void split_block(Ref p, int old_indx, int new_indx);
    void glue_free_blocks();
    Ref alloc_units_rare(int indx);
    Ref alloc_units(int nu);
    Ref alloc_context();
    Ref expand_units(Ref old, int old_nu);
    Ref shrink_units(Ref old, int old_nu, int new_nu);
    void free_units(Ref p, int old_nu) { insert_node(p, units2indx_[old_nu - 1]); }
    static constexpr std::uint32_t U2B(int nu) { return 12u * std::uint32_t(nu); }

    // model
    void restart_model();
    void start_model(int max_order);
    void rescale(Ref ctx);
    Ref create_successors(bool skip, Ref p1);
    void update_model();
    bool decode_symbol1(Ref ctx);
    void decode_bin_symbol(Ref ctx);
    bool decode_symbol2(Ref ctx);
    void update1(Ref ctx, Ref p);
    void update2(Ref ctx, Ref p);
    See *make_esc_freq2(Ref ctx, int diff);
    void clear_mask() { esc_count_ = 1; std::memset(char_mask_, 0, sizeof char_mask_); }

    // range coder
    void coder_init();
    std::uint8_t next_byte() { in_->fill(); return in_->byte(); }
    unsigned current_count() { return (code_ - low_) / (range_ /= scale_); }
    unsigned current_shift_count(unsigned shift) { return (code_ - low_) / (range_ >>= shift); }
    void coder_decode()
    {
        low_ += range_ * low_count_;
        range_ *= high_count_ - low_count_;
    }
    void normalize();

    BitIn *in_ = nullptr;
    std::uint32_t low_ = 0, code_ = 0, range_ = 0;
    std::uint32_t low_count_ = 0, high_count_ = 0, scale_ = 0;

    std::vector<std::uint8_t> heap_;
    bool ready_ = false;
    std::uint32_t sub_size_ = 0;
    Ref heap_start_ = 0, heap_end_ = 0, lo_unit_ = 0, hi_unit_ = 0, text_ = 0, units_start_ = 0, fake_units_start_ = 0;
    Ref free_list_[38] = {};
    int glue_count_ = 0;
    std::uint8_t indx2units_[38] = {};
    std::uint8_t units2indx_[128] = {};

    See see2_[25][16] = {};
    See dummy_see2_{};
    Ref min_ctx_ = 0, med_ctx_ = 0, max_ctx_ = 0, found_ = 0;
    int num_masked_ = 0, init_esc_ = 0, order_fall_ = 0, max_order_ = 0, run_length_ = 0, init_rl_ = 0;
    std::uint8_t char_mask_[256] = {};
    std::uint8_t ns2indx_[256] = {}, ns2bsindx_[256] = {}, hb2flag_[256] = {};
    std::uint8_t esc_count_ = 0, prev_success_ = 0, hi_bits_flag_ = 0;
    std::uint16_t bin_summ_[128][64] = {};
};

} // namespace raye::archive::detail::rar
