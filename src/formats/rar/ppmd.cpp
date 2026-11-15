// SPDX-License-Identifier: GPL-3.0-or-later
// PPMd var. H: memory is a byte heap addressed by 32-bit offsets, units
// of 12 bytes, laid out exactly like the original so that model restarts
// happen at the same symbol as in the encoder.
#include "ppmd.h"

namespace raye::archive::detail::rar {

namespace {

constexpr int kMaxFreq = 124;
constexpr int kIntBits = 7, kPeriodBits = 7, kTotBits = kIntBits + kPeriodBits;
constexpr int kInterval = 1 << kIntBits, kBinScale = 1 << kTotBits;
constexpr std::uint32_t kTop = 1u << 24, kBot = 1u << 15;
constexpr std::uint8_t kExpEscape[16] = {25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2};
constexpr std::uint16_t kInitBinEsc[8] = {0x3cdd, 0x1f3f, 0x59bf, 0x48f3, 0x64a1, 0x5abc, 0x6632, 0x6051};
constexpr int kIndexes = 38;
constexpr std::uint32_t kSentinel = 12; // list head used while gluing free blocks

inline unsigned get_mean(unsigned summ) { return (summ + (1u << (kPeriodBits - 2))) >> kPeriodBits; }

} // namespace

// ---------------------------------------------------------------- allocator

void Ppmd::start_alloc(std::uint32_t mb)
{
    const std::uint32_t size = mb << 20;
    if (size == sub_size_ && !heap_.empty()) return;
    sub_size_ = size;
    const std::uint32_t alloc = size / 12 * 12 + 12;
    heap_.assign(std::size_t(24) + alloc + 48, 0);
    heap_start_ = 24;
    heap_end_ = heap_start_ + alloc - 12;
}

void Ppmd::init_alloc()
{
    std::memset(free_list_, 0, sizeof free_list_);
    text_ = heap_start_;
    const std::uint32_t size2 = 12 * (sub_size_ / 8 / 12 * 7);
    const std::uint32_t size1 = sub_size_ - size2;
    lo_unit_ = units_start_ = heap_start_ + size1;
    fake_units_start_ = heap_start_ + size1;
    hi_unit_ = lo_unit_ + size2;
    glue_count_ = 0;
    int i = 0, k = 1;
    for (; i < 4; ++i, k += 1) indx2units_[i] = std::uint8_t(k);
    for (++k; i < 8; ++i, k += 2) indx2units_[i] = std::uint8_t(k);
    for (++k; i < 12; ++i, k += 3) indx2units_[i] = std::uint8_t(k);
    for (++k; i < kIndexes; ++i, k += 4) indx2units_[i] = std::uint8_t(k);
    for (i = 0, k = 0; k < 128; ++k) {
        i += indx2units_[i] < k + 1;
        units2indx_[k] = std::uint8_t(i);
    }
}

void Ppmd::insert_node(Ref p, int indx)
{
    s32(p, free_list_[indx]);
    free_list_[indx] = p;
}

Ppmd::Ref Ppmd::remove_node(int indx)
{
    const Ref r = free_list_[indx];
    free_list_[indx] = g32(r);
    return r;
}

void Ppmd::split_block(Ref p, int old_indx, int new_indx)
{
    int udiff = indx2units_[old_indx] - indx2units_[new_indx];
    p += U2B(indx2units_[new_indx]);
    int i = units2indx_[udiff - 1];
    if (indx2units_[i] != udiff) {
        insert_node(p, --i);
        p += U2B(indx2units_[i]);
        udiff -= indx2units_[i];
    }
    insert_node(p, units2indx_[udiff - 1]);
}

void Ppmd::glue_free_blocks()
{
    // Block layout while gluing: stamp@0, units@2, next@4, prev@8.
    auto next = [&](Ref p) { return g32(p + 4); };
    auto prev = [&](Ref p) { return g32(p + 8); };
    auto unlink = [&](Ref p) {
        s32(prev(p) + 4, next(p));
        s32(next(p) + 8, prev(p));
    };
    if (lo_unit_ != hi_unit_) heap_[lo_unit_] = 0;
    s32(kSentinel + 4, kSentinel);
    s32(kSentinel + 8, kSentinel);
    for (int i = 0; i < kIndexes; ++i)
        while (free_list_[i]) {
            const Ref p = remove_node(i);
            s32(p + 8, kSentinel);
            s32(p + 4, next(kSentinel));
            s32(next(p) + 8, p);
            s32(kSentinel + 4, p);
            s16(p, 0xffff);
            s16(p + 2, indx2units_[i]);
        }
    for (Ref p = next(kSentinel); p != kSentinel; p = next(p)) {
        for (;;) {
            const Ref p1 = p + U2B(g16(p + 2));
            if (p1 + 12 > heap_.size() || g16(p1) != 0xffff || int(g16(p + 2)) + g16(p1 + 2) >= 0x10000) break;
            unlink(p1);
            s16(p + 2, std::uint16_t(g16(p + 2) + g16(p1 + 2)));
        }
    }
    for (Ref p; (p = next(kSentinel)) != kSentinel;) {
        unlink(p);
        int sz = g16(p + 2);
        for (; sz > 128; sz -= 128, p += U2B(128)) insert_node(p, kIndexes - 1);
        int i = units2indx_[sz - 1];
        if (indx2units_[i] != sz) {
            const int k = sz - indx2units_[--i];
            insert_node(p + U2B(sz - k), k - 1);
        }
        insert_node(p, i);
    }
}

Ppmd::Ref Ppmd::alloc_units_rare(int indx)
{
    if (!glue_count_) {
        glue_count_ = 255;
        glue_free_blocks();
        if (free_list_[indx]) return remove_node(indx);
    }
    int i = indx;
    do {
        if (++i == kIndexes) {
            --glue_count_;
            const std::uint32_t n = U2B(indx2units_[indx]);
            if (fake_units_start_ > text_ && fake_units_start_ - text_ > n) {
                fake_units_start_ -= n;
                units_start_ -= n;
                return units_start_;
            }
            return 0;
        }
    } while (!free_list_[i]);
    const Ref r = remove_node(i);
    split_block(r, i, indx);
    return r;
}

Ppmd::Ref Ppmd::alloc_units(int nu)
{
    const int indx = units2indx_[nu - 1];
    if (free_list_[indx]) return remove_node(indx);
    const Ref r = lo_unit_;
    lo_unit_ += U2B(indx2units_[indx]);
    if (lo_unit_ <= hi_unit_) return r;
    lo_unit_ -= U2B(indx2units_[indx]);
    return alloc_units_rare(indx);
}

Ppmd::Ref Ppmd::alloc_context()
{
    if (hi_unit_ != lo_unit_) return hi_unit_ -= 12;
    if (free_list_[0]) return remove_node(0);
    return alloc_units_rare(0);
}

Ppmd::Ref Ppmd::expand_units(Ref old, int old_nu)
{
    const int i0 = units2indx_[old_nu - 1], i1 = units2indx_[old_nu];
    if (i0 == i1) return old;
    const Ref p = alloc_units(old_nu + 1);
    if (p) {
        std::memmove(&heap_[p], &heap_[old], U2B(old_nu));
        insert_node(old, i0);
    }
    return p;
}

Ppmd::Ref Ppmd::shrink_units(Ref old, int old_nu, int new_nu)
{
    const int i0 = units2indx_[old_nu - 1], i1 = units2indx_[new_nu - 1];
    if (i0 == i1) return old;
    if (free_list_[i1]) {
        const Ref p = remove_node(i1);
        std::memmove(&heap_[p], &heap_[old], U2B(new_nu));
        insert_node(old, i0);
        return p;
    }
    split_block(old, i0, i1);
    return old;
}

// ---------------------------------------------------------------- model

void Ppmd::restart_model()
{
    std::memset(char_mask_, 0, sizeof char_mask_);
    init_alloc();
    init_rl_ = -(max_order_ < 12 ? max_order_ : 12) - 1;
    min_ctx_ = max_ctx_ = alloc_context();
    s32(min_ctx_ + 8, 0);
    order_fall_ = max_order_;
    s16(min_ctx_, 256);
    s16(min_ctx_ + 2, 257);
    found_ = alloc_units(128);
    s32(min_ctx_ + 4, found_);
    for (unsigned i = 0; i < 256; ++i) {
        const Ref s = st(found_, i);
        heap_[s] = std::uint8_t(i);
        heap_[s + 1] = 1;
        set_succ(s, 0);
    }
    run_length_ = init_rl_;
    prev_success_ = 0;
    for (int i = 0; i < 128; ++i)
        for (int k = 0; k < 8; ++k)
            for (int m = 0; m < 64; m += 8) bin_summ_[i][k + m] = std::uint16_t(kBinScale - kInitBinEsc[k] / (i + 2));
    for (int i = 0; i < 25; ++i)
        for (auto &s : see2_[i]) s.init(unsigned(5 * i + 10));
}

void Ppmd::start_model(int max_order)
{
    esc_count_ = 1;
    max_order_ = max_order;
    restart_model();
    ns2bsindx_[0] = 0;
    ns2bsindx_[1] = 2;
    std::memset(ns2bsindx_ + 2, 4, 9);
    std::memset(ns2bsindx_ + 11, 6, 256 - 11);
    int i = 0;
    for (; i < 3; ++i) ns2indx_[i] = std::uint8_t(i);
    for (int m = i, k = 1, step = 1; i < 256; ++i) {
        ns2indx_[i] = std::uint8_t(m);
        if (!--k) {
            k = ++step;
            ++m;
        }
    }
    std::memset(hb2flag_, 0, 0x40);
    std::memset(hb2flag_ + 0x40, 8, 0x100 - 0x40);
    dummy_see2_.shift = kPeriodBits;
    dummy_see2_.summ = 0;
    dummy_see2_.count = 64;
}

void Ppmd::rescale(Ref ctx)
{
    const int old_ns = ns(ctx);
    int i = old_ns - 1;
    const Ref s0 = stats(ctx);
    Ref p = found_;
    for (; p != s0; p -= 6) swap_states(p, p - 6);
    freq(s0) = std::uint8_t(freq(s0) + 4);
    s16(ctx + 2, std::uint16_t(summ(ctx) + 4));
    int esc_freq = summ(ctx) - freqv(p);
    const int adder = order_fall_ != 0;
    freq(p) = std::uint8_t((freqv(p) + adder) >> 1);
    int sf = freqv(p);
    do {
        p += 6;
        esc_freq -= freqv(p);
        freq(p) = std::uint8_t((freqv(p) + adder) >> 1);
        sf += freqv(p);
        if (freqv(p) > freqv(p - 6)) {
            std::uint8_t tmp[6];
            std::memcpy(tmp, &heap_[p], 6);
            Ref p1 = p;
            do {
                std::memcpy(&heap_[p1], &heap_[p1 - 6], 6);
                p1 -= 6;
            } while (p1 != s0 && tmp[1] > freqv(p1 - 6));
            std::memcpy(&heap_[p1], tmp, 6);
        }
    } while (--i);
    s16(ctx + 2, std::uint16_t(sf));
    if (freqv(p) == 0) {
        do {
            ++i;
            p -= 6;
        } while (freqv(p) == 0);
        esc_freq += i;
        const int new_ns = old_ns - i;
        s16(ctx, std::uint16_t(new_ns));
        if (new_ns == 1) {
            std::uint8_t tmp[6];
            std::memcpy(tmp, &heap_[s0], 6);
            do {
                tmp[1] = std::uint8_t(tmp[1] - (tmp[1] >> 1));
                esc_freq >>= 1;
            } while (esc_freq > 1);
            free_units(s0, (old_ns + 1) >> 1);
            std::memcpy(&heap_[ctx + 2], tmp, 6);
            found_ = ctx + 2;
            return;
        }
    }
    esc_freq -= esc_freq >> 1;
    s16(ctx + 2, std::uint16_t(summ(ctx) + esc_freq));
    const int n0 = (old_ns + 1) >> 1, n1 = (ns(ctx) + 1) >> 1;
    if (n0 != n1) s32(ctx + 4, shrink_units(s0, n0, n1));
    found_ = stats(ctx);
}

Ppmd::Ref Ppmd::create_successors(bool skip, Ref p1)
{
    Ref pc = min_ctx_;
    const Ref up_branch = succ(found_);
    Ref ps[256];
    int n = 0;
    Ref p = 0;
    const std::uint8_t fsym = sym(found_);
    if (!skip) {
        ps[n++] = found_;
        if (!suffix(pc)) goto no_loop;
    }
    if (p1) {
        p = p1;
        pc = suffix(pc);
        goto loop_entry;
    }
    do {
        pc = suffix(pc);
        if (ns(pc) != 1) {
            p = stats(pc);
            for (unsigned k = 0; sym(p) != fsym; ++k) {
                if (k >= ns(pc)) return 0;
                p += 6;
            }
        } else {
            p = pc + 2;
        }
    loop_entry:
        if (succ(p) != up_branch) {
            pc = succ(p);
            break;
        }
        if (n >= 255) return 0;
        ps[n++] = p;
    } while (suffix(pc));
no_loop:
    if (n == 0) return pc;
    if (up_branch >= heap_.size()) return 0;
    std::uint8_t up[6];
    up[0] = heap_[up_branch];
    const Ref up_succ = up_branch + 1;
    std::memcpy(up + 2, &up_succ, 4);
    if (ns(pc) != 1) {
        if (pc <= text_) return 0;
        p = stats(pc);
        for (unsigned k = 0; sym(p) != up[0]; ++k) {
            if (k >= ns(pc)) return 0;
            p += 6;
        }
        const unsigned cf = freqv(p) - 1u;
        const unsigned s0 = summ(pc) - ns(pc) - cf;
        if (s0 == 0) return 0;
        up[1] = std::uint8_t(1 + ((2 * cf <= s0) ? (5 * cf > s0) : ((2 * cf + 3 * s0 - 1) / (2 * s0))));
    } else {
        up[1] = heap_[pc + 3];
    }
    do {
        const Ref c = alloc_context();
        if (!c) return 0;
        s16(c, 1);
        std::memcpy(&heap_[c + 2], up, 6);
        s32(c + 8, pc);
        set_succ(ps[--n], c);
        pc = c;
    } while (n);
    return pc;
}

void Ppmd::update_model()
{
    std::uint8_t fs_sym = sym(found_), fs_freq = freqv(found_);
    Ref fs_succ = succ(found_);
    Ref p = 0, pc;
    if (fs_freq < kMaxFreq / 4 && (pc = suffix(min_ctx_)) != 0) {
        if (ns(pc) != 1) {
            p = stats(pc);
            if (sym(p) != fs_sym) {
                unsigned k = 0;
                do {
                    p += 6;
                    if (++k >= ns(pc)) goto restart;
                } while (sym(p) != fs_sym);
                if (freqv(p) >= freqv(p - 6)) {
                    swap_states(p, p - 6);
                    p -= 6;
                }
            }
            if (freqv(p) < kMaxFreq - 9) {
                freq(p) = std::uint8_t(freqv(p) + 2);
                s16(pc + 2, std::uint16_t(summ(pc) + 2));
            }
        } else {
            p = pc + 2;
            freq(p) = std::uint8_t(freqv(p) + (freqv(p) < 32));
        }
    }
    if (!order_fall_) {
        min_ctx_ = max_ctx_ = create_successors(true, p);
        set_succ(found_, min_ctx_);
        if (!min_ctx_) goto restart;
        return;
    }
    {
        heap_[text_++] = fs_sym;
        Ref successor = text_;
        if (text_ >= fake_units_start_) goto restart;
        if (fs_succ) {
            if (fs_succ <= text_ && (fs_succ = create_successors(false, p)) == 0) goto restart;
            if (!--order_fall_) {
                successor = fs_succ;
                text_ -= (max_ctx_ != min_ctx_);
            }
        } else {
            set_succ(found_, successor);
            fs_succ = min_ctx_;
        }
        const unsigned nsm = ns(min_ctx_);
        const unsigned s0 = summ(min_ctx_) - nsm - (fs_freq - 1u);
        for (pc = max_ctx_; pc != min_ctx_; pc = suffix(pc)) {
            unsigned ns1 = ns(pc);
            if (ns1 != 1) {
                if ((ns1 & 1) == 0) {
                    const Ref s = expand_units(stats(pc), int(ns1 >> 1));
                    if (!s) goto restart;
                    s32(pc + 4, s);
                }
                s16(pc + 2, std::uint16_t(summ(pc) + (2 * ns1 < nsm) + 2 * ((4 * ns1 <= nsm) & (summ(pc) <= 8 * ns1))));
            } else {
                const Ref s = alloc_units(1);
                if (!s) goto restart;
                std::memcpy(&heap_[s], &heap_[pc + 2], 6);
                s32(pc + 4, s);
                if (freqv(s) < kMaxFreq / 4 - 1) freq(s) = std::uint8_t(freqv(s) * 2);
                else freq(s) = kMaxFreq - 4;
                s16(pc + 2, std::uint16_t(freqv(s) + init_esc_ + (nsm > 3)));
            }
            unsigned cf = 2u * fs_freq * (summ(pc) + 6u);
            const unsigned sf = s0 + summ(pc);
            if (cf < 6 * sf) {
                cf = 1 + (cf > sf) + (cf >= 4 * sf);
                s16(pc + 2, std::uint16_t(summ(pc) + 3));
            } else {
                cf = 4 + (cf >= 9 * sf) + (cf >= 12 * sf) + (cf >= 15 * sf);
                s16(pc + 2, std::uint16_t(summ(pc) + cf));
            }
            const Ref np = st(stats(pc), ns1);
            set_succ(np, successor);
            heap_[np] = fs_sym;
            heap_[np + 1] = std::uint8_t(cf);
            s16(pc, std::uint16_t(++ns1));
        }
        max_ctx_ = min_ctx_ = fs_succ;
        return;
    }
restart:
    restart_model();
    esc_count_ = 0;
}

void Ppmd::decode_bin_symbol(Ref ctx)
{
    const Ref rs = ctx + 2;
    hi_bits_flag_ = hb2flag_[sym(found_)];
    const Ref sfx = suffix(ctx);
    std::uint16_t &bs = bin_summ_[freqv(rs) - 1][prev_success_ + ns2bsindx_[ns(sfx) - 1] + hi_bits_flag_ +
                                                 2 * hb2flag_[sym(rs)] + ((run_length_ >> 26) & 0x20)];
    if (current_shift_count(kTotBits) < bs) {
        found_ = rs;
        freq(rs) = std::uint8_t(freqv(rs) + (freqv(rs) < 128));
        low_count_ = 0;
        high_count_ = bs;
        bs = std::uint16_t(bs + kInterval - get_mean(bs));
        prev_success_ = 1;
        ++run_length_;
    } else {
        low_count_ = bs;
        bs = std::uint16_t(bs - get_mean(bs));
        high_count_ = kBinScale;
        init_esc_ = kExpEscape[bs >> 10];
        num_masked_ = 1;
        char_mask_[sym(rs)] = esc_count_;
        prev_success_ = 0;
        found_ = 0;
    }
}

void Ppmd::update1(Ref ctx, Ref p)
{
    found_ = p;
    freq(p) = std::uint8_t(freqv(p) + 4);
    s16(ctx + 2, std::uint16_t(summ(ctx) + 4));
    if (freqv(p) > freqv(p - 6)) {
        swap_states(p, p - 6);
        found_ = p -= 6;
        if (freqv(p) > kMaxFreq) rescale(ctx);
    }
}

bool Ppmd::decode_symbol1(Ref ctx)
{
    scale_ = summ(ctx);
    Ref p = stats(ctx);
    const unsigned count = current_count();
    if (count >= scale_) return false;
    unsigned hi = freqv(p);
    if (count < hi) {
        high_count_ = hi;
        prev_success_ = 2 * hi > scale_;
        run_length_ += prev_success_;
        found_ = p;
        hi += 4;
        freq(p) = std::uint8_t(hi);
        s16(ctx + 2, std::uint16_t(summ(ctx) + 4));
        if (hi > unsigned(kMaxFreq)) rescale(ctx);
        low_count_ = 0;
        return true;
    }
    if (!found_) return false;
    prev_success_ = 0;
    int i = ns(ctx) - 1;
    while ((hi += freqv(p += 6)) <= count) {
        if (--i == 0) {
            hi_bits_flag_ = hb2flag_[sym(found_)];
            low_count_ = hi;
            char_mask_[sym(p)] = esc_count_;
            i = (num_masked_ = ns(ctx)) - 1;
            found_ = 0;
            do {
                p -= 6;
                char_mask_[sym(p)] = esc_count_;
            } while (--i);
            high_count_ = scale_;
            return true;
        }
    }
    low_count_ = (high_count_ = hi) - freqv(p);
    update1(ctx, p);
    return true;
}

Ppmd::See *Ppmd::make_esc_freq2(Ref ctx, int diff)
{
    const int n = ns(ctx);
    if (n != 256) {
        See *s = &see2_[ns2indx_[diff - 1]][(diff < int(ns(suffix(ctx))) - n) + 2 * (summ(ctx) < 11 * n) +
                                            4 * (num_masked_ > diff) + hi_bits_flag_];
        scale_ = s->mean();
        return s;
    }
    scale_ = 1;
    return &dummy_see2_;
}

void Ppmd::update2(Ref ctx, Ref p)
{
    found_ = p;
    freq(p) = std::uint8_t(freqv(p) + 4);
    s16(ctx + 2, std::uint16_t(summ(ctx) + 4));
    if (freqv(p) > kMaxFreq) rescale(ctx);
    ++esc_count_;
    run_length_ = init_rl_;
}

bool Ppmd::decode_symbol2(Ref ctx)
{
    int i = ns(ctx) - num_masked_;
    if (i <= 0) return false;
    See *see = make_esc_freq2(ctx, i);
    Ref ps[256];
    int n = 0;
    Ref p = stats(ctx) - 6;
    const Ref end = stats(ctx) + 6 * ns(ctx);
    unsigned hi = 0;
    do {
        do {
            p += 6;
            if (p >= end) return false;
        } while (char_mask_[sym(p)] == esc_count_);
        hi += freqv(p);
        ps[n++] = p;
    } while (--i);
    scale_ += hi;
    const unsigned count = current_count();
    if (count >= scale_) return false;
    if (count < hi) {
        int k = 0;
        p = ps[0];
        hi = 0;
        while ((hi += freqv(p)) <= count) {
            if (++k >= n) return false;
            p = ps[k];
        }
        low_count_ = (high_count_ = hi) - freqv(p);
        see->update();
        update2(ctx, p);
    } else {
        low_count_ = hi;
        high_count_ = scale_;
        for (int k = 0; k < n; ++k) char_mask_[sym(ps[k])] = esc_count_;
        see->summ = std::uint16_t(see->summ + scale_);
        num_masked_ = ns(ctx);
    }
    return true;
}

// ---------------------------------------------------------------- coder

void Ppmd::coder_init()
{
    low_ = code_ = 0;
    range_ = 0xffffffffu;
    for (int i = 0; i < 4; ++i) code_ = (code_ << 8) | next_byte();
}

void Ppmd::normalize()
{
    for (;;) {
        if ((low_ ^ (low_ + range_)) >= kTop) {
            if (range_ >= kBot) break;
            range_ = (0u - low_) & (kBot - 1);
        }
        code_ = (code_ << 8) | next_byte();
        range_ <<= 8;
        low_ <<= 8;
    }
}

bool Ppmd::init(BitIn &in, int &esc)
{
    in_ = &in;
    int max_order = next_byte();
    const bool reset = (max_order & 0x20) != 0;
    int mb = 0;
    if (reset) mb = next_byte();
    else if (!ready_) return false;
    if (max_order & 0x40) esc = next_byte();
    coder_init();
    if (reset) {
        max_order = (max_order & 0x1f) + 1;
        if (max_order > 16) max_order = 16 + (max_order - 16) * 3;
        if (max_order == 1) {
            ready_ = false;
            return false;
        }
        start_alloc(std::uint32_t(mb + 1));
        start_model(max_order);
        ready_ = true;
    }
    return min_ctx_ != 0;
}

int Ppmd::decode_char()
{
    auto bad = [&](Ref c) { return c <= text_ || c > heap_end_; };
    if (bad(min_ctx_)) return -1;
    if (ns(min_ctx_) != 1) {
        if (bad(stats(min_ctx_))) return -1;
        if (!decode_symbol1(min_ctx_)) return -1;
    } else {
        if (!suffix(min_ctx_) || !found_) return -1;
        decode_bin_symbol(min_ctx_);
    }
    coder_decode();
    while (!found_) {
        normalize();
        do {
            ++order_fall_;
            min_ctx_ = suffix(min_ctx_);
            if (bad(min_ctx_)) return -1;
        } while (ns(min_ctx_) == num_masked_);
        if (!decode_symbol2(min_ctx_)) return -1;
        coder_decode();
    }
    const int symbol = sym(found_);
    if (!order_fall_ && succ(found_) > text_) {
        min_ctx_ = max_ctx_ = succ(found_);
    } else {
        update_model();
        if (esc_count_ == 0) clear_mask();
    }
    normalize();
    return symbol;
}

} // namespace raye::archive::detail::rar
