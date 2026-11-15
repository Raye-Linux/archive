// SPDX-License-Identifier: GPL-3.0-or-later
// The model lives in one block of memory addressed by 32-bit offsets, so
// that it behaves exactly like every other PPMd H coder: when the block
// fills up the model restarts at the same moment, and both sides agree.
#include "ppmd.h"

#include <raye/archive/error.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace raye::archive::detail::ppmd7 {

namespace {

constexpr unsigned kUnit = 12;
constexpr unsigned kIndexes = 4 + 4 + 4 + 26;
constexpr unsigned kMaxFreq = 124;
constexpr unsigned kIntBits = 7, kPeriodBits = 7, kBinScale = 1 << (kIntBits + kPeriodBits);
constexpr std::uint32_t kTop = 1u << 24;
constexpr std::uint16_t kInitBinEsc[8] = {0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051};
constexpr std::uint8_t kExpEscape[16] = {25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2};

struct State {
    std::uint8_t symbol, freq;
    std::uint16_t succ_lo, succ_hi;
    std::uint32_t successor() const { return succ_lo | std::uint32_t(succ_hi) << 16; }
    void set_successor(std::uint32_t v) { succ_lo = std::uint16_t(v); succ_hi = std::uint16_t(v >> 16); }
};
static_assert(sizeof(State) == 6);

struct Ctx {
    std::uint16_t num_stats, summ_freq;
    std::uint32_t stats, suffix;
};
static_assert(sizeof(Ctx) == 12);

struct Node {
    std::uint16_t stamp, nu;
    std::uint32_t next, prev;
};

struct See {
    std::uint16_t summ;
    std::uint8_t shift, count;
    void update()
    {
        if (shift < kPeriodBits && --count == 0) {
            summ = std::uint16_t(summ << 1);
            count = std::uint8_t(3 << shift++);
        }
    }
};

unsigned mean(unsigned prob) { return (prob + (1u << (kPeriodBits - 2))) >> kPeriodBits; }

} // namespace

class Model {
public:
    Model(unsigned order, std::uint32_t size) : max_order(order), size_(size)
    {
        for (unsigned i = 0, k = 0; i < kIndexes; ++i) {
            unsigned step = i >= 12 ? 4 : (i >> 2) + 1;
            do units2indx[k++] = std::uint8_t(i); while (--step);
            indx2units[i] = std::uint8_t(k);
        }
        ns2bsindx[0] = 0 << 1;
        ns2bsindx[1] = 1 << 1;
        std::memset(ns2bsindx + 2, 2 << 1, 9);
        std::memset(ns2bsindx + 11, 3 << 1, 256 - 11);
        unsigned i = 0;
        for (; i < 3; ++i) ns2indx[i] = std::uint8_t(i);
        for (unsigned m = i, k = 1; i < 256; ++i) {
            ns2indx[i] = std::uint8_t(m);
            if (--k == 0) k = (++m) - 2;
        }
        std::memset(hb2flag, 0, 0x40);
        std::memset(hb2flag + 0x40, 8, 0x100 - 0x40);

        align_ = 4 - (size & 3);
        // calloc: pages the model never reaches are never touched.
        mem_.reset(static_cast<std::uint8_t *>(std::calloc(std::size_t(align_) + size + kUnit * 2, 1)));
        if (!mem_) fail(ErrorCode::Internal, "not enough memory for PPMd");
        base = mem_.get();
        restart();
        dummy_see.shift = kPeriodBits;
        dummy_see.summ = 0;
        dummy_see.count = 64;
    }

    // ---- addressing
    std::uint8_t *ptr(std::uint32_t ref) const { return base + ref; }
    std::uint32_t ref(const void *p) const { return std::uint32_t(static_cast<const std::uint8_t *>(p) - base); }
    Ctx *ctx(std::uint32_t r) const { return reinterpret_cast<Ctx *>(base + r); }
    State *stats(const Ctx *c) const { return reinterpret_cast<State *>(base + c->stats); }
    static State *one_state(Ctx *c) { return reinterpret_cast<State *>(&c->summ_freq); }
    Ctx *suffix(const Ctx *c) const { return ctx(c->suffix); }
    Node *node(std::uint32_t r) const { return reinterpret_cast<Node *>(base + r); }

    // ---- memory
    unsigned u2i(unsigned nu) const { return units2indx[nu - 1]; }
    unsigned i2u(unsigned i) const { return indx2units[i]; }

    void insert_node(void *p, unsigned i)
    {
        std::memcpy(p, &free_list[i], 4);
        free_list[i] = ref(p);
    }
    void *remove_node(unsigned i)
    {
        std::uint32_t r = free_list[i];
        std::uint8_t *p = ptr(r);
        std::memcpy(&free_list[i], p, 4);
        return p;
    }
    void split_block(void *p, unsigned old_i, unsigned new_i)
    {
        const unsigned nu = i2u(old_i) - i2u(new_i);
        auto *q = static_cast<std::uint8_t *>(p) + i2u(new_i) * kUnit;
        unsigned i = u2i(nu);
        if (i2u(i) != nu) {
            const unsigned k = i2u(--i);
            insert_node(q + k * kUnit, nu - k - 1);
        }
        insert_node(q, i);
    }

    void glue_free_blocks()
    {
        const std::uint32_t head = align_ + size_;
        std::uint32_t n = head;
        glue_count = 255;
        for (unsigned i = 0; i < kIndexes; ++i) {
            const auto nu = std::uint16_t(i2u(i));
            std::uint32_t next = free_list[i];
            free_list[i] = 0;
            while (next != 0) {
                Node *nd = node(next);
                nd->next = n;
                node(n)->prev = next;
                n = next;
                std::uint32_t link;
                std::memcpy(&link, nd, 4);
                next = link;
                nd->stamp = 0;
                nd->nu = nu;
            }
        }
        node(head)->stamp = 1;
        node(head)->next = n;
        node(n)->prev = head;
        if (lo_unit != hi_unit) reinterpret_cast<Node *>(lo_unit)->stamp = 1;

        while (n != head) {
            Node *nd = node(n);
            std::uint32_t nu = nd->nu;
            for (;;) {
                Node *n2 = node(n + nu * kUnit);
                nu += n2->nu;
                if (n2->stamp != 0 || nu >= 0x10000) break;
                node(n2->prev)->next = n2->next;
                node(n2->next)->prev = n2->prev;
                nd->nu = std::uint16_t(nu);
            }
            n = nd->next;
        }

        for (n = node(head)->next; n != head;) {
            Node *nd = node(n);
            const std::uint32_t next = nd->next;
            unsigned nu = nd->nu;
            for (; nu > 128; nu -= 128, n += 128 * kUnit) insert_node(ptr(n), kIndexes - 1);
            unsigned i = u2i(nu);
            if (i2u(i) != nu) {
                const unsigned k = i2u(--i);
                insert_node(ptr(n + k * kUnit), nu - k - 1);
            }
            insert_node(ptr(n), i);
            n = next;
        }
    }

    void *alloc_units_rare(unsigned indx)
    {
        if (glue_count == 0) {
            glue_free_blocks();
            if (free_list[indx] != 0) return remove_node(indx);
        }
        unsigned i = indx;
        do {
            if (++i == kIndexes) {
                const std::uint32_t bytes = i2u(indx) * kUnit;
                --glue_count;
                if (std::uint32_t(units_start - text) > bytes) return units_start -= bytes;
                return nullptr;
            }
        } while (free_list[i] == 0);
        void *r = remove_node(i);
        split_block(r, i, indx);
        return r;
    }

    void *alloc_units(unsigned indx)
    {
        if (free_list[indx] != 0) return remove_node(indx);
        const std::uint32_t bytes = i2u(indx) * kUnit;
        if (bytes <= std::uint32_t(hi_unit - lo_unit)) {
            void *r = lo_unit;
            lo_unit += bytes;
            return r;
        }
        return alloc_units_rare(indx);
    }

    void *shrink_units(void *old, unsigned old_nu, unsigned new_nu)
    {
        const unsigned i0 = u2i(old_nu), i1 = u2i(new_nu);
        if (i0 == i1) return old;
        if (free_list[i1] != 0) {
            void *p = remove_node(i1);
            std::memcpy(p, old, new_nu * kUnit);
            insert_node(old, i0);
            return p;
        }
        split_block(old, i0, i1);
        return old;
    }

    // ---- model
    void restart()
    {
        std::memset(free_list, 0, sizeof free_list);
        text = base + align_;
        hi_unit = text + size_;
        lo_unit = units_start = hi_unit - size_ / 8 / kUnit * 7 * kUnit;
        glue_count = 0;

        order_fall = max_order;
        run_length = init_rl = -std::int32_t(max_order < 12 ? max_order : 12) - 1;
        prev_success = 0;

        hi_unit -= kUnit;
        min_context = max_context = reinterpret_cast<Ctx *>(hi_unit);
        min_context->suffix = 0;
        min_context->num_stats = 256;
        min_context->summ_freq = 256 + 1;
        found_state = reinterpret_cast<State *>(lo_unit);
        lo_unit += (256 / 2) * kUnit;
        min_context->stats = ref(found_state);
        for (unsigned i = 0; i < 256; ++i) {
            State &s = found_state[i];
            s.symbol = std::uint8_t(i);
            s.freq = 1;
            s.set_successor(0);
        }
        for (unsigned i = 0; i < 128; ++i)
            for (unsigned k = 0; k < 8; ++k) {
                const auto v = std::uint16_t(kBinScale - kInitBinEsc[k] / (i + 2));
                for (unsigned m = 0; m < 64; m += 8) bin_summ[i][k + m] = v;
            }
        for (unsigned i = 0; i < 25; ++i)
            for (unsigned k = 0; k < 16; ++k) {
                See &s = see[i][k];
                s.shift = kPeriodBits - 4;
                s.summ = std::uint16_t((5 * i + 10) << s.shift);
                s.count = 4;
            }
    }

    Ctx *create_successors(bool skip)
    {
        Ctx *c = min_context;
        const std::uint32_t up_branch = found_state->successor();
        State *ps[64];
        unsigned nps = 0;
        if (!skip) ps[nps++] = found_state;
        while (c->suffix) {
            c = suffix(c);
            State *s;
            if (c->num_stats != 1) {
                for (s = stats(c); s->symbol != found_state->symbol; ++s) {}
            } else {
                s = one_state(c);
            }
            const std::uint32_t succ = s->successor();
            if (succ != up_branch) {
                c = ctx(succ);
                if (nps == 0) return c;
                break;
            }
            ps[nps++] = s;
        }
        State up;
        up.symbol = *ptr(up_branch);
        up.set_successor(up_branch + 1);
        if (c->num_stats == 1) {
            up.freq = one_state(c)->freq;
        } else {
            State *s;
            for (s = stats(c); s->symbol != up.symbol; ++s) {}
            const std::uint32_t cf = s->freq - 1u;
            const std::uint32_t s0 = c->summ_freq - c->num_stats - cf;
            up.freq = std::uint8_t(1 + ((2 * cf <= s0) ? (5 * cf > s0) : ((2 * cf + 3 * s0 - 1) / (2 * s0))));
        }
        do {
            Ctx *c1;
            if (hi_unit != lo_unit) {
                hi_unit -= kUnit;
                c1 = reinterpret_cast<Ctx *>(hi_unit);
            } else if (free_list[0] != 0) {
                c1 = static_cast<Ctx *>(remove_node(0));
            } else {
                c1 = static_cast<Ctx *>(alloc_units_rare(0));
                if (!c1) return nullptr;
            }
            c1->num_stats = 1;
            *one_state(c1) = up;
            c1->suffix = ref(c);
            ps[--nps]->set_successor(ref(c1));
            c = c1;
        } while (nps != 0);
        return c;
    }

    void update_model()
    {
        std::uint32_t fsucc = found_state->successor();
        if (found_state->freq < kMaxFreq / 4 && min_context->suffix != 0) {
            Ctx *c = suffix(min_context);
            if (c->num_stats == 1) {
                State *s = one_state(c);
                if (s->freq < 32) ++s->freq;
            } else {
                State *s = stats(c);
                if (s->symbol != found_state->symbol) {
                    do ++s; while (s->symbol != found_state->symbol);
                    if (s[0].freq >= s[-1].freq) {
                        std::swap(s[0], s[-1]);
                        --s;
                    }
                }
                if (s->freq < kMaxFreq - 9) {
                    s->freq += 2;
                    c->summ_freq += 2;
                }
            }
        }

        if (order_fall == 0) {
            min_context = max_context = create_successors(true);
            if (!min_context) { restart(); return; }
            found_state->set_successor(ref(min_context));
            return;
        }

        *text++ = found_state->symbol;
        std::uint32_t succ = ref(text);
        if (text >= units_start) { restart(); return; }

        if (fsucc) {
            if (fsucc <= succ) {
                Ctx *cs = create_successors(false);
                if (!cs) { restart(); return; }
                fsucc = ref(cs);
            }
            if (--order_fall == 0) {
                succ = fsucc;
                text -= (max_context != min_context);
            }
        } else {
            found_state->set_successor(succ);
            fsucc = ref(min_context);
        }

        const unsigned ns = min_context->num_stats;
        const std::uint32_t s0 = min_context->summ_freq - ns - (found_state->freq - 1u);

        for (Ctx *c = max_context; c != min_context; c = suffix(c)) {
            const unsigned ns1 = c->num_stats;
            if (ns1 != 1) {
                if ((ns1 & 1) == 0) {
                    const unsigned old_nu = ns1 >> 1;
                    const unsigned i = u2i(old_nu);
                    if (i != u2i(old_nu + 1)) {
                        void *p = alloc_units(i + 1);
                        if (!p) { restart(); return; }
                        void *old = stats(c);
                        std::memcpy(p, old, old_nu * kUnit);
                        insert_node(old, i);
                        c->stats = ref(p);
                    }
                }
                c->summ_freq = std::uint16_t(c->summ_freq + (2 * ns1 < ns) +
                                             2 * ((4 * ns1 <= ns) & (c->summ_freq <= 8 * ns1)));
            } else {
                auto *s = static_cast<State *>(alloc_units(0));
                if (!s) { restart(); return; }
                *s = *one_state(c);
                c->stats = ref(s);
                if (s->freq < kMaxFreq / 4 - 1) s->freq = std::uint8_t(s->freq << 1);
                else s->freq = kMaxFreq - 4;
                c->summ_freq = std::uint16_t(s->freq + init_esc + (ns > 3));
            }
            std::uint32_t cf = 2 * std::uint32_t(found_state->freq) * (c->summ_freq + 6u);
            const std::uint32_t sf = s0 + c->summ_freq;
            if (cf < 6 * sf) {
                cf = 1 + (cf > sf) + (cf >= 4 * sf);
                c->summ_freq += 3;
            } else {
                cf = 4 + (cf >= 9 * sf) + (cf >= 12 * sf) + (cf >= 15 * sf);
                c->summ_freq = std::uint16_t(c->summ_freq + cf);
            }
            State *s = stats(c) + ns1;
            s->set_successor(succ);
            s->symbol = found_state->symbol;
            s->freq = std::uint8_t(cf);
            c->num_stats = std::uint16_t(ns1 + 1);
        }
        max_context = min_context = ctx(fsucc);
    }

    void rescale()
    {
        State *st = stats(min_context);
        State *s = found_state;
        {
            State tmp = *s;
            for (; s != st; --s) s[0] = s[-1];
            *s = tmp;
        }
        unsigned esc = min_context->summ_freq - s->freq;
        s->freq += 4;
        const unsigned adder = order_fall != 0;
        s->freq = std::uint8_t((s->freq + adder) >> 1);
        unsigned sum = s->freq;
        unsigned i = min_context->num_stats - 1u;
        do {
            esc -= (++s)->freq;
            s->freq = std::uint8_t((s->freq + adder) >> 1);
            sum += s->freq;
            if (s[0].freq > s[-1].freq) {
                State *s1 = s;
                State tmp = *s1;
                do s1[0] = s1[-1]; while (--s1 != st && tmp.freq > s1[-1].freq);
                *s1 = tmp;
            }
        } while (--i);

        if (s->freq == 0) {
            const unsigned num = min_context->num_stats;
            do ++i; while ((--s)->freq == 0);
            esc += i;
            min_context->num_stats = std::uint16_t(min_context->num_stats - i);
            if (min_context->num_stats == 1) {
                State tmp = *st;
                do {
                    tmp.freq = std::uint8_t(tmp.freq - (tmp.freq >> 1));
                    esc >>= 1;
                } while (esc > 1);
                insert_node(st, u2i((num + 1) >> 1));
                *(found_state = one_state(min_context)) = tmp;
                return;
            }
            const unsigned n0 = (num + 1) >> 1, n1 = (min_context->num_stats + 1u) >> 1;
            if (n0 != n1) min_context->stats = ref(shrink_units(st, n0, n1));
        }
        min_context->summ_freq = std::uint16_t(sum + esc - (esc >> 1));
        found_state = stats(min_context);
    }

    See *make_esc_freq(unsigned masked, std::uint32_t &esc)
    {
        const unsigned ns = min_context->num_stats;
        if (ns == 256) {
            esc = 1;
            return &dummy_see;
        }
        const unsigned non_masked = ns - masked;
        See *s = see[ns2indx[non_masked - 1]] + (non_masked < unsigned(suffix(min_context)->num_stats) - ns) +
                 2 * (min_context->summ_freq < 11 * ns) + 4 * (masked > non_masked) + hi_bits_flag;
        const unsigned r = s->summ >> s->shift;
        s->summ = std::uint16_t(s->summ - r);
        esc = r + (r == 0);
        return s;
    }

    void next_context()
    {
        Ctx *c = ctx(found_state->successor());
        if (order_fall == 0 && reinterpret_cast<std::uint8_t *>(c) > text) min_context = max_context = c;
        else update_model();
    }

    void update1()
    {
        State *s = found_state;
        s->freq += 4;
        min_context->summ_freq += 4;
        if (s[0].freq > s[-1].freq) {
            std::swap(s[0], s[-1]);
            found_state = --s;
            if (s->freq > kMaxFreq) rescale();
        }
        next_context();
    }

    void update1_0()
    {
        prev_success = 2u * found_state->freq > min_context->summ_freq;
        run_length += prev_success;
        min_context->summ_freq += 4;
        if ((found_state->freq += 4) > kMaxFreq) rescale();
        next_context();
    }

    void update_bin()
    {
        found_state->freq = std::uint8_t(found_state->freq + (found_state->freq < 128 ? 1 : 0));
        prev_success = 1;
        ++run_length;
        next_context();
    }

    void update2()
    {
        found_state->freq += 4;
        min_context->summ_freq += 4;
        if (found_state->freq > kMaxFreq) rescale();
        run_length = init_rl;
        update_model();
    }

    std::uint16_t &bin_prob()
    {
        State *one = one_state(min_context);
        hi_bits_flag = hb2flag[found_state->symbol];
        return bin_summ[one->freq - 1][prev_success + ns2bsindx[suffix(min_context)->num_stats - 1] + hi_bits_flag +
                                       2 * hb2flag[one->symbol] + ((run_length >> 26) & 0x20)];
    }

    // Returns false when an escape reaches the root (end marker).
    bool escape_up(unsigned masked)
    {
        do {
            ++order_fall;
            if (!min_context->suffix) return false;
            min_context = suffix(min_context);
        } while (min_context->num_stats == masked);
        return true;
    }

    // state
    unsigned max_order;
    Ctx *min_context = nullptr, *max_context = nullptr;
    State *found_state = nullptr;
    unsigned order_fall = 0, init_esc = 0, prev_success = 0, hi_bits_flag = 0;
    std::int32_t run_length = 0, init_rl = 0;
    std::uint8_t *base = nullptr, *lo_unit = nullptr, *hi_unit = nullptr, *text = nullptr, *units_start = nullptr;
    unsigned glue_count = 0;
    std::uint8_t indx2units[kIndexes], units2indx[128], ns2indx[256], ns2bsindx[256], hb2flag[256];
    std::uint32_t free_list[kIndexes] = {};
    See dummy_see{}, see[25][16]{};
    std::uint16_t bin_summ[128][64]{};

private:
    std::uint32_t size_, align_ = 0;
    struct Free {
        void operator()(std::uint8_t *p) const { std::free(p); }
    };
    std::unique_ptr<std::uint8_t, Free> mem_;
};

// ---- decoder

Decoder::Decoder(unsigned order, std::uint32_t memory, int (*rd)(void *), void *ctx)
    : m_(std::make_unique<Model>(order, memory)), read_(rd), ctx_(ctx) {}
Decoder::~Decoder() = default;

void Decoder::normalize()
{
    while (range_ < kTop) {
        code_ = code_ << 8 | std::uint32_t(read_(ctx_));
        range_ <<= 8;
    }
}

int Decoder::decode()
{
    Model &p = *m_;
    if (!started_) {
        if (read_(ctx_) != 0) return -2;
        for (int i = 0; i < 4; ++i) code_ = code_ << 8 | std::uint32_t(read_(ctx_));
        if (code_ == 0xFFFFFFFF) return -2;
        started_ = true;
    }
    auto threshold = [&](std::uint32_t total) { return code_ / (range_ /= total); };
    auto take = [&](std::uint32_t start, std::uint32_t size) {
        code_ -= start * range_;
        range_ *= size;
        normalize();
    };
    std::int8_t mask[256];
    if (p.min_context->num_stats != 1) {
        State *s = p.stats(p.min_context);
        std::uint32_t count = threshold(p.min_context->summ_freq), hi = s->freq;
        if (count < hi) {
            take(0, s->freq);
            p.found_state = s;
            const int sym = s->symbol;
            p.update1_0();
            return sym;
        }
        p.prev_success = 0;
        unsigned i = p.min_context->num_stats - 1u;
        do {
            if ((hi += (++s)->freq) > count) {
                take(hi - s->freq, s->freq);
                p.found_state = s;
                const int sym = s->symbol;
                p.update1();
                return sym;
            }
        } while (--i);
        if (count >= p.min_context->summ_freq) return -2;
        p.hi_bits_flag = p.hb2flag[p.found_state->symbol];
        take(hi, p.min_context->summ_freq - hi);
        std::memset(mask, -1, sizeof mask);
        mask[s->symbol] = 0;
        i = p.min_context->num_stats - 1u;
        do mask[(--s)->symbol] = 0; while (--i);
    } else {
        std::uint16_t &prob = p.bin_prob();
        const std::uint32_t bound = (range_ >> 14) * prob;
        if (code_ < bound) {
            range_ = bound;
            normalize();
            prob = std::uint16_t(prob + (1 << kIntBits) - mean(prob));
            p.found_state = Model::one_state(p.min_context);
            const int sym = p.found_state->symbol;
            p.update_bin();
            return sym;
        }
        code_ -= bound;
        range_ -= bound;
        normalize();
        prob = std::uint16_t(prob - mean(prob));
        p.init_esc = kExpEscape[prob >> 10];
        std::memset(mask, -1, sizeof mask);
        mask[Model::one_state(p.min_context)->symbol] = 0;
        p.prev_success = 0;
    }
    for (;;) {
        State *ps[256];
        const unsigned masked = p.min_context->num_stats;
        if (!p.escape_up(masked)) return -1;
        std::uint32_t hi = 0;
        State *s = p.stats(p.min_context);
        unsigned i = 0;
        const unsigned num = p.min_context->num_stats - masked;
        State *const end = s + p.min_context->num_stats;
        while (i != num) {
            if (s == end) return -2;
            const int k = mask[s->symbol];
            hi += s->freq & std::uint32_t(k);
            ps[i] = s++;
            i -= unsigned(k);
        }
        std::uint32_t freq_sum;
        See *see = p.make_esc_freq(masked, freq_sum);
        freq_sum += hi;
        const std::uint32_t count = threshold(freq_sum);
        if (count < hi) {
            State **pps = ps;
            for (hi = 0; (hi += (*pps)->freq) <= count; ++pps) {}
            s = *pps;
            take(hi - s->freq, s->freq);
            see->update();
            p.found_state = s;
            const int sym = s->symbol;
            p.update2();
            return sym;
        }
        if (count >= freq_sum) return -2;
        take(hi, freq_sum - hi);
        see->summ = std::uint16_t(see->summ + freq_sum);
        do mask[ps[--i]->symbol] = 0; while (i != 0);
    }
}

// ---- encoder

Encoder::Encoder(unsigned order, std::uint32_t memory) : m_(std::make_unique<Model>(order, memory)) {}
Encoder::~Encoder() = default;

void Encoder::shift_low()
{
    if (std::uint32_t(low_) < 0xFF000000u || (low_ >> 32) != 0) {
        std::uint8_t c = cache_;
        const auto carry = std::uint8_t(low_ >> 32);
        do {
            out.push_back(std::uint8_t(c + carry));
            c = 0xFF;
        } while (--cache_size_ != 0);
        cache_ = std::uint8_t(std::uint32_t(low_) >> 24);
    }
    ++cache_size_;
    low_ = std::uint64_t(std::uint32_t(low_) << 8);
}

void Encoder::put(std::uint32_t start, std::uint32_t size, std::uint32_t total)
{
    low_ += std::uint64_t(start) * (range_ /= total);
    range_ *= size;
    while (range_ < kTop) {
        range_ <<= 8;
        shift_low();
    }
}

void Encoder::put_bit(std::uint32_t size0, int bit)
{
    const std::uint32_t bound = (range_ >> 14) * size0;
    if (!bit) {
        range_ = bound;
    } else {
        low_ += bound;
        range_ -= bound;
    }
    while (range_ < kTop) {
        range_ <<= 8;
        shift_low();
    }
}

void Encoder::encode(const std::uint8_t *data, std::size_t n)
{
    for (std::size_t i = 0; i < n; ++i) symbol(data[i]);
}

void Encoder::finish()
{
    for (int i = 0; i < 5; ++i) shift_low();
}

void Encoder::symbol(int c)
{
    Model &p = *m_;
    std::int8_t mask[256];
    if (p.min_context->num_stats != 1) {
        State *s = p.stats(p.min_context);
        if (s->symbol == c) {
            put(0, s->freq, p.min_context->summ_freq);
            p.found_state = s;
            p.update1_0();
            return;
        }
        p.prev_success = 0;
        std::uint32_t sum = s->freq;
        unsigned i = p.min_context->num_stats - 1u;
        do {
            if ((++s)->symbol == c) {
                put(sum, s->freq, p.min_context->summ_freq);
                p.found_state = s;
                p.update1();
                return;
            }
            sum += s->freq;
        } while (--i);
        p.hi_bits_flag = p.hb2flag[p.found_state->symbol];
        std::memset(mask, -1, sizeof mask);
        mask[s->symbol] = 0;
        i = p.min_context->num_stats - 1u;
        do mask[(--s)->symbol] = 0; while (--i);
        put(sum, p.min_context->summ_freq - sum, p.min_context->summ_freq);
    } else {
        std::uint16_t &prob = p.bin_prob();
        State *s = Model::one_state(p.min_context);
        if (s->symbol == c) {
            put_bit(prob, 0);
            prob = std::uint16_t(prob + (1 << kIntBits) - mean(prob));
            p.found_state = s;
            p.update_bin();
            return;
        }
        put_bit(prob, 1);
        prob = std::uint16_t(prob - mean(prob));
        p.init_esc = kExpEscape[prob >> 10];
        std::memset(mask, -1, sizeof mask);
        mask[s->symbol] = 0;
        p.prev_success = 0;
    }
    for (;;) {
        const unsigned masked = p.min_context->num_stats;
        if (!p.escape_up(masked)) return;
        std::uint32_t esc;
        See *see = p.make_esc_freq(masked, esc);
        State *s = p.stats(p.min_context);
        std::uint32_t sum = 0;
        unsigned i = p.min_context->num_stats;
        do {
            const int cur = s->symbol;
            if (cur == c) {
                const std::uint32_t low = sum;
                State *s1 = s;
                do {
                    sum += s->freq & std::uint32_t(int(mask[s->symbol]));
                    ++s;
                } while (--i);
                put(low, s1->freq, sum + esc);
                see->update();
                p.found_state = s1;
                p.update2();
                return;
            }
            sum += s->freq & std::uint32_t(int(mask[cur]));
            mask[cur] = 0;
            ++s;
        } while (--i);
        put(sum, esc, sum + esc);
        see->summ = std::uint16_t(see->summ + sum + esc);
    }
}

} // namespace raye::archive::detail::ppmd7
