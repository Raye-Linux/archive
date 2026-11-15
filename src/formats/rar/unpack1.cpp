// SPDX-License-Identifier: GPL-3.0-or-later
// RAR 1.5 decoder: adaptive codes driven by running averages, with
// move-to-front style symbol tables instead of stored Huffman tables.
#include "rar.h"

namespace raye::archive::detail::rar {

namespace {

constexpr std::uint32_t kDecL1[] = {0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff};
constexpr std::uint32_t kPosL1[] = {0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32};
constexpr std::uint32_t kDecL2[] = {0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff};
constexpr std::uint32_t kPosL2[] = {0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36};
constexpr std::uint32_t kDecHf0[] = {0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff};
constexpr std::uint32_t kPosHf0[] = {0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33};
constexpr std::uint32_t kDecHf1[] = {0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff};
constexpr std::uint32_t kPosHf1[] = {0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127};
constexpr std::uint32_t kDecHf2[] = {0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff};
constexpr std::uint32_t kPosHf2[] = {0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0};
constexpr std::uint32_t kDecHf3[] = {0x800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff};
constexpr std::uint32_t kPosHf3[] = {0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0};
constexpr std::uint32_t kDecHf4[] = {0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff};
constexpr std::uint32_t kPosHf4[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0};

constexpr unsigned kShortLen1[] = {1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0};
constexpr unsigned kShortXor1[] = {0, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0};
constexpr unsigned kShortLen2[] = {2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0};
constexpr unsigned kShortXor2[] = {0, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0};

class Rar1 final : public Decoder {
public:
    explicit Rar1(std::uint64_t window) { win_.ensure(window); }

    void decode(ByteIn &in, Output &out, const Item &item, bool solid) override
    {
        path_ = &item.entry.path;
        if (!solid) {
            unp_ = 0;
            avr_plc_b_ = avr_ln1_ = avr_ln2_ = avr_ln3_ = num_huf_ = buf60_ = 0;
            avr_plc_ = 0x3500;
            max_dist3_ = 0x2001;
            nhfb_ = nlzb_ = 0x80;
            std::fill(std::begin(old_), std::end(old_), 0);
            old_ptr_ = 0;
            last_dist_ = last_len_ = 0;
            init_huff();
        }
        flags_cnt_ = 0;
        flag_buf_ = 0;
        st_mode_ = 0;
        lcount_ = 0;
        wr_ = unp_;
        start_ = unp_;
        size_ = item.entry.size;
        bits_.reset(&in);
        if (size_ > 0) {
            bits_.fill();
            get_flags();
            flags_cnt_ = 8;
        }
        const std::uint64_t flush_at = std::min<std::uint64_t>(win_.size() / 2, 4 << 20);
        while (unp_ - start_ < size_) {
            bits_.fill();
            if (bits_.overrun()) fail(ErrorCode::Truncated, "compressed data ends early", *path_);
            if (unp_ - wr_ >= flush_at) flush(out);
            if (st_mode_) {
                huff_decode();
                continue;
            }
            if (--flags_cnt_ < 0) {
                get_flags();
                flags_cnt_ = 7;
            }
            if (flag_buf_ & 0x80) {
                flag_buf_ <<= 1;
                if (nlzb_ > nhfb_) long_lz();
                else huff_decode();
            } else {
                flag_buf_ <<= 1;
                if (--flags_cnt_ < 0) {
                    get_flags();
                    flags_cnt_ = 7;
                }
                if (flag_buf_ & 0x80) {
                    flag_buf_ <<= 1;
                    if (nlzb_ > nhfb_) huff_decode();
                    else long_lz();
                } else {
                    flag_buf_ <<= 1;
                    short_lz();
                }
            }
        }
        flush(out);
    }

private:
    void flush(Output &out)
    {
        win_.emit(wr_, unp_, out);
        wr_ = unp_;
    }

    std::uint32_t decode_num(std::uint32_t num, unsigned start, const std::uint32_t *dec, const std::uint32_t *pos)
    {
        num &= 0xfff0;
        unsigned i = 0;
        for (; dec[i] <= num; ++i) ++start;
        bits_.skip(start);
        return ((num - (i ? dec[i - 1] : 0)) >> (16 - start)) + pos[start];
    }

    void copy(std::uint32_t dist, std::uint32_t len)
    {
        if (dist > win_.size()) fail(ErrorCode::Corrupt, "match distance is outside the dictionary", *path_);
        win_.copy(unp_, dist, len);
    }

    void short_lz()
    {
        num_huf_ = 0;
        std::uint32_t b = bits_.peek16();
        if (lcount_ == 2) {
            bits_.skip(1);
            if (b >= 0x8000) {
                copy(last_dist_, last_len_);
                return;
            }
            b <<= 1;
            lcount_ = 0;
        }
        b = (b >> 8) & 0xff;
        unsigned len = 0;
        if (avr_ln1_ < 37) {
            for (;; ++len) {
                const unsigned l = len == 1 ? buf60_ + 3 : kShortLen1[len];
                if (len >= 15 || ((b ^ kShortXor1[len]) & (~(0xffu >> l) & 0xff)) == 0) {
                    bits_.skip(l);
                    break;
                }
            }
        } else {
            for (;; ++len) {
                const unsigned l = len == 3 ? buf60_ + 3 : kShortLen2[len];
                if (len >= 15 || ((b ^ kShortXor2[len]) & (~(0xffu >> l) & 0xff)) == 0) {
                    bits_.skip(l);
                    break;
                }
            }
        }
        if (len >= 9) {
            if (len == 9) {
                ++lcount_;
                copy(last_dist_, last_len_);
                return;
            }
            if (len == 14) {
                lcount_ = 0;
                len = decode_num(bits_.peek16(), 3, kDecL2, kPosL2) + 5;
                const std::uint32_t dist = (bits_.peek16() >> 1) | 0x8000;
                bits_.skip(15);
                last_len_ = len;
                last_dist_ = dist;
                copy(dist, len);
                return;
            }
            lcount_ = 0;
            const unsigned save = len;
            const std::uint32_t dist = old_[(old_ptr_ - (len - 9)) & 3];
            len = decode_num(bits_.peek16(), 2, kDecL1, kPosL1) + 2;
            if (len == 0x101 && save == 10) {
                buf60_ ^= 1;
                return;
            }
            if (dist > 256) ++len;
            if (dist >= max_dist3_) ++len;
            old_[old_ptr_++] = dist;
            old_ptr_ &= 3;
            last_len_ = len;
            last_dist_ = dist;
            copy(dist, len);
            return;
        }
        lcount_ = 0;
        avr_ln1_ += len;
        avr_ln1_ -= avr_ln1_ >> 4;
        int place = int(decode_num(bits_.peek16(), 5, kDecHf2, kPosHf2) & 0xff);
        std::uint32_t dist = chset_a_[place];
        if (--place != -1) {
            const std::uint32_t last = chset_a_[place];
            chset_a_[place + 1] = std::uint16_t(last);
            chset_a_[place] = std::uint16_t(dist);
        }
        len += 2;
        old_[old_ptr_++] = ++dist;
        old_ptr_ &= 3;
        last_len_ = len;
        last_dist_ = dist;
        copy(dist, len);
    }

    void long_lz()
    {
        num_huf_ = 0;
        nlzb_ += 16;
        if (nlzb_ > 0xff) {
            nlzb_ = 0x90;
            nhfb_ >>= 1;
        }
        const std::uint32_t old_avr2 = avr_ln2_;
        std::uint32_t b = bits_.peek16();
        std::uint32_t len;
        if (avr_ln2_ >= 122) {
            len = decode_num(b, 3, kDecL2, kPosL2);
        } else if (avr_ln2_ >= 64) {
            len = decode_num(b, 2, kDecL1, kPosL1);
        } else if (b < 0x100) {
            len = b;
            bits_.skip(16);
        } else {
            for (len = 0; ((b << len) & 0x8000) == 0; ++len) {}
            bits_.skip(len + 1);
        }
        avr_ln2_ += len;
        avr_ln2_ -= avr_ln2_ >> 5;
        b = bits_.peek16();
        std::uint32_t place;
        if (avr_plc_b_ > 0x28ff) place = decode_num(b, 5, kDecHf2, kPosHf2);
        else if (avr_plc_b_ > 0x6ff) place = decode_num(b, 5, kDecHf1, kPosHf1);
        else place = decode_num(b, 4, kDecHf0, kPosHf0);
        avr_plc_b_ += place;
        avr_plc_b_ -= avr_plc_b_ >> 8;
        std::uint32_t dist, new_place;
        for (;;) {
            dist = chset_b_[place & 0xff];
            new_place = ntopl_b_[dist++ & 0xff]++;
            if (!(dist & 0xff)) corr_huff(chset_b_, ntopl_b_);
            else break;
        }
        chset_b_[place & 0xff] = chset_b_[new_place];
        chset_b_[new_place] = std::uint16_t(dist);
        dist = ((dist & 0xff00) | (bits_.peek16() >> 8)) >> 1;
        bits_.skip(7);
        const std::uint32_t old_avr3 = avr_ln3_;
        if (len != 1 && len != 4) {
            if (len == 0 && dist <= max_dist3_) {
                ++avr_ln3_;
                avr_ln3_ -= avr_ln3_ >> 8;
            } else if (avr_ln3_ > 0) {
                --avr_ln3_;
            }
        }
        len += 3;
        if (dist >= max_dist3_) ++len;
        if (dist <= 256) len += 8;
        if (old_avr3 > 0xb0 || (avr_plc_ >= 0x2a00 && old_avr2 < 0x40)) max_dist3_ = 0x7f00;
        else max_dist3_ = 0x2001;
        old_[old_ptr_++] = dist;
        old_ptr_ &= 3;
        last_len_ = len;
        last_dist_ = dist;
        copy(dist, len);
    }

    void huff_decode()
    {
        std::uint32_t b = bits_.peek16();
        int place;
        if (avr_plc_ > 0x75ff) place = int(decode_num(b, 8, kDecHf4, kPosHf4));
        else if (avr_plc_ > 0x5dff) place = int(decode_num(b, 6, kDecHf3, kPosHf3));
        else if (avr_plc_ > 0x35ff) place = int(decode_num(b, 5, kDecHf2, kPosHf2));
        else if (avr_plc_ > 0x0dff) place = int(decode_num(b, 5, kDecHf1, kPosHf1));
        else place = int(decode_num(b, 4, kDecHf0, kPosHf0));
        place &= 0xff;
        if (st_mode_) {
            if (place == 0 && b > 0xfff) place = 0x100;
            if (--place == -1) {
                b = bits_.peek16();
                bits_.skip(1);
                if (b & 0x8000) {
                    num_huf_ = st_mode_ = 0;
                    return;
                }
                const std::uint32_t len = (b & 0x4000) ? 4 : 3;
                bits_.skip(1);
                std::uint32_t dist = decode_num(bits_.peek16(), 5, kDecHf2, kPosHf2);
                dist = (dist << 5) | (bits_.peek16() >> 11);
                bits_.skip(5);
                copy(dist, len);
                return;
            }
        } else if (num_huf_++ >= 16 && flags_cnt_ == 0) {
            st_mode_ = 1;
        }
        avr_plc_ += std::uint32_t(place);
        avr_plc_ -= avr_plc_ >> 8;
        nhfb_ += 16;
        if (nhfb_ > 0xff) {
            nhfb_ = 0x90;
            nlzb_ >>= 1;
        }
        win_.at(unp_++) = std::uint8_t(chset_[place] >> 8);
        std::uint32_t cur, new_place;
        for (;;) {
            cur = chset_[place];
            new_place = ntopl_[cur++ & 0xff]++;
            if ((cur & 0xff) > 0xa1) corr_huff(chset_, ntopl_);
            else break;
        }
        chset_[place] = chset_[new_place];
        chset_[new_place] = std::uint16_t(cur);
    }

    void get_flags()
    {
        const std::uint32_t place = decode_num(bits_.peek16(), 5, kDecHf2, kPosHf2);
        if (place >= 256) return;
        std::uint32_t flags, new_place;
        for (;;) {
            flags = chset_c_[place];
            flag_buf_ = flags >> 8;
            new_place = ntopl_c_[flags++ & 0xff]++;
            if ((flags & 0xff) != 0) break;
            corr_huff(chset_c_, ntopl_c_);
        }
        chset_c_[place] = chset_c_[new_place];
        chset_c_[new_place] = std::uint16_t(flags);
    }

    void init_huff()
    {
        for (unsigned i = 0; i < 256; ++i) {
            chset_[i] = chset_b_[i] = std::uint16_t(i << 8);
            chset_a_[i] = std::uint16_t(i);
            chset_c_[i] = std::uint16_t(((~i + 1) & 0xff) << 8);
        }
        std::fill(std::begin(ntopl_), std::end(ntopl_), 0);
        std::fill(std::begin(ntopl_b_), std::end(ntopl_b_), 0);
        std::fill(std::begin(ntopl_c_), std::end(ntopl_c_), 0);
        corr_huff(chset_b_, ntopl_b_);
    }

    static void corr_huff(std::uint16_t *set, std::uint8_t *to_place)
    {
        for (int i = 7; i >= 0; --i)
            for (int j = 0; j < 32; ++j, ++set) *set = std::uint16_t((*set & ~0xff) | i);
        std::memset(to_place, 0, 256);
        for (int i = 6; i >= 0; --i) to_place[i] = std::uint8_t((7 - i) * 32);
    }

    Window win_;
    BitIn bits_;
    std::uint64_t unp_ = 0, wr_ = 0, start_ = 0, size_ = 0;
    std::uint16_t chset_[256] = {}, chset_a_[256] = {}, chset_b_[256] = {}, chset_c_[256] = {};
    std::uint8_t ntopl_[256] = {}, ntopl_b_[256] = {}, ntopl_c_[256] = {};
    std::uint32_t avr_plc_ = 0, avr_plc_b_ = 0, avr_ln1_ = 0, avr_ln2_ = 0, avr_ln3_ = 0;
    std::uint32_t num_huf_ = 0, buf60_ = 0, max_dist3_ = 0, nhfb_ = 0, nlzb_ = 0;
    int flags_cnt_ = 0;
    std::uint32_t flag_buf_ = 0;
    int st_mode_ = 0;
    unsigned lcount_ = 0;
    std::uint32_t old_[4] = {};
    unsigned old_ptr_ = 0;
    std::uint32_t last_dist_ = 0, last_len_ = 0;
    const std::string *path_ = nullptr;
};

} // namespace

std::unique_ptr<Decoder> make_rar1_decoder(std::uint64_t window)
{
    return std::make_unique<Rar1>(window);
}

} // namespace raye::archive::detail::rar
