// SPDX-License-Identifier: GPL-3.0-or-later
// RAR 2.0 decoder: LZ with Huffman tables, and the multimedia mode that
// predicts audio samples per channel.
#include "rar.h"

#include <cstdlib>

namespace raye::archive::detail::rar {

namespace {

constexpr unsigned kNC = 298, kDC = 48, kRC = 28, kBC = 19, kMC = 257;

constexpr std::uint8_t kLDecode[28] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224};
constexpr std::uint8_t kLBits[28] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5};
constexpr std::uint32_t kDDecode[48] = {0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
                                        2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072,
                                        196608, 262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968,
                                        917504, 983040};
constexpr std::uint8_t kDBits[48] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
                                     11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16};
constexpr std::uint8_t kSDDecode[8] = {0, 4, 8, 16, 32, 64, 128, 192};
constexpr std::uint8_t kSDBits[8] = {2, 2, 3, 4, 5, 6, 6, 6};

struct Audio {
    int k[5] = {};
    int d1 = 0, d2 = 0, d3 = 0, d4 = 0;
    int last_delta = 0;
    std::uint32_t dif[11] = {};
    std::uint32_t count = 0;
    int last_char = 0;
};

class Rar2 final : public Decoder {
public:
    explicit Rar2(std::uint64_t window) { win_.ensure(window); }

    void decode(ByteIn &in, Output &out, const Item &item, bool solid) override
    {
        path_ = &item.entry.path;
        if (!solid) {
            unp_ = 0;
            tables_read_ = false;
            audio_ = false;
            channel_delta_ = 0;
            cur_ = 0;
            channels_ = 1;
            for (auto &a : av_) a = Audio{};
            std::fill(std::begin(old_table_), std::end(old_table_), 0);
            std::fill(std::begin(old_), std::end(old_), 0);
            old_ptr_ = 0;
            last_dist_ = last_len_ = 0;
        }
        wr_ = unp_;
        const std::uint64_t start = unp_;
        const std::uint64_t size = item.entry.size;
        bits_.reset(&in);
        if (!solid || !tables_read_) read_tables();
        const std::uint64_t flush_at = std::min<std::uint64_t>(win_.size() / 2, 4 << 20);
        while (unp_ - start < size) {
            bits_.fill();
            if (bits_.overrun()) fail(ErrorCode::Truncated, "compressed data ends early", *path_);
            if (unp_ - wr_ >= flush_at) flush(out);
            if (audio_) {
                const unsigned n = md_[cur_].decode(bits_);
                if (n == 256) {
                    read_tables();
                    continue;
                }
                win_.at(unp_++) = decode_audio(int(n));
                if (++cur_ == channels_) cur_ = 0;
                continue;
            }
            const unsigned n = ld_.decode(bits_);
            if (n < 256) {
                win_.at(unp_++) = std::uint8_t(n);
            } else if (n > 269) {
                const unsigned li = n - 270;
                std::uint32_t len = kLDecode[li] + 3u + bits_.get(kLBits[li]);
                const unsigned ds = dd_.decode(bits_);
                const std::uint32_t dist = kDDecode[ds] + 1u + bits_.get(kDBits[ds]);
                if (dist >= 0x2000) {
                    ++len;
                    if (dist >= 0x40000) ++len;
                }
                copy(len, dist);
            } else if (n == 269) {
                read_tables();
            } else if (n == 256) {
                copy(last_len_, last_dist_);
            } else if (n < 261) {
                const std::uint32_t dist = old_[(old_ptr_ - (n - 256)) & 3];
                const unsigned ls = rd_.decode(bits_);
                std::uint32_t len = kLDecode[ls] + 2u + bits_.get(kLBits[ls]);
                if (dist >= 0x101) {
                    ++len;
                    if (dist >= 0x2000) {
                        ++len;
                        if (dist >= 0x40000) ++len;
                    }
                }
                copy(len, dist);
            } else {
                const unsigned k = n - 261;
                copy(2, kSDDecode[k] + 1u + bits_.get(kSDBits[k]));
            }
        }
        // A table may follow the last symbol; it belongs to the next solid file.
        if (bits_.more(5)) {
            if (audio_) {
                if (md_[cur_].decode(bits_) == 256) read_tables();
            } else if (ld_.decode(bits_) == 269) {
                read_tables();
            }
        }
        flush(out);
    }

private:
    void copy(std::uint32_t len, std::uint32_t dist)
    {
        last_dist_ = old_[old_ptr_++ & 3] = dist;
        last_len_ = len;
        if (!len) return;
        if (dist == 0 || dist > win_.size()) fail(ErrorCode::Corrupt, "match distance is outside the dictionary", *path_);
        win_.copy(unp_, dist, len);
    }

    void flush(Output &out)
    {
        win_.emit(wr_, unp_, out);
        wr_ = unp_;
    }

    void read_tables()
    {
        bits_.fill();
        const std::uint32_t b = bits_.peek16();
        audio_ = (b & 0x8000) != 0;
        if (!(b & 0x4000)) std::fill(std::begin(old_table_), std::end(old_table_), 0);
        bits_.skip(2);
        unsigned size;
        if (audio_) {
            channels_ = ((b >> 12) & 3) + 1;
            if (cur_ >= channels_) cur_ = 0;
            bits_.skip(2);
            size = kMC * channels_;
        } else {
            size = kNC + kDC + kRC;
        }
        std::uint8_t bl[kBC];
        for (unsigned i = 0; i < kBC; ++i) bl[i] = std::uint8_t(bits_.get(4));
        Huff bc;
        bc.build(bl, kBC);
        std::uint8_t t[kMC * 4];
        for (unsigned i = 0; i < size;) {
            bits_.fill();
            const unsigned n = bc.decode(bits_);
            if (n < 16) {
                t[i] = std::uint8_t((n + old_table_[i]) & 15);
                ++i;
            } else if (n == 16) {
                unsigned rep = bits_.get(2) + 3;
                if (i == 0) fail(ErrorCode::Corrupt, "Huffman table repeats a length before the first one", *path_);
                for (; rep > 0 && i < size; --rep, ++i) t[i] = t[i - 1];
            } else {
                unsigned rep = n == 17 ? bits_.get(3) + 3 : bits_.get(7) + 11;
                for (; rep > 0 && i < size; --rep) t[i++] = 0;
            }
        }
        tables_read_ = true;
        if (audio_) {
            for (unsigned c = 0; c < channels_; ++c) md_[c].build(t + c * kMC, kMC);
        } else {
            ld_.build(t, kNC);
            dd_.build(t + kNC, kDC);
            rd_.build(t + kNC + kDC, kRC);
        }
        std::memcpy(old_table_, t, size);
    }

    std::uint8_t decode_audio(int delta)
    {
        Audio &v = av_[cur_];
        ++v.count;
        v.d4 = v.d3;
        v.d3 = v.d2;
        v.d2 = v.last_delta - v.d1;
        v.d1 = v.last_delta;
        int pch = 8 * v.last_char + v.k[0] * v.d1 + v.k[1] * v.d2 + v.k[2] * v.d3 + v.k[3] * v.d4 + v.k[4] * channel_delta_;
        pch = (pch >> 3) & 0xff;
        const unsigned ch = unsigned(pch - delta);
        const int d = int(std::int8_t(std::uint8_t(delta))) * 8;
        const int ds[5] = {v.d1, v.d2, v.d3, v.d4, channel_delta_};
        v.dif[0] += std::uint32_t(std::abs(d));
        for (int i = 0; i < 5; ++i) {
            v.dif[1 + 2 * i] += std::uint32_t(std::abs(d - ds[i]));
            v.dif[2 + 2 * i] += std::uint32_t(std::abs(d + ds[i]));
        }
        channel_delta_ = v.last_delta = std::int8_t(std::uint8_t(ch - unsigned(v.last_char)));
        v.last_char = int(ch & 0xff);
        if ((v.count & 0x1f) == 0) {
            std::uint32_t min = v.dif[0], num = 0;
            v.dif[0] = 0;
            for (std::uint32_t i = 1; i < 11; ++i) {
                if (v.dif[i] < min) {
                    min = v.dif[i];
                    num = i;
                }
                v.dif[i] = 0;
            }
            if (num) {
                int &k = v.k[(num - 1) / 2];
                if (num & 1) {
                    if (k >= -16) --k;
                } else if (k < 16) {
                    ++k;
                }
            }
        }
        return std::uint8_t(ch);
    }

    Window win_;
    BitIn bits_;
    Huff ld_, dd_, rd_, md_[4];
    std::uint8_t old_table_[kMC * 4] = {};
    bool tables_read_ = false, audio_ = false;
    unsigned channels_ = 1, cur_ = 0;
    int channel_delta_ = 0;
    Audio av_[4];
    std::uint64_t unp_ = 0, wr_ = 0;
    std::uint32_t old_[4] = {};
    unsigned old_ptr_ = 0;
    std::uint32_t last_dist_ = 0, last_len_ = 0;
    const std::string *path_ = nullptr;
};

} // namespace

std::unique_ptr<Decoder> make_rar2_decoder(std::uint64_t window)
{
    return std::make_unique<Rar2>(window);
}

} // namespace raye::archive::detail::rar
