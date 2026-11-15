// SPDX-License-Identifier: GPL-3.0-or-later
// RAR 5.0 / 7.0 LZ decoder: Huffman-coded blocks, four repeat distances,
// and DELTA, E8, E8E9 and ARM filters run natively on the output.
#include "rar.h"

#include "../../core/bytes.h"

#include <deque>

namespace raye::archive::detail::rar {

namespace {

constexpr unsigned kNC = 306, kLDC = 16, kRC = 44, kBC = 20;
constexpr std::uint32_t kMaxFilterBlock = 0x400000;
constexpr std::size_t kMaxFilters = 8192;

enum FilterType : std::uint8_t { kDelta = 0, kE8 = 1, kE8E9 = 2, kArm = 3 };

struct Filter {
    std::uint64_t start;
    std::uint32_t length;
    std::uint8_t type, channels;
};

class Rar5 final : public Decoder {
public:
    Rar5(std::uint64_t window, bool v7) : dc_(v7 ? 80 : 64) { win_.ensure(window); }

    void decode(ByteIn &in, Output &out, const Item &item, bool solid) override
    {
        if (!solid) {
            unp_ = wr_ = 0;
            tables_ = false;
            std::fill(std::begin(old_), std::end(old_), 0);
            last_len_ = 0;
        }
        if (item.dict > win_.size() && item.dict <= (std::uint64_t(1) << 40)) {
            // A later file of a solid set may ask for more; keep what we have.
            if (!solid) win_.ensure(window_size(item.dict, item.entry.size, item.size_known));
        }
        filters_.clear();
        file_start_ = wr_ = unp_;
        bits_.reset(&in);
        bool in_block = false, last = false;
        std::uint64_t block_end = 0;
        const std::uint64_t flush_at = std::min<std::uint64_t>(win_.size() / 2, 4 << 20);
        for (;;) {
            bits_.fill();
            if (!in_block || bits_.bit_pos() >= block_end) {
                if (in_block && last) break;
                // Solid files may end on a block that is not marked last: the
                // end of their packed data is the end of the file, as in unrar.
                if (in_block) {
                    bits_.align();
                    if (!bits_.more(3)) break;
                }
                block_end = block_header(last);
                in_block = true;
                continue;
            }
            if (unp_ - wr_ >= flush_at) {
                flush(out, false);
                if (unp_ - wr_ > win_.size() - 0x2000)
                    fail(ErrorCode::Corrupt, "filter block does not fit the window", item.entry.path);
            }
            const unsigned sym = ld_.decode(bits_);
            if (sym < 256) {
                win_.at(unp_++) = std::uint8_t(sym);
                continue;
            }
            if (sym >= 262) {
                std::uint32_t len = slot_length(sym - 262);
                const std::uint64_t dist = distance();
                if (dist > 0x100) {
                    ++len;
                    if (dist > 0x2000) {
                        ++len;
                        if (dist > 0x40000) ++len;
                    }
                }
                old_[3] = old_[2];
                old_[2] = old_[1];
                old_[1] = old_[0];
                old_[0] = dist;
                last_len_ = len;
                copy(dist, len);
                continue;
            }
            if (sym == 256) {
                read_filter(out);
                continue;
            }
            if (sym == 257) {
                if (last_len_) copy(old_[0], last_len_);
                continue;
            }
            const unsigned idx = sym - 258;
            const std::uint64_t dist = old_[idx];
            for (unsigned i = idx; i > 0; --i) old_[i] = old_[i - 1];
            old_[0] = dist;
            const std::uint32_t len = slot_length(rd_.decode(bits_));
            last_len_ = len;
            copy(dist, len);
        }
        flush(out, true);
    }

private:
    void copy(std::uint64_t dist, std::uint32_t len)
    {
        if (dist == 0 || dist > win_.size()) fail(ErrorCode::Corrupt, "match distance is outside the dictionary");
        win_.copy(unp_, dist, len);
    }

    std::uint32_t slot_length(unsigned slot)
    {
        if (slot < 8) return slot + 2;
        const unsigned lbits = slot / 4 - 1;
        return 2 + ((4u | (slot & 3)) << lbits) + bits_.get(lbits);
    }

    std::uint64_t get_long(unsigned n)
    {
        if (n <= 32) return bits_.get(n);
        const std::uint64_t hi = bits_.get(n - 32);
        return (hi << 32) | bits_.get(32);
    }

    std::uint64_t distance()
    {
        const unsigned slot = dd_.decode(bits_);
        if (slot < 4) return 1 + slot;
        const unsigned dbits = slot / 2 - 1;
        std::uint64_t dist = 1 + (std::uint64_t(2 | (slot & 1)) << dbits);
        if (dbits >= 4) {
            if (dbits > 4) dist += get_long(dbits - 4) << 4;
            dist += ldd_.decode(bits_);
        } else {
            dist += bits_.get(dbits);
        }
        return dist;
    }

    // Returns the bit position where the block's data ends.
    std::uint64_t block_header(bool &last)
    {
        bits_.align();
        const std::uint8_t flags = bits_.byte();
        const std::uint8_t sum = bits_.byte();
        const unsigned count = ((flags >> 3) & 3) + 1;
        if (count == 4) fail(ErrorCode::Corrupt, "bad block header in compressed data");
        std::uint32_t size = 0;
        std::uint8_t check = 0x5a ^ flags;
        for (unsigned i = 0; i < count; ++i) {
            const std::uint8_t b = bits_.byte();
            size |= std::uint32_t(b) << (8 * i);
            check ^= b;
        }
        if (check != sum) fail(ErrorCode::Corrupt, "block header checksum does not match");
        last = (flags & 0x40) != 0;
        const std::uint64_t start = bits_.bit_pos();
        const std::uint64_t end = size ? start + (std::uint64_t(size) - 1) * 8 + (flags & 7) + 1 : start;
        if (flags & 0x80) read_tables(end);
        else if (!tables_) fail(ErrorCode::Corrupt, "compressed block without Huffman tables");
        return end;
    }

    void read_tables(std::uint64_t end)
    {
        std::uint8_t bl[kBC];
        for (unsigned i = 0; i < kBC;) {
            const std::uint8_t len = std::uint8_t(bits_.get(4));
            if (len == 15) {
                unsigned zeros = bits_.get(4);
                if (zeros == 0) bl[i++] = 15;
                else for (zeros += 2; zeros-- > 0 && i < kBC;) bl[i++] = 0;
            } else {
                bl[i++] = len;
            }
        }
        Huff bc;
        bc.build(bl, kBC);
        const unsigned total = kNC + dc_ + kLDC + kRC;
        std::uint8_t t[kNC + 80 + kLDC + kRC];
        for (unsigned i = 0; i < total;) {
            bits_.fill();
            const unsigned n = bc.decode(bits_);
            if (n < 16) {
                t[i++] = std::uint8_t(n);
            } else if (n < 18) {
                unsigned rep = n == 16 ? bits_.get(3) + 3 : bits_.get(7) + 11;
                if (i == 0) fail(ErrorCode::Corrupt, "Huffman table repeats a length before the first one");
                for (; rep > 0 && i < total; --rep, ++i) t[i] = t[i - 1];
            } else {
                unsigned rep = n == 18 ? bits_.get(3) + 3 : bits_.get(7) + 11;
                for (; rep > 0 && i < total; --rep) t[i++] = 0;
            }
        }
        if (bits_.bit_pos() > end) fail(ErrorCode::Corrupt, "Huffman tables run past their block");
        ld_.build(t, kNC);
        dd_.build(t + kNC, dc_);
        ldd_.build(t + kNC + dc_, kLDC);
        rd_.build(t + kNC + dc_ + kLDC, kRC);
        tables_ = true;
    }

    std::uint32_t filter_number()
    {
        const unsigned n = bits_.get(2) + 1;
        std::uint32_t v = 0;
        for (unsigned i = 0; i < n; ++i) v |= bits_.get(8) << (8 * i);
        return v;
    }

    void read_filter(Output &out)
    {
        Filter f{};
        const std::uint32_t start = filter_number();
        f.length = filter_number();
        f.type = std::uint8_t(bits_.get(3));
        if (f.type == kDelta) f.channels = std::uint8_t(bits_.get(5) + 1);
        if (f.type > kArm) fail(ErrorCode::Corrupt, "unknown filter in compressed data");
        if (f.length > kMaxFilterBlock) f.length = 0;
        f.start = unp_ + start;
        if (!filters_.empty() && f.start < filters_.back().start)
            fail(ErrorCode::Corrupt, "filters out of order in compressed data");
        if (filters_.size() >= kMaxFilters) {
            flush(out, false);
            if (filters_.size() >= kMaxFilters) fail(ErrorCode::Corrupt, "too many filters in compressed data");
        }
        filters_.push_back(f);
    }

    void flush(Output &out, bool final)
    {
        while (!filters_.empty()) {
            Filter &f = filters_.front();
            if (f.start < wr_) { // overlaps data already written: drop it
                filters_.pop_front();
                continue;
            }
            if (f.start >= unp_) break;
            win_.emit(wr_, f.start, out);
            wr_ = f.start;
            if (f.start + f.length > unp_) {
                if (!final) return;
                break;
            }
            buf_.resize(f.length);
            win_.read(f.start, f.length, buf_.data());
            const std::uint8_t *res = apply(f, std::uint32_t(f.start - file_start_));
            out.put(res, f.length);
            wr_ += f.length;
            filters_.pop_front();
        }
        win_.emit(wr_, unp_, out);
        wr_ = unp_;
        if (final) filters_.clear();
    }

    const std::uint8_t *apply(const Filter &f, std::uint32_t offset)
    {
        std::uint8_t *d = buf_.data();
        const std::uint32_t n = f.length;
        switch (f.type) {
        case kE8:
        case kE8E9: {
            constexpr std::uint32_t kFileSize = 0x1000000;
            const bool e9 = f.type == kE8E9;
            if (n < 5) break;
            for (std::uint32_t pos = 0; pos < n - 4;) {
                const std::uint8_t b = d[pos++];
                if (b == 0xe8 || (e9 && b == 0xe9)) {
                    const std::uint32_t at = (pos + offset) % kFileSize;
                    const std::uint32_t addr = le32(d + pos);
                    if (addr & 0x80000000u) {
                        if (((addr + at) & 0x80000000u) == 0) put_le32(d + pos, addr + kFileSize);
                    } else if ((addr - kFileSize) & 0x80000000u) {
                        put_le32(d + pos, addr - at);
                    }
                    pos += 4;
                }
            }
            break;
        }
        case kArm:
            for (std::uint32_t pos = 0; pos + 3 < n; pos += 4) {
                std::uint8_t *p = d + pos;
                if (p[3] == 0xeb) {
                    std::uint32_t v = p[0] | std::uint32_t(p[1]) << 8 | std::uint32_t(p[2]) << 16;
                    v -= (offset + pos) / 4;
                    p[0] = std::uint8_t(v);
                    p[1] = std::uint8_t(v >> 8);
                    p[2] = std::uint8_t(v >> 16);
                }
            }
            break;
        case kDelta: {
            dst_.resize(n);
            std::uint32_t src = 0;
            for (unsigned c = 0; c < f.channels; ++c) {
                std::uint8_t prev = 0;
                for (std::uint32_t pos = c; pos < n; pos += f.channels) dst_[pos] = prev = std::uint8_t(prev - d[src++]);
            }
            return dst_.data();
        }
        }
        return d;
    }

    Window win_;
    BitIn bits_;
    Huff ld_, dd_, ldd_, rd_;
    unsigned dc_;
    bool tables_ = false;
    std::uint64_t unp_ = 0, wr_ = 0, file_start_ = 0;
    std::uint64_t old_[4] = {};
    std::uint32_t last_len_ = 0;
    std::deque<Filter> filters_;
    std::vector<std::uint8_t> buf_, dst_;
};

} // namespace

std::unique_ptr<Decoder> make_rar5_decoder(std::uint64_t window, bool v7)
{
    return std::make_unique<Rar5>(window, v7);
}

} // namespace raye::archive::detail::rar
