// SPDX-License-Identifier: GPL-3.0-or-later
// RAR 2.9 / 3.x / 4.x decoder: LZ with Huffman tables, PPMd blocks, and
// the standard VM filters (E8, E8E9, Itanium, delta, RGB, audio) run as
// native code. Filters are recognised by the CRC of their byte code.
#include "rar.h"

#include "ppmd.h"

#include "../../core/bytes.h"

#include <cstdlib>

namespace raye::archive::detail::rar {

namespace {

constexpr unsigned kNC = 299, kDC = 60, kLDC = 17, kRC = 28, kBC = 20;
constexpr unsigned kTable = kNC + kDC + kLDC + kRC;
constexpr std::uint32_t kVmMem = 0x40000;

constexpr std::uint8_t kLDecode[28] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224};
constexpr std::uint8_t kLBits[28] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5};
constexpr std::uint8_t kSDDecode[8] = {0, 4, 8, 16, 32, 64, 128, 192};
constexpr std::uint8_t kSDBits[8] = {2, 2, 3, 4, 5, 6, 6, 6};

struct DistTable {
    std::uint32_t base[kDC];
    std::uint8_t bits[kDC];
    DistTable()
    {
        static const std::uint8_t counts[] = {4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12};
        std::uint32_t dist = 0;
        unsigned slot = 0;
        for (unsigned b = 0; b < sizeof counts; ++b)
            for (unsigned j = 0; j < counts[b]; ++j, ++slot) {
                base[slot] = dist;
                bits[slot] = std::uint8_t(b);
                dist += 1u << b;
            }
    }
};
const DistTable kDist;

enum class FilterKind : std::uint8_t { E8, E8E9, Itanium, Delta, Rgb, Audio };

struct FilterDef {
    FilterKind kind;
    std::uint32_t last_length = 0;
};

struct Pending {
    std::uint64_t start;
    std::uint32_t length;
    std::size_t def;
    std::uint32_t r[7];
};

// MSB-first reader over a filter's own byte code.
class CodeBits {
public:
    explicit CodeBits(const std::vector<std::uint8_t> &d) : d_(d) { d_.resize(d_.size() + 8, 0); }
    std::uint32_t peek16() const
    {
        const std::size_t b = pos_ >> 3;
        if (b + 3 > d_.size()) return 0;
        const std::uint32_t v = std::uint32_t(d_[b]) << 16 | std::uint32_t(d_[b + 1]) << 8 | d_[b + 2];
        return (v >> (8 - (pos_ & 7))) & 0xffff;
    }
    void skip(unsigned n) { pos_ += n; }
    bool over() const { return (pos_ >> 3) > d_.size() - 8; }
    // RAR VM number encoding.
    std::uint32_t number()
    {
        std::uint32_t v = peek16();
        switch (v & 0xc000) {
        case 0: skip(6); return (v >> 10) & 15;
        case 0x4000:
            if ((v & 0x3c00) == 0) { skip(14); return 0xffffff00 | ((v >> 2) & 0xff); }
            skip(10);
            return (v >> 6) & 0xff;
        case 0x8000: skip(2); v = peek16(); skip(16); return v;
        default:
            skip(2);
            v = peek16() << 16;
            skip(16);
            v |= peek16();
            skip(16);
            return v;
        }
    }

private:
    std::vector<std::uint8_t> d_;
    std::size_t pos_ = 0;
};

class Rar3 final : public Decoder {
public:
    explicit Rar3(std::uint64_t window) { win_.ensure(window); }

    void decode(ByteIn &in, Output &out, const Item &item, bool solid) override
    {
        path_ = &item.entry.path;
        if (!solid) {
            unp_ = wr_ = 0;
            std::fill(std::begin(old_table_), std::end(old_table_), 0);
            tables_read_ = false;
            std::fill(std::begin(old_), std::end(old_), 0);
            last_len_ = 0;
            ppm_block_ = false;
            esc_ = 2;
            defs_.clear();
            last_filter_ = 0;
            ppm_.reset();
        }
        stack_.clear();
        file_start_ = wr_ = unp_;
        bits_.reset(&in);
        if (!solid || !tables_read_) read_tables();
        const std::uint64_t flush_at = std::min<std::uint64_t>(win_.size() / 2, 4 << 20);
        const std::uint64_t stop_at = item.size_known ? item.entry.size + (4 << 20) : ~std::uint64_t(0);
        for (;;) {
            bits_.fill();
            if (bits_.overrun()) {
                if (item.size_known && unp_ - file_start_ >= item.entry.size) break;
                fail(ErrorCode::Truncated, "compressed data ends early", *path_);
            }
            if (unp_ - wr_ >= flush_at) {
                flush(out);
                if (unp_ - wr_ > win_.size() - 0x2000) fail(ErrorCode::Corrupt, "filter block does not fit the window", *path_);
            }
            if (unp_ - file_start_ > stop_at) break; // runaway data: the checksum will say it
            if (ppm_block_) {
                if (!ppm_step()) break;
                continue;
            }
            const unsigned sym = ld_.decode(bits_);
            if (sym < 256) {
                win_.at(unp_++) = std::uint8_t(sym);
            } else if (sym >= 271) {
                const unsigned li = sym - 271;
                std::uint32_t len = kLDecode[li] + 3u + bits_.get(kLBits[li]);
                const unsigned ds = dd_.decode(bits_);
                std::uint32_t dist = kDist.base[ds] + 1;
                const unsigned db = kDist.bits[ds];
                if (db) {
                    if (ds > 9) {
                        if (db > 4) dist += bits_.get(db - 4) << 4;
                        if (low_rep_ > 0) {
                            --low_rep_;
                            dist += prev_low_;
                        } else {
                            const unsigned low = ldd_.decode(bits_);
                            if (low == 16) {
                                low_rep_ = 15;
                                dist += prev_low_;
                            } else {
                                dist += low;
                                prev_low_ = low;
                            }
                        }
                    } else {
                        dist += bits_.get(db);
                    }
                }
                if (dist >= 0x2000) {
                    ++len;
                    if (dist >= 0x40000) ++len;
                }
                insert_old(dist);
                last_len_ = len;
                copy(dist, len);
            } else if (sym == 256) {
                if (!end_of_block()) break;
            } else if (sym == 257) {
                read_vm_code();
            } else if (sym == 258) {
                if (last_len_) copy(old_[0], last_len_);
            } else if (sym < 263) {
                const unsigned n = sym - 259;
                const std::uint32_t dist = old_[n];
                for (unsigned i = n; i > 0; --i) old_[i] = old_[i - 1];
                old_[0] = dist;
                const unsigned ls = rd_.decode(bits_);
                const std::uint32_t len = kLDecode[ls] + 2u + bits_.get(kLBits[ls]);
                last_len_ = len;
                copy(dist, len);
            } else {
                const unsigned n = sym - 263;
                const std::uint32_t dist = kSDDecode[n] + 1u + bits_.get(kSDBits[n]);
                insert_old(dist);
                last_len_ = 2;
                copy(dist, 2);
            }
        }
        flush(out);
        stack_.clear();
    }

private:
    void insert_old(std::uint32_t d)
    {
        old_[3] = old_[2];
        old_[2] = old_[1];
        old_[1] = old_[0];
        old_[0] = d;
    }

    void copy(std::uint64_t dist, std::uint32_t len)
    {
        if (dist == 0 || dist > win_.size()) fail(ErrorCode::Corrupt, "match distance is outside the dictionary", *path_);
        win_.copy(unp_, dist, len);
    }

    bool ppm_step()
    {
        const int ch = ppm_.decode_char();
        if (ch < 0) fail(ErrorCode::Corrupt, "PPMd data is damaged", *path_);
        if (ch == esc_) {
            const int next = ppm_.decode_char();
            switch (next) {
            case 0: read_tables(); return true;
            case 2:
            case -1: return false;
            case 3: read_vm_code_ppm(); return true;
            case 4: {
                std::uint32_t dist = 0, len = 0;
                for (int i = 0; i < 4; ++i) {
                    const int c = ppm_.decode_char();
                    if (c < 0) fail(ErrorCode::Corrupt, "PPMd data is damaged", *path_);
                    if (i == 3) len = std::uint8_t(c);
                    else dist = (dist << 8) + std::uint8_t(c);
                }
                copy(dist + 2, len + 32);
                return true;
            }
            case 5: {
                const int c = ppm_.decode_char();
                if (c < 0) fail(ErrorCode::Corrupt, "PPMd data is damaged", *path_);
                copy(1, std::uint32_t(std::uint8_t(c)) + 4);
                return true;
            }
            default: break; // 1: the escape character itself
            }
        }
        win_.at(unp_++) = std::uint8_t(ch);
        return true;
    }

    bool end_of_block()
    {
        const std::uint32_t b = bits_.peek16();
        bool new_table, new_file = false;
        if (b & 0x8000) {
            new_table = true;
            bits_.skip(1);
        } else {
            new_file = true;
            new_table = (b & 0x4000) != 0;
            bits_.skip(2);
        }
        tables_read_ = !new_table;
        if (new_file) return false;
        read_tables();
        return true;
    }

    void read_tables()
    {
        bits_.align();
        bits_.fill();
        const std::uint32_t b = bits_.peek16();
        if (b & 0x8000) {
            ppm_block_ = true;
            if (!ppm_.init(bits_, esc_)) fail(ErrorCode::Corrupt, "bad PPMd parameters", *path_);
            tables_read_ = false; // a later solid file starts with a new block header
            return;
        }
        ppm_block_ = false;
        prev_low_ = 0;
        low_rep_ = 0;
        if (!(b & 0x4000)) std::fill(std::begin(old_table_), std::end(old_table_), 0);
        bits_.skip(2);
        std::uint8_t bl[kBC];
        for (unsigned i = 0; i < kBC; ++i) {
            const std::uint8_t len = std::uint8_t(bits_.get(4));
            if (len == 15) {
                unsigned zeros = bits_.get(4);
                if (zeros == 0) {
                    bl[i] = 15;
                } else {
                    zeros += 2;
                    while (zeros-- > 0 && i < kBC) bl[i++] = 0;
                    --i;
                }
            } else {
                bl[i] = len;
            }
        }
        Huff bc;
        bc.build(bl, kBC);
        std::uint8_t t[kTable];
        for (unsigned i = 0; i < kTable;) {
            bits_.fill();
            const unsigned n = bc.decode(bits_);
            if (n < 16) {
                t[i] = std::uint8_t((n + old_table_[i]) & 15);
                ++i;
            } else if (n < 18) {
                unsigned rep = n == 16 ? bits_.get(3) + 3 : bits_.get(7) + 11;
                if (i == 0) fail(ErrorCode::Corrupt, "Huffman table repeats a length before the first one", *path_);
                for (; rep > 0 && i < kTable; --rep, ++i) t[i] = t[i - 1];
            } else {
                unsigned rep = n == 18 ? bits_.get(3) + 3 : bits_.get(7) + 11;
                for (; rep > 0 && i < kTable; --rep) t[i++] = 0;
            }
        }
        tables_read_ = true;
        ld_.build(t, kNC);
        dd_.build(t + kNC, kDC);
        ldd_.build(t + kNC + kDC, kLDC);
        rd_.build(t + kNC + kDC + kLDC, kRC);
        std::memcpy(old_table_, t, kTable);
    }

    void read_vm_code()
    {
        const std::uint8_t first = std::uint8_t(bits_.get(8));
        std::uint32_t len = (first & 7) + 1;
        if (len == 7) len = bits_.get(8) + 7;
        else if (len == 8) len = bits_.get(16);
        if (len == 0) fail(ErrorCode::Corrupt, "empty filter code", *path_);
        std::vector<std::uint8_t> code(len);
        for (std::uint32_t i = 0; i < len; ++i) {
            bits_.fill();
            code[i] = std::uint8_t(bits_.get(8));
        }
        add_vm_code(first, code);
    }

    void read_vm_code_ppm()
    {
        auto next = [&] {
            const int c = ppm_.decode_char();
            if (c < 0) fail(ErrorCode::Corrupt, "PPMd data is damaged", *path_);
            return std::uint32_t(c);
        };
        const std::uint8_t first = std::uint8_t(next());
        std::uint32_t len = (first & 7) + 1;
        if (len == 7) len = next() + 7;
        else if (len == 8) {
            len = next() << 8;
            len |= next();
        }
        if (len == 0) fail(ErrorCode::Corrupt, "empty filter code", *path_);
        std::vector<std::uint8_t> code(len);
        for (auto &c : code) c = std::uint8_t(next());
        add_vm_code(first, code);
    }

    static FilterKind identify(const std::vector<std::uint8_t> &code)
    {
        std::uint8_t x = 0;
        for (std::size_t i = 1; i < code.size(); ++i) x ^= code[i];
        if (code.empty() || x != code[0]) fail(ErrorCode::Corrupt, "filter code checksum does not match");
        const std::uint32_t crc = crc32(0, code.data(), code.size());
        struct Known { std::size_t len; std::uint32_t crc; FilterKind kind; };
        static const Known known[] = {
            {53, 0xad576887, FilterKind::E8},     {57, 0x3cd7e57e, FilterKind::E8E9},
            {120, 0x3769893f, FilterKind::Itanium}, {29, 0x0e06077d, FilterKind::Delta},
            {149, 0x1c2c5dc8, FilterKind::Rgb},   {216, 0xbc85e701, FilterKind::Audio},
        };
        for (const auto &k : known)
            if (k.len == code.size() && k.crc == crc) return k.kind;
        fail(ErrorCode::UnsupportedMethod, "this archive uses a custom RAR VM filter");
    }

    void add_vm_code(std::uint8_t first, const std::vector<std::uint8_t> &code)
    {
        CodeBits in(code);
        std::size_t pos;
        if (first & 0x80) {
            pos = in.number();
            if (pos == 0) {
                defs_.clear();
                stack_.clear();
            } else {
                --pos;
            }
        } else {
            pos = last_filter_;
        }
        if (pos > defs_.size() || pos > 1024) fail(ErrorCode::Corrupt, "bad filter number", *path_);
        last_filter_ = pos;
        const bool fresh = pos == defs_.size();
        Pending p{};
        p.def = pos;
        std::uint32_t start = in.number();
        if (first & 0x40) start += 258;
        p.start = unp_ + start;
        if (first & 0x20) {
            p.length = in.number();
            if (!fresh) defs_[pos].last_length = p.length;
        } else {
            p.length = fresh ? 0 : defs_[pos].last_length;
        }
        p.r[3] = 0x3c000;
        p.r[4] = p.length;
        p.r[5] = 0;
        if (first & 0x10) {
            const unsigned mask = in.peek16() >> 9;
            in.skip(7);
            for (unsigned i = 0; i < 7; ++i)
                if (mask & (1u << i)) p.r[i] = in.number();
        }
        if (fresh) {
            const std::uint32_t size = in.number();
            if (size == 0 || size >= 0x10000) fail(ErrorCode::Corrupt, "bad filter code size", *path_);
            std::vector<std::uint8_t> prog(size);
            for (auto &b : prog) {
                b = std::uint8_t(in.peek16() >> 8);
                in.skip(8);
            }
            FilterDef d{identify(prog), (first & 0x20) ? p.length : 0};
            defs_.push_back(d);
        }
        if (first & 0x08) {
            const std::uint32_t size = in.number();
            if (size > 0x2000 - 0x40) fail(ErrorCode::Corrupt, "filter data too large", *path_);
            in.skip(size * 8); // global data: standard filters do not read it
        }
        if (in.over()) fail(ErrorCode::Corrupt, "filter code is cut short", *path_);
        p.r[4] = p.length;
        if (stack_.size() >= 8192) fail(ErrorCode::Corrupt, "too many filters in compressed data", *path_);
        stack_.push_back(p);
    }

    void flush(Output &out)
    {
        std::size_t i = 0;
        while (i < stack_.size()) {
            Pending &f = stack_[i];
            if (f.start < wr_) {
                stack_.erase(stack_.begin() + std::ptrdiff_t(i));
                continue;
            }
            if (f.start >= unp_) {
                ++i;
                continue;
            }
            win_.emit(wr_, f.start, out);
            wr_ = f.start;
            if (f.start + f.length > unp_) {
                // Not decoded yet: write nothing past its start for now.
                return;
            }
            mem_.resize(std::size_t(f.length) * 2 + 8);
            win_.read(f.start, f.length, mem_.data());
            std::uint32_t data_off = 0, data_len = f.length;
            run(f, data_off, data_len);
            std::size_t j = i + 1;
            // Several filters may be chained on the same block.
            while (j < stack_.size() && stack_[j].start == f.start && stack_[j].length == data_len) {
                if (data_off) std::memmove(mem_.data(), mem_.data() + data_off, data_len);
                Pending &g = stack_[j];
                std::uint32_t off2 = 0, len2 = data_len;
                run(g, off2, len2);
                data_off = off2;
                data_len = len2;
                ++j;
            }
            out.put(mem_.data() + data_off, data_len);
            wr_ = f.start + f.length;
            stack_.erase(stack_.begin() + std::ptrdiff_t(i), stack_.begin() + std::ptrdiff_t(j));
        }
        win_.emit(wr_, unp_, out);
        wr_ = unp_;
    }

    // Runs a standard filter on mem_[0, len). Its result is at mem_[off, off+len).
    void run(Pending &f, std::uint32_t &off, std::uint32_t &len)
    {
        const FilterKind kind = defs_.at(f.def).kind;
        const std::uint32_t size = f.r[4];
        std::uint8_t *d = mem_.data();
        const std::uint32_t file_off = std::uint32_t(wr_ - file_start_);
        if (size != len) fail(ErrorCode::Corrupt, "filter size does not match its block", *path_);
        switch (kind) {
        case FilterKind::E8:
        case FilterKind::E8E9: {
            if (size > kVmMem || size < 4) fail(ErrorCode::Corrupt, "bad E8 filter size", *path_);
            constexpr std::uint32_t kFile = 0x1000000;
            const bool e9 = kind == FilterKind::E8E9;
            for (std::uint32_t pos = 0; pos < size - 4;) {
                const std::uint8_t b = d[pos++];
                if (b == 0xe8 || (e9 && b == 0xe9)) {
                    const std::uint32_t at = pos + file_off;
                    const std::uint32_t addr = le32(d + pos);
                    if (addr & 0x80000000u) {
                        if (((addr + at) & 0x80000000u) == 0) put_le32(d + pos, addr + kFile);
                    } else if ((addr - kFile) & 0x80000000u) {
                        put_le32(d + pos, addr - at);
                    }
                    pos += 4;
                }
            }
            off = 0;
            return;
        }
        case FilterKind::Itanium: {
            if (size > kVmMem || size < 21) fail(ErrorCode::Corrupt, "bad Itanium filter size", *path_);
            static const std::uint8_t masks[16] = {4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0};
            std::uint32_t fo = file_off >> 4;
            for (std::uint32_t pos = 0; pos < size - 21; pos += 16, ++fo) {
                std::uint8_t *p = d + pos;
                const int b = (p[0] & 0x1f) - 0x10;
                if (b < 0) continue;
                const std::uint8_t m = masks[b];
                if (!m) continue;
                for (unsigned k = 0; k <= 2; ++k) {
                    if (!(m & (1u << k))) continue;
                    const unsigned sp = k * 41 + 5;
                    if (ia_get(p, sp + 37, 4) == 5) {
                        const std::uint32_t o = ia_get(p, sp + 13, 20);
                        ia_set(p, (o - fo) & 0xfffff, sp + 13, 20);
                    }
                }
            }
            off = 0;
            return;
        }
        case FilterKind::Delta: {
            const std::uint32_t ch = f.r[0];
            if (size > kVmMem / 2 || ch > 1024 || ch == 0) fail(ErrorCode::Corrupt, "bad delta filter", *path_);
            std::uint32_t src = 0;
            for (std::uint32_t c = 0; c < ch; ++c) {
                std::uint8_t prev = 0;
                for (std::uint32_t p = size + c; p < 2 * size; p += ch) d[p] = prev = std::uint8_t(prev - d[src++]);
            }
            off = size;
            return;
        }
        case FilterKind::Rgb: {
            const std::uint32_t width = f.r[0] - 3, pos_r = f.r[1];
            if (size > kVmMem / 2 || size < 3 || width > size || pos_r > 2) fail(ErrorCode::Corrupt, "bad RGB filter", *path_);
            std::uint8_t *dst = d + size;
            const std::uint8_t *src = d;
            for (std::uint32_t c = 0; c < 3; ++c) {
                std::uint32_t prev = 0;
                for (std::uint32_t i = c; i < size; i += 3) {
                    std::uint32_t pred;
                    if (i >= width + 3) {
                        const std::uint8_t *up = dst + i - width;
                        const std::uint32_t ub = up[0], ul = *(up - 3);
                        pred = prev + ub - ul;
                        const int pa = std::abs(int(pred - prev)), pb = std::abs(int(pred - ub)), pc = std::abs(int(pred - ul));
                        if (pa <= pb && pa <= pc) pred = prev;
                        else if (pb <= pc) pred = ub;
                        else pred = ul;
                    } else {
                        pred = prev;
                    }
                    dst[i] = std::uint8_t(pred - *src++);
                    prev = dst[i];
                }
            }
            for (std::uint32_t i = pos_r; i + 2 < size; i += 3) {
                const std::uint8_t g = dst[i + 1];
                dst[i] = std::uint8_t(dst[i] + g);
                dst[i + 2] = std::uint8_t(dst[i + 2] + g);
            }
            off = size;
            return;
        }
        case FilterKind::Audio: {
            const std::uint32_t ch = f.r[0];
            if (size > kVmMem / 2 || ch > 128 || ch == 0) fail(ErrorCode::Corrupt, "bad audio filter", *path_);
            std::uint8_t *dst = d + size;
            const std::uint8_t *src = d;
            for (std::uint32_t c = 0; c < ch; ++c) {
                std::uint32_t prev = 0, prev_delta = 0, dif[7] = {};
                int d1 = 0, d2 = 0, d3, k1 = 0, k2 = 0, k3 = 0;
                for (std::uint32_t i = c, count = 0; i < size; i += ch, ++count) {
                    d3 = d2;
                    d2 = int(prev_delta) - d1;
                    d1 = int(prev_delta);
                    std::uint32_t pred = 8 * prev + std::uint32_t(k1 * d1) + std::uint32_t(k2 * d2) + std::uint32_t(k3 * d3);
                    pred = (pred >> 3) & 0xff;
                    const std::uint32_t cur = *src++;
                    pred -= cur;
                    dst[i] = std::uint8_t(pred);
                    prev_delta = std::uint32_t(std::int8_t(std::uint8_t(pred - prev)));
                    prev = std::uint8_t(pred);
                    const int dv = int(std::int8_t(std::uint8_t(cur))) * 8;
                    dif[0] += std::uint32_t(std::abs(dv));
                    dif[1] += std::uint32_t(std::abs(dv - d1));
                    dif[2] += std::uint32_t(std::abs(dv + d1));
                    dif[3] += std::uint32_t(std::abs(dv - d2));
                    dif[4] += std::uint32_t(std::abs(dv + d2));
                    dif[5] += std::uint32_t(std::abs(dv - d3));
                    dif[6] += std::uint32_t(std::abs(dv + d3));
                    if ((count & 0x1f) == 0) {
                        std::uint32_t min = dif[0], num = 0;
                        dif[0] = 0;
                        for (std::uint32_t j = 1; j < 7; ++j) {
                            if (dif[j] < min) { min = dif[j]; num = j; }
                            dif[j] = 0;
                        }
                        switch (num) {
                        case 1: if (k1 >= -16) --k1; break;
                        case 2: if (k1 < 16) ++k1; break;
                        case 3: if (k2 >= -16) --k2; break;
                        case 4: if (k2 < 16) ++k2; break;
                        case 5: if (k3 >= -16) --k3; break;
                        case 6: if (k3 < 16) ++k3; break;
                        }
                    }
                }
            }
            off = size;
            return;
        }
        }
    }

    static std::uint32_t ia_get(const std::uint8_t *d, unsigned bit, unsigned count)
    {
        const unsigned b = bit / 8;
        std::uint32_t v = d[b] | std::uint32_t(d[b + 1]) << 8 | std::uint32_t(d[b + 2]) << 16 | std::uint32_t(d[b + 3]) << 24;
        v >>= bit & 7;
        return v & (0xffffffffu >> (32 - count));
    }

    static void ia_set(std::uint8_t *d, std::uint32_t v, unsigned bit, unsigned count)
    {
        const unsigned b = bit / 8, sh = bit & 7;
        std::uint32_t and_mask = 0xffffffffu >> (32 - count);
        and_mask = ~(and_mask << sh);
        v <<= sh;
        for (unsigned i = 0; i < 4; ++i) {
            d[b + i] &= std::uint8_t(and_mask);
            d[b + i] |= std::uint8_t(v);
            and_mask = (and_mask >> 8) | 0xff000000u;
            v >>= 8;
        }
    }

    Window win_;
    BitIn bits_;
    Huff ld_, dd_, ldd_, rd_;
    std::uint8_t old_table_[kTable] = {};
    bool tables_read_ = false, ppm_block_ = false;
    int esc_ = 2;
    Ppmd ppm_;
    std::uint64_t unp_ = 0, wr_ = 0, file_start_ = 0;
    std::uint32_t old_[4] = {};
    std::uint32_t last_len_ = 0, prev_low_ = 0, low_rep_ = 0;
    std::vector<FilterDef> defs_;
    std::size_t last_filter_ = 0;
    std::vector<Pending> stack_;
    std::vector<std::uint8_t> mem_;
    const std::string *path_ = nullptr;
};

} // namespace

std::unique_ptr<Decoder> make_rar3_decoder(std::uint64_t window)
{
    return std::make_unique<Rar3>(window);
}

} // namespace raye::archive::detail::rar
