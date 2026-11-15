// SPDX-License-Identifier: GPL-3.0-or-later
#include "rar.h"

#include <algorithm>
#include <ctime>

namespace raye::archive::detail::rar {

const Source &Volumes::get(std::uint32_t v, const std::string &entry) const
{
    if (v >= src.size() || !src[v])
        fail(ErrorCode::MissingVolume, "a volume of this archive is missing", entry);
    return *src[v];
}

// ---------------------------------------------------------------- input

PackedStream::PackedStream(const Volumes &vols, const Item &item, const Keys *keys) : vols_(vols), item_(item)
{
    for (const auto &p : item.parts) total_ += p.size;
    if (keys) aes_ = std::make_unique<Aes>(keys->key, Aes::Mode::Cbc, false, keys->iv);
}

std::size_t PackedStream::read_raw(std::uint8_t *out, std::size_t n)
{
    while (part_ < item_.parts.size()) {
        const Part &p = item_.parts[part_];
        if (in_part_ >= p.size) {
            ++part_;
            in_part_ = 0;
            continue;
        }
        const std::size_t take = std::size_t(std::min<std::uint64_t>(n, p.size - in_part_));
        const std::size_t got = vols_.get(p.volume, item_.entry.path).read_at(p.offset + in_part_, out, take);
        if (got == 0) return 0; // volume shorter than its header said
        in_part_ += got;
        return got;
    }
    return 0;
}

std::size_t PackedStream::read(std::uint8_t *out, std::size_t n)
{
    if (!aes_) return read_raw(out, n);
    if (pend_pos_ >= pend_.size()) {
        pend_.resize(1 << 16);
        std::size_t have = 0;
        while (have < pend_.size()) {
            const std::size_t got = read_raw(pend_.data() + have, pend_.size() - have);
            if (!got) break;
            have += got;
        }
        have &= ~std::size_t(15); // a partial AES block is padding we cannot use
        aes_->process(pend_.data(), pend_.data(), have);
        pend_.resize(have);
        pend_pos_ = 0;
        if (!have) return 0;
    }
    const std::size_t take = std::min(n, pend_.size() - pend_pos_);
    std::memcpy(out, pend_.data() + pend_pos_, take);
    pend_pos_ += take;
    return take;
}

void BitIn::refill()
{
    const std::size_t keep_from = pos_ >> 3;
    const std::size_t keep = len_ > keep_from ? len_ - keep_from : 0;
    if (keep_from) {
        std::memmove(buf_.data(), buf_.data() + keep_from, keep);
        dropped_ += keep_from;
        pos_ -= keep_from * 8;
        len_ = keep;
    }
    while (len_ < kChunk && !eof_) {
        const std::size_t got = src_->read(buf_.data() + len_, kChunk - len_);
        if (!got) eof_ = true;
        len_ += got;
    }
    std::memset(buf_.data() + len_, 0, buf_.size() - len_);
}

void Huff::build(const std::uint8_t *lens, unsigned n)
{
    unsigned count[16] = {};
    for (unsigned i = 0; i < n; ++i) ++count[lens[i] & 15];
    count[0] = 0;
    std::uint32_t upper = 0;
    limit_[0] = 0;
    pos_[0] = 0;
    for (unsigned i = 1; i < 16; ++i) {
        upper += count[i];
        limit_[i] = upper << (16 - i);
        upper *= 2;
        pos_[i] = pos_[i - 1] + count[i - 1];
    }
    std::uint32_t next[16];
    std::memcpy(next, pos_, sizeof next);
    std::fill(std::begin(sym_), std::end(sym_), 0);
    for (unsigned i = 0; i < n; ++i)
        if (lens[i] & 15) sym_[next[lens[i] & 15]++] = std::uint16_t(i);
    n_ = n;
    unsigned len = 0;
    for (unsigned code = 0; code < (1u << kQuick); ++code) {
        const std::uint32_t bits = code << (16 - kQuick);
        while (len < 16 && bits >= limit_[len]) ++len;
        qlen_[code] = std::uint8_t(len);
        const std::uint32_t pos = len < 16 ? pos_[len] + ((bits - limit_[len - 1]) >> (16 - len)) : n;
        qsym_[code] = pos < n ? sym_[pos] : 0;
    }
}

// ---------------------------------------------------------------- output

Output::Output(Sink *sink, const Item &item, Context &ctx)
    : sink_(sink), ctx_(ctx), limit_(item.entry.size), known_(item.size_known)
{
    if (item.has_blake) b2_ = std::make_unique<Blake2sp>();
}

void Output::put(const std::uint8_t *p, std::size_t n)
{
    if (known_) n = std::size_t(std::min<std::uint64_t>(n, limit_ - std::min(limit_, written_)));
    if (!n) return;
    crc_ = crc32(crc_, p, n);
    if (b2_) b2_->update(p, n);
    if (sink_) sink_->write(p, n);
    written_ += n;
    ctx_.add_bytes(n);
    since_check_ += n;
    if (since_check_ >= (1 << 20)) {
        since_check_ = 0;
        ctx_.checkpoint();
    }
}

std::array<std::uint8_t, 32> Output::blake()
{
    if (!b2_) return {};
    return b2_->final();
}

void Window::ensure(std::uint64_t size)
{
    if (size <= size_) return;
    w_.reset(new (std::nothrow) std::uint8_t[size]());
    if (!w_) {
        size_ = 0;
        fail(ErrorCode::NoSpace, "not enough memory for the dictionary of this archive");
    }
    size_ = size;
}

void Window::emit(std::uint64_t from, std::uint64_t to, Output &out)
{
    while (from < to) {
        const std::uint64_t off = from & (size_ - 1);
        const std::size_t n = std::size_t(std::min(to - from, size_ - off));
        out.put(w_.get() + off, n);
        from += n;
    }
}

void Window::read(std::uint64_t from, std::size_t n, std::uint8_t *dst) const
{
    while (n) {
        const std::uint64_t off = from & (size_ - 1);
        const std::size_t k = std::size_t(std::min<std::uint64_t>(n, size_ - off));
        std::memcpy(dst, w_.get() + off, k);
        dst += k;
        from += k;
        n -= k;
    }
}

std::uint64_t window_size(std::uint64_t dict, std::uint64_t total, bool total_known)
{
    if (dict > (std::uint64_t(1) << 32))
        fail(ErrorCode::UnsupportedMethod, "dictionaries larger than 4 GB are not supported");
    // Room for a 4 MB filter block plus the longest match, whatever the dictionary.
    std::uint64_t want = std::max<std::uint64_t>(dict, 8 << 20);
    if (total_known) want = std::min(want, total + 0x10000);
    want = std::max<std::uint64_t>(want, 0x40000);
    std::uint64_t s = 1;
    while (s < want) s <<= 1;
    return s;
}

// ---------------------------------------------------------------- names, times

Timestamp dos_time(std::uint32_t d)
{
    std::tm t{};
    t.tm_sec = int(d & 31) * 2;
    t.tm_min = int(d >> 5) & 63;
    t.tm_hour = int(d >> 11) & 31;
    t.tm_mday = int(d >> 16) & 31;
    t.tm_mon = int((d >> 21) & 15) - 1;
    t.tm_year = int(d >> 25) + 80;
    t.tm_isdst = -1;
    const std::time_t v = std::mktime(&t);
    return Timestamp{std::int64_t(v), 0};
}

Timestamp file_time(std::uint64_t ft)
{
    constexpr std::uint64_t kEpoch = 116444736000000000ull; // 1601 -> 1970 in 100 ns
    const std::int64_t rel = std::int64_t(ft) - std::int64_t(kEpoch);
    std::int64_t s = rel / 10000000;
    std::int64_t r = rel % 10000000;
    if (r < 0) { r += 10000000; --s; }
    return Timestamp{s, std::uint32_t(r * 100)};
}

static void put_utf8(std::string &s, std::uint32_t c)
{
    if (c < 0x80) s += char(c);
    else if (c < 0x800) { s += char(0xc0 | c >> 6); s += char(0x80 | (c & 63)); }
    else if (c < 0x10000) { s += char(0xe0 | c >> 12); s += char(0x80 | ((c >> 6) & 63)); s += char(0x80 | (c & 63)); }
    else { s += char(0xf0 | c >> 18); s += char(0x80 | ((c >> 12) & 63)); s += char(0x80 | ((c >> 6) & 63)); s += char(0x80 | (c & 63)); }
}

std::string utf16_to_utf8(const std::vector<std::uint16_t> &w)
{
    std::string s;
    for (std::size_t i = 0; i < w.size(); ++i) {
        std::uint32_t c = w[i];
        if (c >= 0xd800 && c < 0xdc00 && i + 1 < w.size() && w[i + 1] >= 0xdc00 && w[i + 1] < 0xe000)
            c = 0x10000 + ((c - 0xd800) << 10) + (w[++i] - 0xdc00);
        else if (c >= 0xd800 && c < 0xe000) c = 0xfffd;
        put_utf8(s, c);
    }
    return s;
}

static bool valid_utf8(std::string_view s)
{
    for (std::size_t i = 0; i < s.size();) {
        const auto c = std::uint8_t(s[i]);
        int n = c < 0x80 ? 0 : (c >> 5) == 6 ? 1 : (c >> 4) == 14 ? 2 : (c >> 3) == 30 ? 3 : -1;
        if (n < 0) return false;
        for (int k = 1; k <= n; ++k)
            if (i + std::size_t(k) >= s.size() || (std::uint8_t(s[i + std::size_t(k)]) >> 6) != 2) return false;
        i += std::size_t(n) + 1;
    }
    return true;
}

std::string legacy_name(std::string_view s)
{
    if (valid_utf8(s)) return std::string(s);
    static const std::uint16_t cp437[128] = {
        0xc7, 0xfc, 0xe9, 0xe2, 0xe4, 0xe0, 0xe5, 0xe7, 0xea, 0xeb, 0xe8, 0xef, 0xee, 0xec, 0xc4, 0xc5,
        0xc9, 0xe6, 0xc6, 0xf4, 0xf6, 0xf2, 0xfb, 0xf9, 0xff, 0xd6, 0xdc, 0xa2, 0xa3, 0xa5, 0x20a7, 0x192,
        0xe1, 0xed, 0xf3, 0xfa, 0xf1, 0xd1, 0xaa, 0xba, 0xbf, 0x2310, 0xac, 0xbd, 0xbc, 0xa1, 0xab, 0xbb,
        0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510,
        0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f, 0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567,
        0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,
        0x3b1, 0xdf, 0x393, 0x3c0, 0x3a3, 0x3c3, 0xb5, 0x3c4, 0x3a6, 0x398, 0x3a9, 0x3b4, 0x221e, 0x3c6, 0x3b5, 0x2229,
        0x2261, 0xb1, 0x2265, 0x2264, 0x2320, 0x2321, 0xf7, 0x2248, 0xb0, 0x2219, 0xb7, 0x221a, 0x207f, 0xb2, 0x25a0, 0xa0};
    std::string out;
    for (char ch : s) {
        const auto c = std::uint8_t(ch);
        put_utf8(out, c < 0x80 ? c : cp437[c - 0x80]);
    }
    return out;
}

} // namespace raye::archive::detail::rar
