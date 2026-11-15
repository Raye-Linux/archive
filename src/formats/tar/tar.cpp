// SPDX-License-Identifier: GPL-3.0-or-later
#include "tar.h"

#include <raye/archive/error.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <cstring>

namespace raye::archive::detail {

namespace {

constexpr std::uint64_t kMaxText = 16u << 20; // pax header or GNU long name

[[noreturn]] void bad_header(const std::string &why = "a tar header is damaged")
{
    fail(ErrorCode::Corrupt, why);
}

std::string field(const std::uint8_t *h, std::size_t off, std::size_t len)
{
    const auto *p = reinterpret_cast<const char *>(h + off);
    return std::string(p, strnlen(p, len));
}

// Octal (with spaces/NULs around it) or GNU base-256.
std::uint64_t number(const std::uint8_t *h, std::size_t off, std::size_t len, bool *negative = nullptr)
{
    const std::uint8_t *p = h + off;
    if (p[0] & 0x80) {
        if (p[0] == 0xff) { // negative (times before 1970)
            if (negative) *negative = true;
            std::uint64_t v = 0;
            for (std::size_t i = 1; i < len; ++i) v = (v << 8) | std::uint8_t(~p[i]);
            return v + 1;
        }
        std::uint64_t v = p[0] & 0x3f;
        for (std::size_t i = 1; i < len; ++i) {
            if (v >> 56) bad_header("a number in a tar header is too big");
            v = (v << 8) | p[i];
        }
        return v;
    }
    std::size_t i = 0;
    while (i < len && (p[i] == ' ' || p[i] == 0)) ++i;
    std::uint64_t v = 0;
    for (; i < len && p[i] >= '0' && p[i] <= '7'; ++i) {
        if (v >> 61) bad_header("a number in a tar header is too big");
        v = v * 8 + unsigned(p[i] - '0');
    }
    for (; i < len; ++i)
        if (p[i] != ' ' && p[i] != 0) bad_header("a number in a tar header is not a number");
    return v;
}

bool all_zero(const std::uint8_t *b) { return std::all_of(b, b + 512, [](std::uint8_t c) { return c == 0; }); }

std::uint64_t to_u64(std::string_view s)
{
    std::uint64_t v = 0;
    auto r = std::from_chars(s.data(), s.data() + s.size(), v);
    if (r.ec != std::errc() || r.ptr != s.data() + s.size()) bad_header("a pax value is not a number");
    return v;
}

// "1700000000.25" or "-12.5" -> Timestamp
Timestamp to_time(std::string_view s)
{
    bool neg = !s.empty() && s[0] == '-';
    if (neg) s.remove_prefix(1);
    const auto dot = s.find('.');
    std::int64_t sec = std::int64_t(to_u64(s.substr(0, dot)));
    std::uint32_t ns = 0;
    if (dot != std::string_view::npos) {
        std::string frac(s.substr(dot + 1, 9));
        for (char c : frac)
            if (c < '0' || c > '9') bad_header("a pax time is not a number");
        frac.resize(9, '0');
        ns = std::uint32_t(std::stoul(frac));
    }
    if (neg) {
        sec = -sec;
        if (ns) { sec -= 1; ns = 1000000000u - ns; }
    }
    return {sec, ns};
}

std::vector<std::pair<std::string, std::string>> pax_records(const std::string &text)
{
    std::vector<std::pair<std::string, std::string>> out;
    std::size_t pos = 0;
    while (pos < text.size()) {
        if (text[pos] == 0) break; // some writers pad with NULs
        std::size_t sp = text.find(' ', pos);
        if (sp == std::string::npos || sp - pos > 20) bad_header("a pax header is damaged");
        const std::uint64_t len = to_u64(std::string_view(text).substr(pos, sp - pos));
        if (len < sp - pos + 3 || pos + len > text.size() || text[pos + len - 1] != '\n') bad_header("a pax header is damaged");
        std::string_view rec(text.data() + sp + 1, pos + len - 1 - (sp + 1));
        const auto eq = rec.find('=');
        if (eq == std::string_view::npos) bad_header("a pax header is damaged");
        out.emplace_back(std::string(rec.substr(0, eq)), std::string(rec.substr(eq + 1)));
        pos += len;
    }
    return out;
}

void check_segments(TarItem &it, std::uint64_t stored)
{
    std::uint64_t at = 0, sum = 0;
    for (auto &[off, len] : it.segments) {
        if (off < at || len > it.entry.size || off > it.entry.size - len) bad_header("a sparse file map is damaged");
        at = off + len;
        sum += len;
    }
    if (sum != stored) bad_header("a sparse file map does not match its data");
}

} // namespace

bool tar_header_ok(const std::uint8_t *h)
{
    unsigned stored = 0;
    bool digit = false;
    for (int i = 148; i < 156; ++i) {
        const auto c = h[i];
        if (c >= '0' && c <= '7') { stored = stored * 8 + unsigned(c - '0'); digit = true; }
        else if (c != ' ' && c != 0) return false;
    }
    if (!digit) return false;
    unsigned sum = 0;
    int ssum = 0; // some old tars summed signed chars
    for (int i = 0; i < 512; ++i) {
        const std::uint8_t c = (i >= 148 && i < 156) ? ' ' : h[i];
        sum += c;
        ssum += static_cast<signed char>(c);
    }
    return sum == stored || unsigned(ssum) == stored;
}

bool TarParser::block(std::uint8_t *b)
{
    std::size_t got = 0;
    while (got < 512) {
        const std::size_t r = in_.read(b + got, 512 - got);
        if (!r) break;
        got += r;
    }
    if (got == 0) return false;
    if (got < 512) fail(ErrorCode::Truncated, "tar archive ends in the middle of a header");
    return true;
}

std::string TarParser::read_text(std::uint64_t size)
{
    if (size > kMaxText) bad_header("a tar extended header is too big");
    std::string s(std::size_t(size), '\0');
    in_.read_exact(s.data(), s.size());
    const std::uint64_t pad = (512 - size % 512) % 512;
    if (in_.skip(pad) != pad) fail(ErrorCode::Truncated, "tar archive ends early");
    return s;
}

void TarParser::skip_rest()
{
    const std::uint64_t n = left_ + pad_;
    // The last entry's padding may be missing in sloppy archives: data counts, padding not.
    const std::uint64_t got = in_.skip(n);
    if (got < left_) fail(ErrorCode::Truncated, "tar archive ends in the middle of an entry");
    left_ = pad_ = 0;
}

std::size_t TarParser::read_data(void *buf, std::size_t n)
{
    n = std::size_t(std::min<std::uint64_t>(n, left_));
    if (!n) return 0;
    in_.read_exact(buf, n);
    left_ -= n;
    return n;
}

bool TarParser::next(TarItem &it)
{
    skip_rest();
    it = TarItem{};
    std::uint8_t h[512];
    std::vector<std::pair<std::string, std::string>> pax = global_;
    std::string long_name, long_link;
    bool have_long_name = false, have_long_link = false;
    for (;;) {
        if (!block(h)) return false;
        if (all_zero(h)) {
            // End: two zero blocks (or one, then nothing). A lone zero block
            // between headers happens with concatenated archives: go on.
            if (!block(h) || all_zero(h)) return false;
        }
        if (!tar_header_ok(h)) bad_header();
        const char type = char(h[156]);
        const std::uint64_t size = number(h, 124, 12);
        if (type == 'x' || type == 'X' || type == 'g') {
            auto recs = pax_records(read_text(size));
            if (type == 'g') {
                for (auto &r : recs) {
                    auto old = std::find_if(global_.begin(), global_.end(), [&](auto &g) { return g.first == r.first; });
                    if (old != global_.end()) old->second = r.second;
                    else global_.push_back(r);
                }
                pax = global_;
            } else {
                pax.insert(pax.end(), recs.begin(), recs.end());
            }
            continue;
        }
        if (type == 'L' || type == 'K') {
            std::string s = read_text(size);
            s.resize(strnlen(s.data(), s.size()));
            (type == 'L' ? long_name : long_link) = std::move(s);
            (type == 'L' ? have_long_name : have_long_link) = true;
            continue;
        }
        if (type == 'V' || type == 'A' || type == 'E') { // volume label, Solaris ACL and xattr records
            left_ = 0;
            if (in_.skip((size + 511) / 512 * 512) < size) fail(ErrorCode::Truncated, "tar archive ends early");
            continue;
        }
        break;
    }
    ++count_;
    const char type = char(h[156]);
    const bool gnu = std::memcmp(h + 257, "ustar  \0", 8) == 0;
    const bool ustar = std::memcmp(h + 257, "ustar", 5) == 0 && !gnu;
    Entry &e = it.entry;
    std::string name = field(h, 0, 100);
    if (ustar) {
        const bool star = std::memcmp(h + 508, "tar\0", 4) == 0;
        std::string prefix = field(h, 345, star ? 131 : 155);
        if (!prefix.empty()) name = prefix + "/" + name;
    }
    if (have_long_name) name = long_name;
    e.path = name;
    e.link_target = have_long_link ? long_link : field(h, 157, 100);
    e.mode = std::uint32_t(number(h, 100, 8) & 07777);
    it.uid = number(h, 108, 8);
    it.gid = number(h, 116, 8);
    std::uint64_t size = number(h, 124, 12);
    bool neg = false;
    std::uint64_t mt = number(h, 136, 12, &neg);
    e.mtime = Timestamp{neg ? -std::int64_t(mt) : std::int64_t(mt), 0};
    if (ustar || gnu) {
        it.uname = field(h, 265, 32);
        it.gname = field(h, 297, 32);
    }
    if (gnu) {
        if (h[345] || h[346]) e.atime = Timestamp{std::int64_t(number(h, 345, 12)), 0};
        if (h[357] || h[358]) e.ctime = Timestamp{std::int64_t(number(h, 357, 12)), 0};
    }
    switch (type) {
    case '1': e.type = EntryType::Hardlink; break;
    case '2': e.type = EntryType::Symlink; break;
    case '3': case '4': case '6': e.type = EntryType::Other; break;
    case '5': case 'D': e.type = EntryType::Directory; break;
    default: e.type = EntryType::File; break; // 0, NUL, 7, S and unknown types are plain files
    }
    if (e.type == EntryType::File && type != 'S' && !name.empty() && name.back() == '/') e.type = EntryType::Directory;

    // Old GNU sparse: map in the header and in extension blocks.
    std::uint64_t realsize = 0;
    bool sparse_old = type == 'S';
    if (sparse_old) {
        auto add = [&](const std::uint8_t *b, std::size_t off, int count) {
            for (int i = 0; i < count; ++i) {
                const std::uint64_t o = number(b, off + std::size_t(i) * 24, 12), n = number(b, off + std::size_t(i) * 24 + 12, 12);
                if (o == 0 && n == 0) continue;
                it.segments.emplace_back(o, n);
            }
        };
        add(h, 386, 4);
        realsize = number(h, 483, 12);
        bool ext = h[482] != 0;
        std::uint8_t x[512];
        std::size_t guard = 0;
        while (ext) {
            if (++guard > (1u << 16) || !block(x)) fail(ErrorCode::Truncated, "tar archive ends in a sparse map");
            add(x, 0, 21);
            ext = x[504] != 0;
        }
    }

    // pax overrides, in order.
    std::string sparse_name;
    int sparse_major = -1, sparse_minor = -1;
    bool pax_sparse_old = false;
    std::uint64_t pending_offset = UINT64_MAX;
    for (auto &[k, v] : pax) {
        if (k == "path") e.path = v;
        else if (k == "linkpath") e.link_target = v;
        else if (k == "size") size = to_u64(v);
        else if (k == "mtime") e.mtime = to_time(v);
        else if (k == "atime") e.atime = to_time(v);
        else if (k == "ctime") e.ctime = to_time(v);
        else if (k == "uid") it.uid = to_u64(v);
        else if (k == "gid") it.gid = to_u64(v);
        else if (k == "uname") it.uname = v;
        else if (k == "gname") it.gname = v;
        else if (k == "comment") e.comment = v;
        else if (k == "GNU.sparse.name") sparse_name = v;
        else if (k == "GNU.sparse.realsize" || k == "GNU.sparse.size") realsize = to_u64(v);
        else if (k == "GNU.sparse.major") sparse_major = int(to_u64(v));
        else if (k == "GNU.sparse.minor") sparse_minor = int(to_u64(v));
        else if (k == "GNU.sparse.offset") { pending_offset = to_u64(v); pax_sparse_old = true; }
        else if (k == "GNU.sparse.numbytes") {
            if (pending_offset == UINT64_MAX) bad_header("a sparse file map is damaged");
            it.segments.emplace_back(pending_offset, to_u64(v));
            pending_offset = UINT64_MAX;
        } else if (k == "GNU.sparse.map") {
            pax_sparse_old = true;
            std::vector<std::uint64_t> nums;
            std::size_t p = 0;
            while (p <= v.size() && !v.empty()) {
                const std::size_t c = std::min(v.find(',', p), v.size());
                nums.push_back(to_u64(std::string_view(v).substr(p, c - p)));
                if (nums.size() > (1u << 22)) bad_header("a sparse file map is too big");
                p = c + 1;
            }
            if (nums.size() % 2) bad_header("a sparse file map is damaged");
            for (std::size_t i = 0; i < nums.size(); i += 2) it.segments.emplace_back(nums[i], nums[i + 1]);
        } else if (k.rfind("SCHILY.xattr.", 0) == 0) it.xattrs.emplace_back(k.substr(13), v);
        else if (k.rfind("LIBARCHIVE.xattr.", 0) == 0) it.xattrs.emplace_back(k.substr(17), v);
    }
    if (!sparse_name.empty()) e.path = sparse_name;

    left_ = size;
    pad_ = (512 - size % 512) % 512;
    it.data_pos = in_.pos();
    it.stored = size;
    if (e.type == EntryType::Directory || e.type == EntryType::Symlink || e.type == EntryType::Hardlink ||
        e.type == EntryType::Other) {
        e.size = 0;
        return true;
    }
    if (sparse_major == 1) {
        // pax 1.0: the map is a list of decimal numbers at the start of the data.
        std::string text;
        std::uint64_t want = 0;
        std::vector<std::uint64_t> nums;
        std::size_t used = 0;
        bool count_known = false;
        while (!count_known || nums.size() < 1 + 2 * want) {
            std::uint8_t b[512];
            if (read_data(b, 512) != 512) bad_header("a sparse file map is damaged");
            used += 512;
            text.append(reinterpret_cast<char *>(b), 512);
            std::size_t nl;
            while ((nl = text.find('\n')) != std::string::npos) {
                if (text[0] == '#') { text.erase(0, nl + 1); continue; } // "#!gnu-sparse-format" and friends
                nums.push_back(to_u64(std::string_view(text).substr(0, nl)));
                text.erase(0, nl + 1);
                if (!count_known) {
                    want = nums[0];
                    count_known = true;
                    if (want > (1u << 22)) bad_header("a sparse file map is too big");
                }
                if (nums.size() >= 1 + 2 * want) break;
            }
            if (used > kMaxText) bad_header("a sparse file map is too big");
        }
        for (std::uint64_t i = 0; i < want; ++i) it.segments.emplace_back(nums[1 + 2 * i], nums[2 + 2 * i]);
        it.data_pos += used;
        it.stored = size - used;
        it.sparse = true;
        (void)sparse_minor;
    } else if (sparse_old || pax_sparse_old) {
        it.sparse = true;
    }
    if (it.sparse) {
        e.size = realsize;
        check_segments(it, it.stored);
    } else {
        e.size = size;
    }
    return true;
}

// ------------------------------------------------------------------ writing

namespace {

void put_octal(std::uint8_t *h, std::size_t off, std::size_t len, std::uint64_t v)
{
    // len-1 digits and a NUL; base-256 when it does not fit (GNU, read everywhere).
    if (len - 1 < 22 && v >= (1ull << (3 * (len - 1)))) {
        std::memset(h + off, 0, len);
        h[off] = 0x80;
        for (std::size_t i = len - 1; i > 0 && v; --i, v >>= 8) h[off + i] = std::uint8_t(v);
        return;
    }
    for (std::size_t i = len - 1; i-- > 0;) { h[off + i] = std::uint8_t('0' + (v & 7)); v >>= 3; }
    h[off + len - 1] = 0;
}

void put_str(std::uint8_t *h, std::size_t off, std::size_t len, const std::string &s)
{
    std::memcpy(h + off, s.data(), std::min(len, s.size()));
}

void add_record(std::string &out, const std::string &key, const std::string &value)
{
    const std::size_t body = key.size() + value.size() + 3; // ' ' '=' '\n'
    std::size_t len = body + 1;
    while (std::to_string(len).size() + body != len) len = std::to_string(len).size() + body;
    out += std::to_string(len) + " " + key + "=" + value + "\n";
}

std::string time_text(const Timestamp &t)
{
    std::uint64_t whole;
    std::uint32_t frac;
    std::string r;
    if (t.seconds >= 0) { whole = std::uint64_t(t.seconds); frac = t.nanoseconds; }
    else if (t.nanoseconds) { whole = std::uint64_t(-(t.seconds + 1)); frac = 1000000000u - t.nanoseconds; r = "-"; }
    else { whole = std::uint64_t(-t.seconds); frac = 0; r = "-"; }
    r += std::to_string(whole);
    if (frac) {
        std::string f = std::to_string(frac);
        f.insert(0, 9 - f.size(), '0');
        while (f.back() == '0') f.pop_back();
        r += "." + f;
    }
    return r;
}

void checksum(std::uint8_t *h)
{
    std::memset(h + 148, ' ', 8);
    unsigned sum = 0;
    for (int i = 0; i < 512; ++i) sum += h[i];
    std::snprintf(reinterpret_cast<char *>(h + 148), 8, "%06o", sum);
    h[155] = ' ';
}

// ustar splits a long name at a '/' into prefix (155) and name (100).
bool split_name(const std::string &p, std::string &prefix, std::string &name)
{
    if (p.size() <= 100) { prefix.clear(); name = p; return true; }
    if (p.size() > 256) return false;
    for (std::size_t i = std::min<std::size_t>(p.size() - 1, 155); i > 0; --i) {
        if (p[i] != '/') continue;
        if (p.size() - i - 1 > 100 || p.size() - i - 1 == 0) return false;
        prefix = p.substr(0, i);
        name = p.substr(i + 1);
        return true;
    }
    return false;
}

std::array<std::uint8_t, 512> ustar_block(const std::string &name, const std::string &prefix, char type,
                                           const TarHeaderIn &h, std::uint64_t size, const std::string &link)
{
    std::array<std::uint8_t, 512> b{};
    put_str(b.data(), 0, 100, name);
    put_octal(b.data(), 100, 8, h.mode & 07777);
    put_octal(b.data(), 108, 8, h.uid < 07777777 ? h.uid : 0);
    put_octal(b.data(), 116, 8, h.gid < 07777777 ? h.gid : 0);
    put_octal(b.data(), 124, 12, size);
    put_octal(b.data(), 136, 12, h.mtime.seconds < 0 ? 0 : std::uint64_t(h.mtime.seconds));
    b[156] = std::uint8_t(type);
    put_str(b.data(), 157, 100, link);
    std::memcpy(b.data() + 257, "ustar\0" "00", 8);
    put_str(b.data(), 265, 32, h.uname);
    put_str(b.data(), 297, 32, h.gname);
    put_octal(b.data(), 329, 8, 0);
    put_octal(b.data(), 337, 8, 0);
    put_str(b.data(), 345, 155, prefix);
    checksum(b.data());
    return b;
}

} // namespace

std::vector<std::uint8_t> tar_header(const TarHeaderIn &h)
{
    char type = '0';
    switch (h.type) {
    case EntryType::Directory: type = '5'; break;
    case EntryType::Symlink: type = '2'; break;
    case EntryType::Hardlink: type = '1'; break;
    default: break;
    }
    const std::uint64_t size = h.type == EntryType::File ? h.size : 0;
    std::string pax, prefix, name;
    if (!split_name(h.path, prefix, name)) {
        add_record(pax, "path", h.path);
        name = h.path.substr(0, 100);
        prefix.clear();
    }
    std::string link = h.link;
    if (link.size() > 100) { add_record(pax, "linkpath", link); link.resize(100); }
    if (size >= (1ull << 33)) add_record(pax, "size", std::to_string(size));
    if (h.mtime.nanoseconds || h.mtime.seconds < 0 || h.mtime.seconds >= (1ll << 33)) add_record(pax, "mtime", time_text(h.mtime));
    if (h.atime) add_record(pax, "atime", time_text(*h.atime));
    if (h.ctime) add_record(pax, "ctime", time_text(*h.ctime));
    if (h.uid >= 07777777) add_record(pax, "uid", std::to_string(h.uid));
    if (h.gid >= 07777777) add_record(pax, "gid", std::to_string(h.gid));
    if (h.uname.size() > 32) add_record(pax, "uname", h.uname);
    if (h.gname.size() > 32) add_record(pax, "gname", h.gname);

    std::vector<std::uint8_t> out;
    if (!pax.empty()) {
        std::string base = h.path;
        while (base.size() > 1 && base.back() == '/') base.pop_back();
        base = base.substr(base.rfind('/') == std::string::npos ? 0 : base.rfind('/') + 1);
        TarHeaderIn ph = h;
        ph.mode = 0644;
        auto b = ustar_block(("PaxHeaders/" + base).substr(0, 100), {}, 'x', ph, pax.size(), {});
        out.insert(out.end(), b.begin(), b.end());
        out.insert(out.end(), pax.begin(), pax.end());
        out.resize((out.size() + 511) / 512 * 512, 0);
    }
    auto b = ustar_block(name, prefix, type, h, size, link);
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

} // namespace raye::archive::detail
