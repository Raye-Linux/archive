// SPDX-License-Identifier: GPL-3.0-or-later
// ISO 9660 with Rock Ridge (POSIX names, modes, links, deep folders moved
// by RR_MOVED) and Joliet (UCS-2 names). Rock Ridge wins when present.
#include "items.h"
#include "readers.h"

#include "../../core/bytes.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>

namespace raye::archive::detail {

namespace {

constexpr std::uint64_t kSector = 2048;

[[noreturn]] void damaged(const char *what = "an ISO directory is damaged") { fail(ErrorCode::Corrupt, what); }

std::string ucs2be_to_utf8(const std::uint8_t *p, std::size_t n)
{
    std::string r;
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        std::uint32_t c = std::uint32_t(p[i]) << 8 | p[i + 1];
        if (c >= 0xd800 && c < 0xdc00 && i + 3 < n) { // UTF-16 pair
            const std::uint32_t lo = std::uint32_t(p[i + 2]) << 8 | p[i + 3];
            if (lo >= 0xdc00 && lo < 0xe000) { c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00); i += 2; }
        }
        if (c < 0x80) r.push_back(char(c));
        else if (c < 0x800) { r.push_back(char(0xc0 | c >> 6)); r.push_back(char(0x80 | (c & 0x3f))); }
        else if (c < 0x10000) { r.push_back(char(0xe0 | c >> 12)); r.push_back(char(0x80 | (c >> 6 & 0x3f))); r.push_back(char(0x80 | (c & 0x3f))); }
        else { r.push_back(char(0xf0 | c >> 18)); r.push_back(char(0x80 | (c >> 12 & 0x3f))); r.push_back(char(0x80 | (c >> 6 & 0x3f))); r.push_back(char(0x80 | (c & 0x3f))); }
    }
    return r;
}

std::optional<Timestamp> dir_time(const std::uint8_t *t)
{
    if (!t[0] && !t[1] && !t[2]) return std::nullopt;
    struct tm tm{};
    tm.tm_year = t[0];
    tm.tm_mon = t[1] - 1;
    tm.tm_mday = t[2];
    tm.tm_hour = t[3];
    tm.tm_min = t[4];
    tm.tm_sec = t[5];
    const std::int64_t gmt = std::int8_t(t[6]) * 15 * 60;
    return Timestamp{std::int64_t(timegm(&tm)) - gmt, 0};
}

std::optional<Timestamp> long_time(const std::uint8_t *t) // 17-byte form used by TF with LONG_FORM
{
    auto num = [&](int a, int n) { int v = 0; for (int i = 0; i < n; ++i) v = v * 10 + (t[a + i] - '0'); return v; };
    struct tm tm{};
    tm.tm_year = num(0, 4) - 1900;
    if (tm.tm_year < 0) return std::nullopt;
    tm.tm_mon = num(4, 2) - 1;
    tm.tm_mday = num(6, 2);
    tm.tm_hour = num(8, 2);
    tm.tm_min = num(10, 2);
    tm.tm_sec = num(12, 2);
    return Timestamp{std::int64_t(timegm(&tm)) - std::int8_t(t[16]) * 15 * 60, 0};
}

struct Rec {
    std::uint32_t extent = 0, length = 0;
    std::uint8_t flags = 0;
    std::string name;   // ISO or Joliet name
    std::string rr_name;
    bool has_rr_name = false;
    std::optional<std::uint32_t> mode;
    std::optional<std::uint32_t> filetype; // S_IFMT bits from PX
    std::optional<Timestamp> mtime, atime, ctime;
    std::string symlink;
    bool is_link = false;
    std::optional<std::uint32_t> child_link; // CL: a moved directory lives there
    bool relocated = false;                   // RE: skip, reached through its CL
    bool zisofs = false;
};

class IsoReader final : public ItemReader {
public:
    IsoReader(std::shared_ptr<Source> src, std::uint64_t start) : ItemReader(std::move(src)), start_(start)
    {
        const std::uint64_t size = src_->size();
        std::uint8_t pvd[2048] = {}, joliet[2048] = {};
        bool have_pvd = false, have_joliet = false;
        for (std::uint64_t s = 16; s < 64; ++s) {
            std::uint8_t d[2048];
            if (start_ + (s + 1) * kSector > size) break;
            src_->read_exact(start_ + s * kSector, d, 2048);
            if (std::memcmp(d + 1, "CD001", 5) != 0) break;
            if (d[0] == 1 && !have_pvd) { std::memcpy(pvd, d, 2048); have_pvd = true; }
            else if (d[0] == 2 && d[88] == '%' && d[89] == '/' && (d[90] == '@' || d[90] == 'C' || d[90] == 'E')) {
                std::memcpy(joliet, d, 2048);
                have_joliet = true;
            } else if (d[0] == 255) break;
        }
        if (!have_pvd) damaged("ISO image has no primary volume descriptor");
        block_ = le16(pvd + 128);
        if (block_ != 2048 && block_ != 512 && block_ != 1024) block_ = 2048;
        Rec root = parse_rec(pvd + 156, 34, false);
        // Rock Ridge shows itself with an SP entry in the root's "." record.
        rr_ = detect_rr(root);
        if (!rr_ && have_joliet) {
            joliet_ = true;
            root = parse_rec(joliet + 156, 34, true);
        }
        info_.detail = rr_ ? "ISO 9660, Rock Ridge" : joliet_ ? "ISO 9660, Joliet" : "ISO 9660";
        std::string label(reinterpret_cast<char *>(pvd + 40), 32);
        while (!label.empty() && label.back() == ' ') label.pop_back();
        info_.comment = label;
        walk(root.extent, root.length, "", 0);
    }

private:
    std::uint64_t at(std::uint64_t lba) const { return start_ + lba * block_; }

    Rec parse_rec(const std::uint8_t *r, std::size_t len, bool joliet)
    {
        Rec x;
        if (len < 34) damaged();
        x.extent = le32(r + 2);
        x.length = le32(r + 10);
        x.mtime = dir_time(r + 18);
        x.flags = r[25];
        const std::size_t nl = r[32];
        if (33 + nl > len) damaged();
        if (nl == 1 && (r[33] == 0 || r[33] == 1)) x.name = r[33] == 0 ? "." : "..";
        else if (joliet) x.name = ucs2be_to_utf8(r + 33, nl);
        else x.name.assign(reinterpret_cast<const char *>(r + 33), nl);
        if (!joliet && x.name != "." && x.name != "..") {
            const auto semi = x.name.find(';');
            if (semi != std::string::npos) x.name.resize(semi);
            if (!x.name.empty() && x.name.back() == '.') x.name.pop_back();
        } else if (joliet) {
            const auto semi = x.name.find(';');
            if (semi != std::string::npos) x.name.resize(semi);
        }
        std::size_t su = 33 + nl + ((nl & 1) ? 0 : 1);
        if (rr_ && su < len) parse_susp(x, r + su + rr_skip_, len - std::min(len, su + rr_skip_), 0);
        return x;
    }

    bool detect_rr(const Rec &root)
    {
        if (root.length < 34) return false;
        std::uint8_t d[2048];
        src_->read_exact(at(root.extent), d, 2048);
        const std::size_t len = d[0];
        if (len < 34) return false;
        const std::size_t nl = d[32];
        const std::size_t su = 33 + nl + ((nl & 1) ? 0 : 1);
        if (su + 7 > len || d[su] != 'S' || d[su + 1] != 'P' || d[su + 4] != 0xbe || d[su + 5] != 0xef) return false;
        rr_skip_ = d[su + 6];
        return true;
    }

    void parse_susp(Rec &x, const std::uint8_t *p, std::size_t n, int depth)
    {
        std::string nm, sl;
        bool sl_continue = false;
        while (n >= 4) {
            const std::size_t len = p[2];
            if (len < 4 || len > n) break;
            const char a = char(p[0]), b = char(p[1]);
            const std::uint8_t *d = p + 4;
            const std::size_t dl = len - 4;
            if (a == 'N' && b == 'M' && dl >= 1) {
                const std::uint8_t fl = d[0];
                if (fl & 2) nm = ".";
                else if (fl & 4) nm = "..";
                else nm.append(reinterpret_cast<const char *>(d + 1), dl - 1);
                x.has_rr_name = true;
            } else if (a == 'P' && b == 'X' && dl >= 8) {
                const std::uint32_t m = le32(d);
                x.mode = m & 07777;
                x.filetype = m & 0170000;
            } else if (a == 'S' && b == 'L' && dl >= 1) {
                x.is_link = true;
                // Components joined by '/'; flag 1 glues the next one on, 8 is the root.
                std::string sep = sl_continue || sl.empty() ? "" : "/";
                std::size_t i = 1;
                while (i + 2 <= dl) {
                    const std::uint8_t cf = d[i], cl = d[i + 1];
                    if (i + 2 + cl > dl) break;
                    sl += sep;
                    sep = "/";
                    switch (cf) {
                    case 0: sl.append(reinterpret_cast<const char *>(d + i + 2), cl); break;
                    case 1: sl.append(reinterpret_cast<const char *>(d + i + 2), cl); sep = ""; break;
                    case 2: sl += "."; break;
                    case 4: sl += ".."; break;
                    case 8: sl += "/"; sep = ""; break;
                    default: break;
                    }
                    i += 2 + cl;
                }
                sl_continue = d[0] & 1;
            } else if (a == 'T' && b == 'F' && dl >= 1) {
                const std::uint8_t fl = d[0];
                const std::size_t w = (fl & 0x80) ? 17 : 7;
                std::size_t off = 1;
                auto take = [&](std::optional<Timestamp> *dst) {
                    if (off + w > dl) return;
                    auto t = w == 17 ? long_time(d + off) : dir_time(d + off);
                    if (dst) *dst = t;
                    off += w;
                };
                if (fl & 1) take(nullptr); // creation
                if (fl & 2) take(&x.mtime);
                if (fl & 4) take(&x.atime);
                if (fl & 8) take(&x.ctime);
            } else if (a == 'C' && b == 'L' && dl >= 8) {
                x.child_link = le32(d);
            } else if (a == 'R' && b == 'E') {
                x.relocated = true;
            } else if (a == 'Z' && b == 'F') {
                x.zisofs = true;
            } else if (a == 'C' && b == 'E' && dl >= 24 && depth < 8) {
                const std::uint32_t lba = le32(d), off = le32(d + 8), cl = le32(d + 16);
                if (cl <= 65536 && at(lba) + off + cl <= src_->size()) {
                    std::vector<std::uint8_t> more(cl);
                    src_->read_exact(at(lba) + off, more.data(), cl);
                    Rec tmp;
                    parse_susp(tmp, more.data(), more.size(), depth + 1);
                    if (tmp.has_rr_name) { nm += tmp.rr_name; x.has_rr_name = true; }
                    if (tmp.mode) { x.mode = tmp.mode; x.filetype = tmp.filetype; }
                    if (tmp.is_link) { x.is_link = true; sl += tmp.symlink; }
                    if (tmp.mtime) x.mtime = tmp.mtime;
                    if (tmp.child_link) x.child_link = tmp.child_link;
                    x.relocated |= tmp.relocated;
                    x.zisofs |= tmp.zisofs;
                }
            } else if (a == 'S' && b == 'T') {
                break;
            }
            p += len;
            n -= len;
        }
        if (x.has_rr_name) x.rr_name += nm;
        if (x.is_link) x.symlink += sl;
    }

    void walk(std::uint32_t lba, std::uint32_t length, const std::string &prefix, int depth)
    {
        if (depth > 64) damaged("ISO folders are nested too deep");
        if (!visited_.insert(lba).second) return; // a loop
        if (length > (64u << 20)) damaged();
        if (at(lba) + length > src_->size()) fail(ErrorCode::Truncated, "ISO image ends early");
        std::vector<std::uint8_t> dir(length);
        src_->read_exact(at(lba), dir.data(), dir.size());
        std::size_t pos = 0;
        Item *multi = nullptr; // file split over several extents
        while (pos < dir.size()) {
            const std::size_t len = dir[pos];
            if (len == 0) { // records never cross a sector: go to the next one
                pos = (pos / kSector + 1) * kSector;
                continue;
            }
            if (pos + len > dir.size()) damaged();
            Rec r = parse_rec(&dir[pos], len, joliet_);
            pos += len;
            if (r.name == "." || r.name == ".." || r.relocated) continue;
            if (items_.size() > 10'000'000) damaged("ISO image has too many entries");
            const std::string name = (rr_ && r.has_rr_name) ? r.rr_name : r.name;
            if (name.empty()) continue;
            const std::string path = prefix.empty() ? name : prefix + "/" + name;
            if (multi && multi->entry.path == path) {
                multi->pieces.emplace_back(at(r.extent), r.length);
                multi->entry.size += r.length;
                multi->entry.packed_size = multi->entry.size;
                if (!(r.flags & 0x80)) multi = nullptr;
                continue;
            }
            multi = nullptr;
            Item it;
            Entry &e = it.entry;
            e.path = path;
            e.mtime = r.mtime;
            e.atime = r.atime;
            e.ctime = r.ctime;
            e.mode = r.mode;
            e.method = "Store";
            const bool dir_rec = (r.flags & 2) || r.child_link;
            if (r.is_link) {
                e.type = EntryType::Symlink;
                e.link_target = r.symlink;
            } else if (dir_rec) {
                e.type = EntryType::Directory;
            } else if (r.filetype && *r.filetype != 0100000 && *r.filetype != 0) {
                e.type = EntryType::Other;
            } else {
                e.type = EntryType::File;
                e.size = e.packed_size = r.length;
                it.pieces.emplace_back(at(r.extent), r.length);
                if (r.zisofs && r.length >= 16) {
                    std::uint8_t zh[16];
                    src_->read_exact(at(r.extent), zh, 16);
                    if (std::memcmp(zh, "\x37\xe4\x53\x96\xc9\xdb\xd6\x07", 8) == 0) {
                        e.method = "zisofs";
                        e.size = le32(zh + 8);
                        it.zisofs = true;
                    }
                }
            }
            items_.push_back(std::move(it));
            if (e.type == EntryType::File && (r.flags & 0x80)) multi = &items_.back();
            if (dir_rec && !r.is_link) {
                if (r.child_link) {
                    std::uint8_t d[2048];
                    src_->read_exact(at(*r.child_link), d, 2048);
                    const Rec self = parse_rec(d, d[0], joliet_);
                    walk(self.extent, self.length, path, depth + 1);
                } else {
                    walk(r.extent, r.length, path, depth + 1);
                }
                multi = nullptr;
            }
        }
    }

    std::uint64_t start_;
    std::uint64_t block_ = 2048;
    bool rr_ = false, joliet_ = false;
    std::size_t rr_skip_ = 0;
    std::set<std::uint32_t> visited_;
};

} // namespace

std::unique_ptr<ReaderImpl> open_iso(const OpenRequest &req)
{
    return std::make_unique<IsoReader>(req.source, req.detection.offset);
}

} // namespace raye::archive::detail
