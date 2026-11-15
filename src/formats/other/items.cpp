// SPDX-License-Identifier: GPL-3.0-or-later
#include "items.h"
#include "readers.h"

#include "../../core/bytes.h"

#include <algorithm>
#include <cstring>
#include <iconv.h>
#include <zlib.h>

namespace raye::archive::detail {

void for_each_entry(const std::vector<Entry> &all, const std::vector<std::size_t> &indexes, Context &ctx, bool ordered,
                    const std::function<void(std::size_t)> &one)
{
    std::vector<std::size_t> files, dirs, rest;
    std::set<std::string> seen;
    for (auto i : indexes) {
        if (i >= all.size()) fail(ErrorCode::NotFound, "no entry number " + std::to_string(i));
        if (!seen.insert(all[i].path).second) ordered = true;
        auto t = all[i].type;
        (t == EntryType::File ? files : t == EntryType::Directory ? dirs : rest).push_back(i);
    }
    if (ordered || ctx.threads() <= 1 || files.size() < 2) {
        // Links still go last: a hard link needs its file, a symlink made
        // early could steer a later file elsewhere.
        for (auto i : indexes)
            if (all[i].type == EntryType::Directory || all[i].type == EntryType::File) one(i);
        for (auto i : rest) one(i);
        return;
    }
    for (auto i : dirs) one(i);
    ctx.pool().parallel_for(files.size(), [&](std::size_t k) { one(files[k]); });
    for (auto i : rest) one(i);
}

void run_entry(const Entry &e, EntryHandler &h, Context &ctx, const std::function<void(Sink &)> &write)
{
    Sink *s = h.begin(e);
    if (!s || e.type != EntryType::File) { h.end(e, s); return; }
    ctx.file_started(e.path);
    try {
        write(*s);
    } catch (const Error &err) {
        h.failed(e, s, err);
        return;
    }
    h.end(e, s);
    ctx.file_done();
}

namespace {

// zisofs: 16-byte header, a table of block offsets, each block a zlib
// stream (or nothing for a block of zeros).
void unzisofs(const Source &src, const Item &it, Sink &s, Context &ctx)
{
    if (it.pieces.size() != 1) fail(ErrorCode::Corrupt, "zisofs file is damaged", it.entry.path);
    const auto [base, len] = it.pieces[0];
    std::uint8_t h[16];
    if (len < 16) fail(ErrorCode::Corrupt, "zisofs file is damaged", it.entry.path);
    src.read_exact(base, h, 16);
    const std::uint64_t size = le32(h + 8);
    const unsigned bshift = h[13];
    if (bshift < 15 || bshift > 17 || h[12] < 4) fail(ErrorCode::Corrupt, "zisofs file is damaged", it.entry.path);
    const std::uint64_t bsize = 1ull << bshift, nblocks = (size + bsize - 1) >> bshift;
    std::vector<std::uint8_t> table(std::size_t(nblocks + 1) * 4);
    if (std::uint64_t(h[12]) * 4 + table.size() > len) fail(ErrorCode::Corrupt, "zisofs file is damaged", it.entry.path);
    src.read_exact(base + std::uint64_t(h[12]) * 4, table.data(), table.size());
    std::vector<std::uint8_t> in, out(static_cast<std::size_t>(bsize));
    std::uint64_t done = 0;
    for (std::uint64_t b = 0; b < nblocks; ++b) {
        ctx.checkpoint();
        const std::uint32_t a = le32(&table[std::size_t(b) * 4]), z = le32(&table[std::size_t(b) * 4 + 4]);
        const std::size_t want = std::size_t(std::min<std::uint64_t>(bsize, size - done));
        if (z < a || z > len || z - a > bsize * 2) fail(ErrorCode::Corrupt, "zisofs file is damaged", it.entry.path);
        if (z == a) {
            std::fill(out.begin(), out.end(), 0);
        } else {
            in.resize(z - a);
            src.read_exact(base + a, in.data(), in.size());
            uLongf ol = uLongf(want);
            if (uncompress(out.data(), &ol, in.data(), uLong(in.size())) != Z_OK || ol != want)
                fail(ErrorCode::Corrupt, "zisofs block is damaged", it.entry.path);
        }
        s.write(out.data(), want);
        ctx.add_bytes(want);
        done += want;
    }
}

} // namespace

void ItemReader::extract(const std::vector<std::size_t> &indexes, EntryHandler &h, Context &ctx)
{
    std::vector<Entry> all;
    all.reserve(items_.size());
    for (auto &i : items_) all.push_back(i.entry);
    for_each_entry(all, indexes, ctx, false, [&](std::size_t i) {
        const Item &it = items_[i];
        run_entry(it.entry, h, ctx, [&](Sink &s) {
            if (it.zisofs) return unzisofs(*src_, it, s, ctx);
            std::vector<std::uint8_t> buf(1 << 20);
            std::uint64_t total = 0;
            for (auto [off, len] : it.pieces) {
                while (len) {
                    ctx.checkpoint();
                    const std::size_t k = std::size_t(std::min<std::uint64_t>(len, buf.size()));
                    src_->read_exact(off, buf.data(), k);
                    s.write(buf.data(), k);
                    ctx.add_bytes(k);
                    off += k;
                    len -= k;
                    total += k;
                }
            }
            if (total != it.entry.size) fail(ErrorCode::Corrupt, "entry data is shorter than its size", it.entry.path);
        });
    });
}

std::string latin1_to_utf8(std::string_view s)
{
    std::string r;
    for (unsigned char c : s) {
        if (c < 0x80) r.push_back(char(c));
        else { r.push_back(char(0xc0 | (c >> 6))); r.push_back(char(0x80 | (c & 0x3f))); }
    }
    return r;
}

namespace {

bool valid_utf8(std::string_view s)
{
    for (std::size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        const std::size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
        if (!n || i + n > s.size()) return false;
        for (std::size_t k = 1; k < n; ++k)
            if ((static_cast<unsigned char>(s[i + k]) & 0xc0) != 0x80) return false;
        i += n;
    }
    return true;
}

bool convert(const char *from, std::string_view s, std::string &out)
{
    iconv_t cd = iconv_open("UTF-8", from);
    if (cd == iconv_t(-1)) return false;
    std::string in(s);
    out.assign(in.size() * 4 + 4, '\0');
    char *ip = in.data(), *op = out.data();
    std::size_t il = in.size(), ol = out.size();
    const bool ok = iconv(cd, &ip, &il, &op, &ol) != std::size_t(-1) && il == 0;
    iconv_close(cd);
    out.resize(out.size() - ol);
    return ok;
}

} // namespace

std::string legacy_name_to_utf8(std::string_view s)
{
    if (valid_utf8(s)) return std::string(s);
    std::string r;
    if (convert("CP932", s, r)) return r;
    if (convert("CP437", s, r)) return r;
    return latin1_to_utf8(s);
}

// ================================================================ ar / .deb

namespace {

std::uint64_t dec(std::string_view f, const char *what)
{
    std::uint64_t v = 0;
    bool any = false;
    for (char c : f) {
        if (c == ' ') { if (any) break; continue; }
        if (c < '0' || c > '9') fail(ErrorCode::Corrupt, std::string("ar header has a bad ") + what);
        if (v > (UINT64_MAX - 9) / 10) fail(ErrorCode::Corrupt, "ar header number is too big");
        v = v * 10 + unsigned(c - '0');
        any = true;
    }
    return v;
}

std::uint64_t oct(std::string_view f)
{
    std::uint64_t v = 0;
    for (char c : f) {
        if (c < '0' || c > '7') break;
        v = v * 8 + unsigned(c - '0');
    }
    return v;
}

class ArReader final : public ItemReader {
public:
    ArReader(std::shared_ptr<Source> src, std::uint64_t start) : ItemReader(std::move(src))
    {
        const std::uint64_t size = src_->size();
        std::uint64_t pos = start + 8;
        std::string names; // GNU "//" table
        bool deb = false;
        while (pos + 60 <= size) {
            char h[60];
            src_->read_exact(pos, h, 60);
            if (h[58] != '`' || h[59] != '\n') fail(ErrorCode::Corrupt, "an ar header is damaged");
            std::string name(h, 16);
            while (!name.empty() && name.back() == ' ') name.pop_back();
            const std::uint64_t len = dec({h + 48, 10}, "size");
            std::uint64_t data = pos + 60;
            if (len > size - data) fail(ErrorCode::Truncated, "ar archive ends early");
            std::uint64_t dlen = len;
            pos = data + len + (len & 1);
            if (name == "/" || name == "/SYM64/" || name == "__.SYMDEF" || name == "__.SYMDEF SORTED") continue;
            if (name == "//") {
                if (len > (64u << 20)) fail(ErrorCode::Corrupt, "ar name table is too big");
                names.resize(std::size_t(len));
                src_->read_exact(data, names.data(), names.size());
                continue;
            }
            if (name.rfind("#1/", 0) == 0) { // BSD: name at the start of the data
                const std::uint64_t n = dec(std::string_view(name).substr(3), "name length");
                if (n > dlen || n > 4096) fail(ErrorCode::Corrupt, "an ar name is damaged");
                name.resize(std::size_t(n));
                src_->read_exact(data, name.data(), name.size());
                name.resize(strnlen(name.data(), name.size()));
                data += n;
                dlen -= n;
            } else if (name.size() > 1 && name[0] == '/' && name[1] >= '0' && name[1] <= '9') {
                const std::uint64_t off = dec(std::string_view(name).substr(1), "name offset");
                if (off >= names.size()) fail(ErrorCode::Corrupt, "an ar name is damaged");
                const auto e = names.find_first_of("/\n", std::size_t(off));
                name = names.substr(std::size_t(off), e == std::string::npos ? std::string::npos : e - std::size_t(off));
            } else if (!name.empty() && name.back() == '/') {
                name.pop_back();
            }
            if (items_.empty() && name == "debian-binary") deb = true;
            Item it;
            it.entry.path = name;
            it.entry.size = dlen;
            it.entry.packed_size = dlen;
            it.entry.method = "Store";
            it.entry.mtime = Timestamp{std::int64_t(dec({h + 16, 12}, "date")), 0};
            it.entry.mode = std::uint32_t(oct({h + 40, 8}) & 0777);
            it.pieces.emplace_back(data, dlen);
            items_.push_back(std::move(it));
        }
        info_.detail = deb ? "Debian package" : "ar";
    }
};

} // namespace

std::unique_ptr<ReaderImpl> open_ar(const OpenRequest &req)
{
    return std::make_unique<ArReader>(req.source, req.detection.offset);
}

} // namespace raye::archive::detail
