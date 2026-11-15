// SPDX-License-Identifier: GPL-3.0-or-later
// cpio (newc, crc, odc, old binary in both byte orders) and RPM, whose
// payload is a compressed cpio.
#include "items.h"
#include "readers.h"

#include "../tar/stream.h"

#include "../../core/bytes.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <tuple>

namespace raye::archive::detail {

namespace {

struct CpioItem {
    Entry entry;
    std::uint64_t data_pos = 0, stored = 0;
    std::uint64_t dev = 0, ino = 0, nlink = 1;
};

std::uint64_t hex(const char *p, std::size_t n)
{
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const char c = p[i];
        int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (d < 0) fail(ErrorCode::Corrupt, "a cpio header is damaged");
        v = v * 16 + unsigned(d);
    }
    return v;
}

std::uint64_t octal(const char *p, std::size_t n)
{
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) {
        if (p[i] < '0' || p[i] > '7') fail(ErrorCode::Corrupt, "a cpio header is damaged");
        v = v * 8 + unsigned(p[i] - '0');
    }
    return v;
}

class CpioParser {
public:
    explicit CpioParser(InStream &in) : in_(in) {}
    bool next(CpioItem &it)
    {
        skip(left_ + pad_);
        left_ = pad_ = 0;
        it = CpioItem{};
        char m[6];
        if (in_.read(m, 1) == 0) return false; // no trailer: accept what we have
        in_.read_exact(m + 1, 1);
        std::uint64_t mode, namesize, size, mtime;
        std::size_t align = 1;
        std::uint64_t header = 0;
        if ((std::uint8_t(m[0]) == 0xc7 && std::uint8_t(m[1]) == 0x71) || (std::uint8_t(m[0]) == 0x71 && std::uint8_t(m[1]) == 0xc7)) {
            const bool le = std::uint8_t(m[0]) == 0xc7;
            std::uint8_t b[24];
            in_.read_exact(b, 24);
            auto u16 = [&](int i) { return le ? std::uint16_t(b[i] | b[i + 1] << 8) : std::uint16_t(b[i] << 8 | b[i + 1]); };
            it.dev = u16(0); it.ino = u16(2); mode = u16(4); it.nlink = u16(10);
            mtime = std::uint64_t(u16(14)) << 16 | u16(16);
            namesize = u16(18);
            size = std::uint64_t(u16(20)) << 16 | u16(22);
            align = 2;
            header = 26;
        } else {
            in_.read_exact(m + 2, 4);
            if (std::memcmp(m, "070701", 6) == 0 || std::memcmp(m, "070702", 6) == 0) {
                char h[104];
                in_.read_exact(h, 104);
                it.ino = hex(h, 8); mode = hex(h + 8, 8); it.nlink = hex(h + 32, 8); mtime = hex(h + 40, 8);
                size = hex(h + 48, 8); it.dev = hex(h + 56, 8) << 32 | hex(h + 64, 8); namesize = hex(h + 88, 8);
                align = 4;
                header = 110;
            } else if (std::memcmp(m, "070707", 6) == 0) {
                char h[70];
                in_.read_exact(h, 70);
                it.dev = octal(h, 6); it.ino = octal(h + 6, 6); mode = octal(h + 12, 6); it.nlink = octal(h + 30, 6);
                mtime = octal(h + 42, 11); namesize = octal(h + 53, 6); size = octal(h + 59, 11);
                header = 76;
            } else {
                fail(ErrorCode::Corrupt, "a cpio header is damaged");
            }
        }
        if (namesize == 0 || namesize > 65536) fail(ErrorCode::Corrupt, "a cpio name is damaged");
        std::string name(std::size_t(namesize), '\0');
        in_.read_exact(name.data(), name.size());
        name.resize(strnlen(name.data(), name.size()));
        skip((align - (header + namesize) % align) % align);
        if (name == "TRAILER!!!") return false;
        Entry &e = it.entry;
        e.path = name;
        e.mode = std::uint32_t(mode & 07777);
        e.mtime = Timestamp{std::int64_t(mtime), 0};
        switch (mode & 0170000) {
        case 0040000: e.type = EntryType::Directory; break;
        case 0100000: case 0: e.type = EntryType::File; break;
        case 0120000: e.type = EntryType::Symlink; break;
        default: e.type = EntryType::Other; break;
        }
        it.data_pos = in_.pos();
        it.stored = size;
        left_ = size;
        pad_ = (align - size % align) % align;
        if (e.type == EntryType::Symlink) {
            if (size > 65536) fail(ErrorCode::Corrupt, "a cpio link is damaged");
            e.link_target.resize(std::size_t(size));
            in_.read_exact(e.link_target.data(), e.link_target.size());
            left_ = 0;
        }
        e.size = e.type == EntryType::File ? size : 0;
        e.packed_size = e.size;
        return true;
    }
    std::size_t read_data(void *b, std::size_t n)
    {
        n = std::size_t(std::min<std::uint64_t>(n, left_));
        in_.read_exact(b, n);
        left_ -= n;
        return n;
    }

private:
    void skip(std::uint64_t n)
    {
        if (in_.skip(n) != n) fail(ErrorCode::Truncated, "cpio archive ends early");
    }
    InStream &in_;
    std::uint64_t left_ = 0, pad_ = 0;
};

// newc keeps hard-linked data once, on the last link; the others are empty.
void link_up(std::vector<CpioItem> &items)
{
    std::map<std::tuple<std::uint64_t, std::uint64_t>, std::vector<std::size_t>> groups;
    for (std::size_t i = 0; i < items.size(); ++i)
        if (items[i].nlink > 1 && items[i].entry.type == EntryType::File) groups[{items[i].dev, items[i].ino}].push_back(i);
    for (auto &[k, g] : groups) {
        if (g.size() < 2) continue;
        std::size_t owner = g.front();
        for (auto i : g)
            if (items[i].stored) owner = i;
        for (auto i : g) {
            if (i == owner || items[i].stored) continue;
            items[i].entry.type = EntryType::Hardlink;
            items[i].entry.link_target = items[owner].entry.path;
        }
    }
}

Format payload_format(const Source &s, std::uint64_t off)
{
    std::uint8_t b[6] = {};
    s.read_at(off, b, 6);
    if (b[0] == 0x1f && b[1] == 0x8b) return Format::Gzip;
    if (b[0] == 'B' && b[1] == 'Z' && b[2] == 'h') return Format::Bzip2;
    if (b[0] == 0xfd && std::memcmp(b + 1, "7zXZ", 4) == 0) return Format::Xz;
    if (b[0] == 0x28 && b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd) return Format::Zstd;
    if (b[0] == 0x5d && b[1] == 0) return Format::Lzma;
    if (std::memcmp(b, "0707", 4) == 0) return Format::Tar; // plain bytes
    fail(ErrorCode::UnsupportedMethod, "RPM payload is in an unknown format");
}

class CpioReader final : public ReaderImpl {
public:
    CpioReader(std::shared_ptr<Source> src, std::uint64_t start, Format outer, std::string detail)
        : src_(std::move(src)), start_(start), outer_(outer)
    {
        info_.detail = std::move(detail);
        info_.solid = outer_ != Format::Tar;
    }
    ArchiveInfo info() const override { return info_; }
    std::vector<Entry> list(Context &ctx) override
    {
        auto s = open_stream(outer_, *src_, start_, ctx.threads());
        // Keep the decoded payload when it is small: extraction is then random access.
        class Keep final : public InStream {
        public:
            Keep(InStream &b, std::uint64_t lim) : b_(b), lim_(lim) {}
            std::size_t read(void *buf, std::size_t n) override
            {
                const std::size_t r = b_.read(buf, n);
                if (on && v.size() + r <= lim_) v.insert(v.end(), (std::uint8_t *)buf, (std::uint8_t *)buf + r);
                else if (r) { on = false; v = {}; }
                pos_ += r;
                return r;
            }
            InStream &b_;
            std::uint64_t lim_;
            std::vector<std::uint8_t> v;
            bool on = true;
        };
        std::unique_ptr<Keep> keep;
        InStream *in = s.get();
        if (outer_ != Format::Tar) { keep = std::make_unique<Keep>(*s, std::min<std::uint64_t>(memory_budget() / 2, 512u << 20)); in = keep.get(); }
        CpioParser p(*in);
        items_.clear();
        CpioItem it;
        while (p.next(it)) {
            if ((items_.size() & 255) == 0) ctx.checkpoint();
            it.entry.method = outer_ == Format::Tar ? "Store" : format_name(outer_);
            it.entry.solid = outer_ != Format::Tar;
            items_.push_back(std::move(it));
        }
        link_up(items_);
        if (keep && keep->on) cache_ = memory_source(std::move(keep->v));
        std::vector<Entry> out;
        for (std::size_t i = 0; i < items_.size(); ++i) {
            items_[i].entry.index = i;
            out.push_back(items_[i].entry);
        }
        return out;
    }
    void extract(const std::vector<std::size_t> &indexes, EntryHandler &h, Context &ctx) override
    {
        const Source *ra = cache_ ? cache_.get() : outer_ == Format::Tar ? src_.get() : nullptr;
        const std::uint64_t base = cache_ ? 0 : start_;
        std::vector<Entry> all;
        for (auto &i : items_) all.push_back(i.entry);
        if (ra) {
            for_each_entry(all, indexes, ctx, false, [&](std::size_t i) {
                const auto &it = items_[i];
                run_entry(it.entry, h, ctx, [&](Sink &s) { copy(*ra, base + it.data_pos, it.stored, s, ctx); });
            });
            return;
        }
        // Too big to keep: one more pass over the stream, links at the end.
        auto st = open_stream(outer_, *src_, start_, ctx.threads());
        CpioParser p(*st);
        CpioItem it;
        std::size_t want = 0, idx = 0;
        std::vector<std::size_t> later;
        while (want < indexes.size() && p.next(it)) {
            if (idx == indexes[want]) {
                const Entry &e = items_[idx].entry;
                if (e.type == EntryType::File) {
                    run_entry(e, h, ctx, [&](Sink &s) {
                        std::vector<std::uint8_t> buf(1 << 20);
                        std::uint64_t left = it.stored;
                        while (left) {
                            ctx.checkpoint();
                            const std::size_t k = p.read_data(buf.data(), std::size_t(std::min<std::uint64_t>(left, buf.size())));
                            s.write(buf.data(), k);
                            ctx.add_bytes(k);
                            left -= k;
                        }
                    });
                } else if (e.type == EntryType::Directory) {
                    run_entry(e, h, ctx, {});
                } else {
                    later.push_back(idx);
                }
                ++want;
            }
            ++idx;
        }
        for (auto i : later) run_entry(items_[i].entry, h, ctx, {});
    }

private:
    static void copy(const Source &src, std::uint64_t off, std::uint64_t n, Sink &s, Context &ctx)
    {
        std::vector<std::uint8_t> buf(std::size_t(std::min<std::uint64_t>(std::max<std::uint64_t>(n, 1), 1 << 20)));
        while (n) {
            ctx.checkpoint();
            const std::size_t k = std::size_t(std::min<std::uint64_t>(n, buf.size()));
            src.read_exact(off, buf.data(), k);
            s.write(buf.data(), k);
            ctx.add_bytes(k);
            off += k;
            n -= k;
        }
    }
    std::shared_ptr<Source> src_;
    std::uint64_t start_;
    Format outer_;
    ArchiveInfo info_;
    std::vector<CpioItem> items_;
    std::shared_ptr<Source> cache_;
};

// RPM header: magic, 4 reserved, entry count, data size (big endian).
std::uint64_t skip_rpm_header(const Source &s, std::uint64_t pos, bool pad8)
{
    std::uint8_t h[16];
    s.read_exact(pos, h, 16);
    if (h[0] != 0x8e || h[1] != 0xad || h[2] != 0xe8) fail(ErrorCode::Corrupt, "RPM header is damaged");
    const std::uint64_t n = be32(h + 8), size = be32(h + 12);
    if (n > (1u << 20) || size > (256u << 20)) fail(ErrorCode::Corrupt, "RPM header is damaged");
    pos += 16 + n * 16 + size;
    if (pad8) pos = (pos + 7) / 8 * 8;
    if (pos > s.size()) fail(ErrorCode::Truncated, "RPM file ends early");
    return pos;
}

} // namespace

std::unique_ptr<ReaderImpl> open_cpio(const OpenRequest &req)
{
    return std::make_unique<CpioReader>(req.source, req.detection.offset, Format::Tar, "cpio");
}

std::unique_ptr<ReaderImpl> open_rpm(const OpenRequest &req)
{
    const Source &s = *req.source;
    std::uint64_t pos = req.detection.offset + 96; // lead
    pos = skip_rpm_header(s, pos, true);           // signature, padded to 8
    pos = skip_rpm_header(s, pos, false);          // main header
    const Format f = payload_format(s, pos);
    return std::make_unique<CpioReader>(req.source, pos, f, f == Format::Tar ? "RPM" : std::string("RPM, ") + format_name(f));
}

} // namespace raye::archive::detail
