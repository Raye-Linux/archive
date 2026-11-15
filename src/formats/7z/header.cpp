// SPDX-License-Identifier: GPL-3.0-or-later
#include "sevenz.h"

#include <raye/archive/error.h>

#include <algorithm>
#include <cstdio>

namespace raye::archive::detail::sevenz {

namespace {

[[noreturn]] void corrupt(const std::string &what) { fail(ErrorCode::Corrupt, "7z header: " + what); }

// Header counts come from the file: cap them by what the header can hold.
std::uint64_t count(ByteReader &r, std::uint64_t limit, const char *what)
{
    const std::uint64_t n = read_number(r);
    if (n > limit) corrupt(std::string("too many ") + what);
    return n;
}

std::vector<bool> read_bits(ByteReader &r, std::size_t n)
{
    std::vector<bool> v(n);
    std::uint8_t b = 0, mask = 0;
    for (std::size_t i = 0; i < n; ++i) {
        if (!mask) { b = r.u8(); mask = 0x80; }
        v[i] = (b & mask) != 0;
        mask >>= 1;
    }
    return v;
}

std::vector<bool> read_defined(ByteReader &r, std::size_t n)
{
    if (r.u8()) return std::vector<bool>(n, true);
    return read_bits(r, n);
}

std::vector<std::optional<std::uint32_t>> read_digests(ByteReader &r, std::size_t n)
{
    auto def = read_defined(r, n);
    std::vector<std::optional<std::uint32_t>> out(n);
    for (std::size_t i = 0; i < n; ++i)
        if (def[i]) out[i] = r.u32();
    return out;
}

void wait_for(ByteReader &r, std::uint64_t id)
{
    for (;;) {
        const std::uint64_t t = read_number(r);
        if (t == id) return;
        if (t == kEnd) corrupt("missing section");
        r.skip(std::size_t(count(r, r.left(), "bytes")));
    }
}

void parse_pack_info(ByteReader &r, StreamsInfo &si, std::uint64_t archive_size)
{
    si.pack_pos = read_number(r);
    const std::uint64_t n = count(r, r.left() + 1, "packed streams");
    si.pack_sizes.assign(std::size_t(n), 0);
    for (;;) {
        const std::uint64_t t = read_number(r);
        if (t == kEnd) break;
        if (t == kSize) {
            for (auto &s : si.pack_sizes) {
                s = read_number(r);
                if (s > archive_size) corrupt("packed stream bigger than the archive");
            }
        } else if (t == kCRC) {
            read_digests(r, std::size_t(n)); // packed CRCs: 7-Zip never writes them, ignored
        } else {
            r.skip(std::size_t(count(r, r.left(), "bytes")));
        }
    }
}

void parse_folder(ByteReader &r, Folder &f)
{
    const std::uint64_t ncoders = read_number(r);
    if (ncoders == 0 || ncoders > 64) corrupt("bad coder count");
    std::uint64_t tin = 0, tout = 0;
    for (std::uint64_t i = 0; i < ncoders; ++i) {
        const std::uint8_t flags = r.u8();
        if (flags & 0x80) corrupt("alternative methods are not supported");
        Coder c;
        const std::size_t idlen = flags & 0x0F;
        if (idlen > 8) corrupt("method id too long");
        for (auto b : r.bytes(idlen)) c.id = c.id << 8 | b;
        if (flags & 0x10) {
            c.num_in = std::uint32_t(count(r, 64, "coder streams"));
            c.num_out = std::uint32_t(count(r, 64, "coder streams"));
        }
        if (flags & 0x20) {
            auto p = r.bytes(std::size_t(count(r, r.left(), "property bytes")));
            c.props.assign(p.begin(), p.end());
        }
        tin += c.num_in;
        tout += c.num_out;
        f.coders.push_back(std::move(c));
    }
    if (tout == 0 || tout > 64 || tin > 64) corrupt("bad stream count");
    for (std::uint64_t i = 0; i + 1 < tout; ++i) {
        BindPair b{read_number(r), read_number(r)};
        if (b.in >= tin || b.out >= tout) corrupt("bad bind pair");
        f.binds.push_back(b);
    }
    if (tin < f.binds.size()) corrupt("bad bind pairs");
    const std::uint64_t npacked = tin - f.binds.size();
    if (npacked == 0) corrupt("folder without input");
    if (npacked == 1) {
        for (std::uint64_t i = 0; i < tin; ++i)
            if (std::none_of(f.binds.begin(), f.binds.end(), [&](auto &b) { return b.in == i; })) {
                f.packed.push_back(i);
                break;
            }
    } else {
        for (std::uint64_t i = 0; i < npacked; ++i) {
            const std::uint64_t v = read_number(r);
            if (v >= tin) corrupt("bad packed stream index");
            f.packed.push_back(v);
        }
    }
    if (f.packed.size() != npacked) corrupt("bad packed streams");
    // Every out stream but one must be bound, once.
    std::vector<int> used(std::size_t(tout), 0);
    for (auto &b : f.binds)
        if (used[std::size_t(b.out)]++) corrupt("out stream bound twice");
    std::vector<int> uin(std::size_t(tin), 0);
    for (auto &b : f.binds)
        if (uin[std::size_t(b.in)]++) corrupt("in stream bound twice");
    for (auto p : f.packed)
        if (uin[std::size_t(p)]++) corrupt("in stream used twice");
}

void parse_unpack_info(ByteReader &r, StreamsInfo &si)
{
    wait_for(r, kFolder);
    const std::uint64_t n = count(r, r.left(), "folders");
    if (r.u8() != 0) fail(ErrorCode::UnsupportedMethod, "7z external folder data is not supported");
    si.folders.assign(std::size_t(n), Folder{});
    std::size_t pack = 0;
    for (auto &f : si.folders) {
        parse_folder(r, f);
        f.first_pack = pack;
        pack += f.packed.size();
    }
    if (pack > si.pack_sizes.size()) corrupt("folders use more packed streams than exist");
    wait_for(r, kCodersUnpackSize);
    for (auto &f : si.folders) {
        f.unpack_sizes.resize(f.total_out());
        for (auto &s : f.unpack_sizes) s = read_number(r);
    }
    for (;;) {
        const std::uint64_t t = read_number(r);
        if (t == kEnd) break;
        if (t == kCRC) {
            auto d = read_digests(r, si.folders.size());
            for (std::size_t i = 0; i < d.size(); ++i) si.folders[i].crc = d[i];
        } else {
            r.skip(std::size_t(count(r, r.left(), "bytes")));
        }
    }
}

void parse_substreams(ByteReader &r, StreamsInfo &si)
{
    for (auto &f : si.folders) f.num_substreams = 1;
    std::uint64_t t = read_number(r);
    if (t == kNumUnpackStream) {
        for (auto &f : si.folders) f.num_substreams = count(r, 1u << 26, "files in a folder");
        t = read_number(r);
    }
    std::uint64_t total = 0;
    for (auto &f : si.folders) total += f.num_substreams;
    if (total > (1u << 26)) corrupt("too many files");
    si.sub_sizes.clear();
    for (auto &f : si.folders) {
        if (f.num_substreams == 0) continue;
        std::uint64_t sum = 0;
        if (t == kSize)
            for (std::uint64_t i = 1; i < f.num_substreams; ++i) {
                const std::uint64_t s = read_number(r);
                sum += s;
                if (sum < s || sum > f.unpack_size()) corrupt("file sizes exceed their folder");
                si.sub_sizes.push_back(s);
            }
        si.sub_sizes.push_back(f.unpack_size() - sum);
    }
    if (t == kSize) t = read_number(r);

    si.sub_crcs.assign(std::size_t(total), std::nullopt);
    std::size_t unknown = 0;
    for (auto &f : si.folders)
        if (!(f.num_substreams == 1 && f.crc)) unknown += std::size_t(f.num_substreams);
    std::vector<std::optional<std::uint32_t>> digests;
    while (t != kEnd) {
        if (t == kCRC) digests = read_digests(r, unknown);
        else r.skip(std::size_t(count(r, r.left(), "bytes")));
        t = read_number(r);
    }
    std::size_t k = 0, d = 0;
    for (auto &f : si.folders) {
        if (f.num_substreams == 1 && f.crc) {
            si.sub_crcs[k++] = f.crc;
        } else {
            for (std::uint64_t i = 0; i < f.num_substreams; ++i, ++k, ++d)
                if (d < digests.size()) si.sub_crcs[k] = digests[d];
        }
    }
}

void parse_times(ByteReader &r, std::vector<FileItem> &files, std::optional<std::uint64_t> FileItem::*field)
{
    auto def = read_defined(r, files.size());
    if (r.u8() != 0) fail(ErrorCode::UnsupportedMethod, "7z external data is not supported");
    for (std::size_t i = 0; i < files.size(); ++i)
        if (def[i]) files[i].*field = r.u64();
}

void parse_files(ByteReader &r, Database &db)
{
    const std::uint64_t n = count(r, r.left() + 1, "files");
    auto &files = db.files;
    files.assign(std::size_t(n), FileItem{});
    std::vector<bool> empty_stream, empty_file, anti;
    std::size_t nempty = 0;
    for (;;) {
        const std::uint64_t t = read_number(r);
        if (t == kEnd) break;
        const std::uint64_t size = count(r, r.left(), "bytes");
        ByteReader p(r.bytes(std::size_t(size)));
        switch (t) {
        case kEmptyStream:
            empty_stream = read_bits(p, files.size());
            nempty = std::size_t(std::count(empty_stream.begin(), empty_stream.end(), true));
            break;
        case kEmptyFile: empty_file = read_bits(p, nempty); break;
        case kAnti: anti = read_bits(p, nempty); break;
        case kName: {
            if (p.u8() != 0) fail(ErrorCode::UnsupportedMethod, "7z external names are not supported");
            for (auto &f : files) {
                const std::size_t start = p.pos();
                std::size_t units = 0;
                for (;;) {
                    const std::uint16_t c = p.u16();
                    if (c == 0) break;
                    ++units;
                }
                p.seek(start);
                f.name = utf16le_to_utf8(p.bytes(units * 2).data(), units);
                p.skip(2);
            }
            break;
        }
        case kCTime: parse_times(p, files, &FileItem::ctime); break;
        case kATime: parse_times(p, files, &FileItem::atime); break;
        case kMTime: parse_times(p, files, &FileItem::mtime); break;
        case kWinAttributes: {
            auto def = read_defined(p, files.size());
            if (p.u8() != 0) fail(ErrorCode::UnsupportedMethod, "7z external data is not supported");
            for (std::size_t i = 0; i < files.size(); ++i)
                if (def[i]) files[i].attrib = p.u32();
            break;
        }
        case kStartPos: parse_times(p, files, &FileItem::start_pos); break;
        default: break; // kDummy and anything newer
        }
    }
    std::size_t e = 0;
    for (std::size_t i = 0; i < files.size(); ++i) {
        if (!empty_stream.empty() && empty_stream[i]) {
            files[i].has_stream = false;
            const bool is_file = e < empty_file.size() && empty_file[e];
            files[i].is_dir = !is_file;
            files[i].is_anti = e < anti.size() && anti[e];
            ++e;
        }
    }
}

// ---- writing

void put_bits(std::vector<std::uint8_t> &o, const std::vector<bool> &v)
{
    std::uint8_t b = 0, mask = 0x80;
    for (bool x : v) {
        if (x) b |= mask;
        mask >>= 1;
        if (!mask) { o.push_back(b); b = 0; mask = 0x80; }
    }
    if (mask != 0x80) o.push_back(b);
}

void put_u32(std::vector<std::uint8_t> &o, std::uint32_t v) { for (int i = 0; i < 4; ++i) o.push_back(std::uint8_t(v >> 8 * i)); }
void put_u64(std::vector<std::uint8_t> &o, std::uint64_t v) { for (int i = 0; i < 8; ++i) o.push_back(std::uint8_t(v >> 8 * i)); }

void put_digests(std::vector<std::uint8_t> &o, const std::vector<std::optional<std::uint32_t>> &d)
{
    const bool all = std::all_of(d.begin(), d.end(), [](auto &x) { return x.has_value(); });
    o.push_back(all ? 1 : 0);
    if (!all) {
        std::vector<bool> def;
        for (auto &x : d) def.push_back(x.has_value());
        put_bits(o, def);
    }
    for (auto &x : d)
        if (x) put_u32(o, *x);
}

void put_folder(std::vector<std::uint8_t> &o, const Folder &f)
{
    write_number(o, f.coders.size());
    for (auto &c : f.coders) {
        std::uint8_t id[8];
        int len = 0;
        for (std::uint64_t v = c.id; v; v >>= 8) ++len;
        if (len == 0) len = 1;
        for (int i = 0; i < len; ++i) id[i] = std::uint8_t(c.id >> 8 * (len - 1 - i));
        const bool complex = c.num_in != 1 || c.num_out != 1;
        o.push_back(std::uint8_t(len | (complex ? 0x10 : 0) | (c.props.empty() ? 0 : 0x20)));
        o.insert(o.end(), id, id + len);
        if (complex) { write_number(o, c.num_in); write_number(o, c.num_out); }
        if (!c.props.empty()) {
            write_number(o, c.props.size());
            o.insert(o.end(), c.props.begin(), c.props.end());
        }
    }
    for (auto &b : f.binds) { write_number(o, b.in); write_number(o, b.out); }
    if (f.packed.size() > 1)
        for (auto p : f.packed) write_number(o, p);
}

void put_streams_info(std::vector<std::uint8_t> &o, const StreamsInfo &si, bool substreams)
{
    if (!si.pack_sizes.empty()) {
        o.push_back(kPackInfo);
        write_number(o, si.pack_pos);
        write_number(o, si.pack_sizes.size());
        o.push_back(kSize);
        for (auto s : si.pack_sizes) write_number(o, s);
        o.push_back(kEnd);
    }
    if (!si.folders.empty()) {
        o.push_back(kUnpackInfo);
        o.push_back(kFolder);
        write_number(o, si.folders.size());
        o.push_back(0);
        for (auto &f : si.folders) put_folder(o, f);
        o.push_back(kCodersUnpackSize);
        for (auto &f : si.folders)
            for (auto s : f.unpack_sizes) write_number(o, s);
        if (std::any_of(si.folders.begin(), si.folders.end(), [](auto &f) { return f.crc.has_value(); })) {
            o.push_back(kCRC);
            std::vector<std::optional<std::uint32_t>> d;
            for (auto &f : si.folders) d.push_back(f.crc);
            put_digests(o, d);
        }
        o.push_back(kEnd);
    }
    if (substreams && !si.folders.empty()) {
        o.push_back(kSubStreamsInfo);
        if (std::any_of(si.folders.begin(), si.folders.end(), [](auto &f) { return f.num_substreams != 1; })) {
            o.push_back(kNumUnpackStream);
            for (auto &f : si.folders) write_number(o, f.num_substreams);
        }
        bool sizes = false;
        std::vector<std::uint8_t> s;
        std::size_t k = 0;
        for (auto &f : si.folders) {
            for (std::uint64_t i = 0; i < f.num_substreams; ++i, ++k)
                if (i + 1 < f.num_substreams) { write_number(s, si.sub_sizes[k]); sizes = true; }
        }
        if (sizes) {
            o.push_back(kSize);
            o.insert(o.end(), s.begin(), s.end());
        }
        std::vector<std::optional<std::uint32_t>> d;
        k = 0;
        for (auto &f : si.folders) {
            if (f.num_substreams == 1 && f.crc) { ++k; continue; }
            for (std::uint64_t i = 0; i < f.num_substreams; ++i) d.push_back(si.sub_crcs[k++]);
        }
        if (!d.empty() && std::any_of(d.begin(), d.end(), [](auto &x) { return x.has_value(); })) {
            o.push_back(kCRC);
            put_digests(o, d);
        }
        o.push_back(kEnd);
    }
    o.push_back(kEnd);
}

void put_prop(std::vector<std::uint8_t> &o, std::uint8_t id, const std::vector<std::uint8_t> &data)
{
    o.push_back(id);
    write_number(o, data.size());
    o.insert(o.end(), data.begin(), data.end());
}

void put_times(std::vector<std::uint8_t> &o, std::uint8_t id, const std::vector<FileItem> &files,
               std::optional<std::uint64_t> FileItem::*field)
{
    std::vector<bool> def;
    for (auto &f : files) def.push_back((f.*field).has_value());
    if (std::none_of(def.begin(), def.end(), [](bool b) { return b; })) return;
    std::vector<std::uint8_t> d;
    const bool all = std::all_of(def.begin(), def.end(), [](bool b) { return b; });
    d.push_back(all ? 1 : 0);
    if (!all) put_bits(d, def);
    d.push_back(0);
    for (auto &f : files)
        if (f.*field) put_u64(d, *(f.*field));
    put_prop(o, id, d);
}

} // namespace

std::uint64_t read_number(ByteReader &r)
{
    const std::uint8_t first = r.u8();
    std::uint8_t mask = 0x80;
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        if ((first & mask) == 0) return v | std::uint64_t(first & (mask - 1)) << (8 * i);
        v |= std::uint64_t(r.u8()) << (8 * i);
        mask >>= 1;
    }
    return v;
}

void write_number(std::vector<std::uint8_t> &out, std::uint64_t v)
{
    int extra = 0;
    while (extra < 8 && v >= (std::uint64_t(1) << (7 * (extra + 1)))) ++extra;
    if (extra == 8) {
        out.push_back(0xFF);
        put_u64(out, v);
        return;
    }
    const std::uint8_t high = std::uint8_t(v >> (8 * extra));
    out.push_back(std::uint8_t(~(0xFFu >> extra) | high));
    for (int i = 0; i < extra; ++i) out.push_back(std::uint8_t(v >> (8 * i)));
}

void parse_streams_info(ByteReader &r, StreamsInfo &si, std::uint64_t archive_size)
{
    std::uint64_t t = read_number(r);
    if (t == kPackInfo) { parse_pack_info(r, si, archive_size); t = read_number(r); }
    if (t == kUnpackInfo) { parse_unpack_info(r, si); t = read_number(r); }
    bool subs = false;
    if (t == kSubStreamsInfo) { parse_substreams(r, si); subs = true; t = read_number(r); }
    if (!subs) {
        for (auto &f : si.folders) {
            f.num_substreams = 1;
            si.sub_sizes.push_back(f.unpack_size());
            si.sub_crcs.push_back(f.crc);
        }
    }
    if (t != kEnd) corrupt("unexpected data in stream info");
    std::size_t used = 0;
    for (auto &f : si.folders) used += f.packed.size();
    if (used > si.pack_sizes.size()) corrupt("folders use more packed streams than exist");
}

void parse_header(ByteReader &r, Database &db, std::uint64_t archive_size)
{
    if (read_number(r) != kHeader) corrupt("no header");
    std::uint64_t t = read_number(r);
    if (t == kArchiveProperties) {
        for (;;) {
            const std::uint64_t p = read_number(r);
            if (p == kEnd) break;
            r.skip(std::size_t(count(r, r.left(), "bytes")));
        }
        t = read_number(r);
    }
    if (t == kAdditionalStreamsInfo) {
        StreamsInfo ignored;
        parse_streams_info(r, ignored, archive_size);
        t = read_number(r);
    }
    if (t == kMainStreamsInfo) {
        parse_streams_info(r, db.streams, archive_size);
        t = read_number(r);
    }
    if (t == kFilesInfo) {
        parse_files(r, db);
        t = read_number(r);
    }
    if (t != kEnd) corrupt("unexpected data in header");
    std::size_t with_stream = 0;
    for (auto &f : db.files) with_stream += f.has_stream;
    if (with_stream != db.streams.sub_sizes.size()) corrupt("file count does not match the streams");
}

std::vector<std::uint8_t> write_header(const Database &db)
{
    std::vector<std::uint8_t> o;
    o.push_back(kHeader);
    if (!db.streams.folders.empty()) {
        o.push_back(kMainStreamsInfo);
        put_streams_info(o, db.streams, true);
    }
    if (!db.files.empty()) {
        o.push_back(kFilesInfo);
        write_number(o, db.files.size());
        const auto &files = db.files;
        std::vector<bool> es, ef, an;
        for (auto &f : files) es.push_back(!f.has_stream);
        if (std::count(es.begin(), es.end(), true)) {
            std::vector<std::uint8_t> d;
            put_bits(d, es);
            put_prop(o, kEmptyStream, d);
            bool any_file = false, any_anti = false;
            for (auto &f : files)
                if (!f.has_stream) {
                    ef.push_back(!f.is_dir);
                    an.push_back(f.is_anti);
                    any_file |= !f.is_dir;
                    any_anti |= f.is_anti;
                }
            if (any_file) { d.clear(); put_bits(d, ef); put_prop(o, kEmptyFile, d); }
            if (any_anti) { d.clear(); put_bits(d, an); put_prop(o, kAnti, d); }
        }
        std::vector<std::uint8_t> names;
        names.push_back(0);
        for (auto &f : files) {
            auto u = utf8_to_utf16le(f.name);
            names.insert(names.end(), u.begin(), u.end());
            names.push_back(0);
            names.push_back(0);
        }
        put_prop(o, kName, names);
        put_times(o, kCTime, files, &FileItem::ctime);
        put_times(o, kATime, files, &FileItem::atime);
        put_times(o, kMTime, files, &FileItem::mtime);
        std::vector<bool> def;
        for (auto &f : files) def.push_back(f.attrib.has_value());
        if (std::count(def.begin(), def.end(), true)) {
            std::vector<std::uint8_t> d;
            const bool all = std::all_of(def.begin(), def.end(), [](bool b) { return b; });
            d.push_back(all ? 1 : 0);
            if (!all) put_bits(d, def);
            d.push_back(0);
            for (auto &f : files)
                if (f.attrib) put_u32(d, *f.attrib);
            put_prop(o, kWinAttributes, d);
        }
        o.push_back(kEnd);
    }
    o.push_back(kEnd);
    return o;
}

std::vector<std::uint8_t> write_encoded_header(const StreamsInfo &si)
{
    std::vector<std::uint8_t> o;
    o.push_back(kEncodedHeader);
    put_streams_info(o, si, false);
    return o;
}

// ---- Folder helpers

std::size_t Folder::total_in() const
{
    std::size_t n = 0;
    for (auto &c : coders) n += c.num_in;
    return n;
}

std::size_t Folder::total_out() const
{
    std::size_t n = 0;
    for (auto &c : coders) n += c.num_out;
    return n;
}

std::size_t Folder::main_out() const
{
    const std::size_t n = total_out();
    for (std::size_t i = 0; i < n; ++i)
        if (std::none_of(binds.begin(), binds.end(), [&](auto &b) { return b.out == i; })) return i;
    corrupt("folder has no output");
}

std::size_t Folder::first_in(std::size_t coder) const
{
    std::size_t n = 0;
    for (std::size_t i = 0; i < coder; ++i) n += coders[i].num_in;
    return n;
}

std::size_t Folder::first_out(std::size_t coder) const
{
    std::size_t n = 0;
    for (std::size_t i = 0; i < coder; ++i) n += coders[i].num_out;
    return n;
}

std::size_t Folder::coder_of_in(std::uint64_t in, std::uint32_t *local) const
{
    std::uint64_t n = 0;
    for (std::size_t i = 0; i < coders.size(); ++i) {
        if (in < n + coders[i].num_in) {
            if (local) *local = std::uint32_t(in - n);
            return i;
        }
        n += coders[i].num_in;
    }
    corrupt("bad stream index");
}

std::size_t Folder::coder_of_out(std::uint64_t out, std::uint32_t *local) const
{
    std::uint64_t n = 0;
    for (std::size_t i = 0; i < coders.size(); ++i) {
        if (out < n + coders[i].num_out) {
            if (local) *local = std::uint32_t(out - n);
            return i;
        }
        n += coders[i].num_out;
    }
    corrupt("bad stream index");
}

bool Folder::encrypted() const
{
    return std::any_of(coders.begin(), coders.end(), [](auto &c) { return c.id == method::Aes; });
}

// ---- text and time

std::string utf16le_to_utf8(const std::uint8_t *p, std::size_t units)
{
    std::string s;
    s.reserve(units);
    for (std::size_t i = 0; i < units; ++i) {
        std::uint32_t c = le16(p + 2 * i);
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < units) {
            const std::uint32_t d = le16(p + 2 * (i + 1));
            if (d >= 0xDC00 && d < 0xE000) {
                c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00);
                ++i;
            }
        }
        if (c >= 0xD800 && c < 0xE000) c = 0xFFFD; // lone surrogate
        if (c < 0x80) {
            s += char(c);
        } else if (c < 0x800) {
            s += char(0xC0 | c >> 6);
            s += char(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            s += char(0xE0 | c >> 12);
            s += char(0x80 | (c >> 6 & 0x3F));
            s += char(0x80 | (c & 0x3F));
        } else {
            s += char(0xF0 | c >> 18);
            s += char(0x80 | (c >> 12 & 0x3F));
            s += char(0x80 | (c >> 6 & 0x3F));
            s += char(0x80 | (c & 0x3F));
        }
    }
    return s;
}

std::vector<std::uint8_t> utf8_to_utf16le(const std::string &s)
{
    std::vector<std::uint8_t> o;
    auto unit = [&](std::uint32_t u) { o.push_back(std::uint8_t(u)); o.push_back(std::uint8_t(u >> 8)); };
    for (std::size_t i = 0; i < s.size();) {
        const auto b = std::uint8_t(s[i]);
        std::uint32_t c = 0xFFFD;
        std::size_t len = 1;
        if (b < 0x80) { c = b; }
        else if ((b & 0xE0) == 0xC0) { len = 2; c = b & 0x1F; }
        else if ((b & 0xF0) == 0xE0) { len = 3; c = b & 0x0F; }
        else if ((b & 0xF8) == 0xF0) { len = 4; c = b & 0x07; }
        bool ok = len > 1 || b < 0x80;
        if (i + len > s.size()) ok = false;
        for (std::size_t k = 1; ok && k < len; ++k) {
            const auto x = std::uint8_t(s[i + k]);
            if ((x & 0xC0) != 0x80) ok = false;
            else c = c << 6 | (x & 0x3F);
        }
        if (!ok) { c = 0xFFFD; len = 1; }
        if (c >= 0x10000) {
            c -= 0x10000;
            unit(0xD800 + (c >> 10));
            unit(0xDC00 + (c & 0x3FF));
        } else {
            unit(c);
        }
        i += len;
    }
    return o;
}

namespace {
constexpr std::uint64_t kEpochDiff = 11644473600ull; // seconds from 1601 to 1970
}

std::optional<Timestamp> filetime_to_unix(std::uint64_t ft)
{
    if (ft == 0) return std::nullopt;
    Timestamp t;
    t.seconds = std::int64_t(ft / 10000000) - std::int64_t(kEpochDiff);
    t.nanoseconds = std::uint32_t(ft % 10000000) * 100;
    return t;
}

std::uint64_t unix_to_filetime(const Timestamp &t)
{
    const std::int64_t s = t.seconds + std::int64_t(kEpochDiff);
    if (s < 0) return 0;
    return std::uint64_t(s) * 10000000 + t.nanoseconds / 100;
}

std::string method_label(std::uint64_t id)
{
    switch (id) {
    case method::Copy: return "Copy";
    case method::Delta: return "Delta";
    case method::X86: case method::X86Short: return "BCJ";
    case method::Bcj2: return "BCJ2";
    case method::Ppc: case method::PpcShort: return "PPC";
    case method::Ia64: case method::Ia64Short: return "IA64";
    case method::Arm: case method::ArmShort: return "ARM";
    case method::Armt: case method::ArmtShort: return "ARMT";
    case method::Sparc: case method::SparcShort: return "SPARC";
    case method::Arm64: return "ARM64";
    case method::RiscV: return "RISCV";
    case method::Lzma: return "LZMA";
    case method::Lzma2: return "LZMA2";
    case method::Ppmd: return "PPMd";
    case method::Deflate: return "Deflate";
    case method::Deflate64: return "Deflate64";
    case method::Bzip2: return "BZip2";
    case method::Aes: return "7zAES";
    case method::Zstd: return "ZSTD";
    case method::Brotli: return "Brotli";
    case method::Lz4: return "LZ4";
    }
    char b[24];
    std::snprintf(b, sizeof b, "%llX", static_cast<unsigned long long>(id));
    return b;
}

} // namespace raye::archive::detail::sevenz
