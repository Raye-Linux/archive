// SPDX-License-Identifier: GPL-3.0-or-later
#include "reader.h"

#include "../../core/checksum.h"
#include "../../core/context.h"
#include "../../core/crypto.h"

#include <algorithm>
#include <cstring>
#include <filesystem>

namespace raye::archive::detail::sevenz {

namespace {

constexpr std::uint64_t kProbeBytes = 16 << 20;

bool password_like(const Error &e)
{
    switch (e.code()) {
    case ErrorCode::Corrupt: case ErrorCode::Truncated: case ErrorCode::Checksum: case ErrorCode::UnsupportedMethod:
        return true;
    default:
        return false;
    }
}

std::string dict_label(std::uint64_t d)
{
    for (int b = 10; b < 40; ++b)
        if (d == (std::uint64_t(1) << b)) return std::to_string(b);
    if (d % (1 << 20) == 0) return std::to_string(d >> 20) + "m";
    return std::to_string(d >> 10) + "k";
}

std::string coder_label(const Coder &c)
{
    std::string s = method_label(c.id);
    if (c.id == method::Lzma && c.props.size() == 5) s += ":" + dict_label(le32(c.props.data() + 1));
    if (c.id == method::Lzma2 && c.props.size() == 1) {
        const unsigned p = c.props[0];
        if (p <= 40) s += ":" + (p == 40 ? std::string("4g") : dict_label(std::uint64_t(2 | (p & 1)) << (p / 2 + 11)));
    }
    if (c.id == method::Ppmd && c.props.size() == 5)
        s += ":o" + std::to_string(c.props[0]) + ":mem" + dict_label(le32(c.props.data() + 1));
    return s;
}

class CrcSink final : public Sink {
public:
    void write(const void *d, std::size_t n) override { crc = crc32(crc, d, n); }
    std::uint32_t crc = 0;
};

// Reads exactly n bytes of a folder's output into a callback, in chunks.
template <class F> void pump(Pull &p, std::uint64_t n, std::vector<std::uint8_t> &buf, Context *ctx, F &&f)
{
    while (n) {
        if (ctx) ctx->checkpoint();
        const std::size_t want = std::size_t(std::min<std::uint64_t>(n, buf.size()));
        std::size_t got = 0;
        while (got < want) {
            const std::size_t r = p.read(buf.data() + got, want - got);
            if (!r) fail(ErrorCode::Truncated, "7z data ends before the end of the file");
            got += r;
        }
        f(buf.data(), got);
        n -= got;
    }
}

} // namespace

std::string folder_label(const Folder &f)
{
    std::string s;
    for (std::size_t i = f.coders.size(); i-- > 0;) {
        if (f.coders[i].id == method::Aes) continue;
        if (!s.empty()) s += ' ';
        s += coder_label(f.coders[i]);
    }
    return s;
}

Reader::Reader(const OpenRequest &req, Context &ctx)
    : src_(req.source), base_(req.detection.offset), name_(req.name)
{
    read_headers(ctx);

    // Entries and where their data lives.
    const auto &si = db_.streams;
    std::vector<std::uint64_t> folder_sub_start(si.folders.size() + 1, 0);
    for (std::size_t i = 0; i < si.folders.size(); ++i)
        folder_sub_start[i + 1] = folder_sub_start[i] + si.folders[i].num_substreams;
    folder_entries_.resize(si.folders.size());
    std::size_t folder = 0, sub = 0;
    std::uint64_t in_folder = 0, offset = 0;
    std::string fallback = std::filesystem::path(name_).stem().string();
    if (fallback.empty()) fallback = "file";
    std::size_t unnamed = 0;
    for (std::size_t i = 0; i < db_.files.size(); ++i) {
        const FileItem &f = db_.files[i];
        if (f.is_anti) continue;
        Entry e;
        e.index = entries_.size();
        e.path = f.name;
        if (e.path.empty()) e.path = unnamed++ ? fallback + "_" + std::to_string(unnamed) : fallback;
        std::replace(e.path.begin(), e.path.end(), '\\', '/');
        Where w{i};
        const std::uint32_t attr = f.attrib.value_or(0);
        const bool unix_ext = (attr & kAttrUnixExtension) != 0;
        const std::uint32_t umode = attr >> 16;
        if (f.is_dir || (attr & kAttrDirectory)) e.type = EntryType::Directory;
        if (unix_ext) {
            e.mode = umode & 07777;
            const std::uint32_t kind = umode & 0170000;
            if (kind == 0040000) e.type = EntryType::Directory;
            else if (kind == 0120000 && f.has_stream) e.type = EntryType::Symlink;
            else if (kind != 0 && kind != 0100000 && kind != 0040000) e.type = EntryType::Other;
        }
        if (f.attrib) e.windows_attributes = attr & 0xFFFF;
        if (f.mtime) e.mtime = filetime_to_unix(*f.mtime);
        if (f.atime) e.atime = filetime_to_unix(*f.atime);
        if (f.ctime) e.ctime = filetime_to_unix(*f.ctime);
        if (f.has_stream) {
            while (folder < si.folders.size() && in_folder >= si.folders[folder].num_substreams) {
                ++folder;
                in_folder = 0;
                offset = 0;
            }
            if (folder >= si.folders.size()) fail(ErrorCode::Corrupt, "7z header: more files than streams");
            const Folder &fo = si.folders[folder];
            w.folder = folder;
            w.sub = sub;
            w.offset = offset;
            e.size = si.sub_sizes[sub];
            e.crc32 = si.sub_crcs[sub];
            e.encrypted = fo.encrypted();
            e.solid = fo.num_substreams > 1;
            e.method = folder_label(fo);
            if (in_folder == 0)
                for (std::size_t k = 0; k < fo.packed.size(); ++k) e.packed_size += si.pack_sizes[fo.first_pack + k];
            folder_entries_[folder].push_back(e.index);
            offset += e.size;
            ++in_folder;
            ++sub;
        } else if (e.type == EntryType::Symlink) {
            e.type = EntryType::File;
        }
        entries_.push_back(std::move(e));
        where_.push_back(w);
    }

    info_.format = Format::SevenZip;
    std::string methods;
    for (auto &fo : si.folders) {
        info_.solid |= fo.num_substreams > 1;
        info_.has_encrypted_entries |= fo.encrypted();
        const std::string l = folder_label(fo);
        if (methods.find(l) == std::string::npos) methods += (methods.empty() ? "" : ", ") + l;
    }
    info_.detail = "7z";
    if (!methods.empty()) info_.detail += " " + methods;
    if (info_.solid) info_.detail += ", solid";
    if (info_.encrypted_headers) info_.detail += ", encrypted names";
}

std::vector<std::uint8_t> Reader::decode_header_folder(const StreamsInfo &si, const std::string *pw)
{
    if (si.folders.empty()) fail(ErrorCode::Corrupt, "7z encoded header has no data");
    const Folder &f = si.folders[0];
    const std::uint64_t size = f.unpack_size();
    check_alloc(size, src_->size(), 256 << 20);
    FolderInput in{*src_, base_ + kStartHeaderSize + si.pack_pos, si, 0, pw, keys_.get()};
    auto p = open_folder(in);
    std::vector<std::uint8_t> out(static_cast<std::size_t>(size));
    std::size_t got = 0;
    while (got < out.size()) {
        const std::size_t r = p->read(out.data() + got, out.size() - got);
        if (!r) fail(ErrorCode::Truncated, "7z header ends early");
        got += r;
    }
    if (f.crc && crc32(0, out.data(), out.size()) != *f.crc) fail(ErrorCode::Checksum, "7z header checksum does not match");
    return out;
}

void Reader::read_headers(Context &ctx)
{
    std::uint8_t sh[kStartHeaderSize];
    src_->read_exact(base_, sh, sizeof sh);
    if (std::memcmp(sh, kSignature, 6) != 0) fail(ErrorCode::Corrupt, "not a 7z archive", name_);
    if (sh[6] != 0) fail(ErrorCode::UnsupportedMethod, "7z format version " + std::to_string(sh[6]) + " is too new", name_);
    const std::uint64_t next_off = le64(sh + 12), next_size = le64(sh + 20);
    const std::uint32_t next_crc = le32(sh + 28);
    if (crc32(0, sh + 12, 20) != le32(sh + 8)) {
        // An all-zero start header is what a 7z writer leaves when it was interrupted.
        fail(ErrorCode::Corrupt, "7z start header is damaged (unfinished archive?)", name_);
    }
    if (next_size == 0) return; // empty archive
    const std::uint64_t at = base_ + kStartHeaderSize + next_off;
    if (next_off > src_->size() || next_size > src_->size() || at + next_size > src_->size())
        fail(ErrorCode::Truncated, "7z archive is cut short: the file list is missing", name_);
    if (next_size > (std::uint64_t(1) << 32)) fail(ErrorCode::Corrupt, "7z header is too big", name_);
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(next_size));
    src_->read_exact(at, buf.data(), buf.size());
    if (crc32(0, buf.data(), buf.size()) != next_crc) fail(ErrorCode::Checksum, "7z header checksum does not match", name_);

    for (int depth = 0; depth < 4; ++depth) {
        if (buf.empty()) fail(ErrorCode::Corrupt, "7z header is empty", name_);
        if (buf[0] == kHeader) {
            ByteReader r(buf);
            parse_header(r, db_, src_->size());
            return;
        }
        if (buf[0] != kEncodedHeader) fail(ErrorCode::Corrupt, "7z header has an unknown type", name_);
        ByteReader r(buf);
        r.skip(1);
        StreamsInfo si;
        parse_streams_info(r, si, src_->size());
        if (si.folders.empty()) fail(ErrorCode::Corrupt, "7z encoded header has no data", name_);
        if (!si.folders[0].encrypted()) {
            buf = decode_header_folder(si, nullptr);
            continue;
        }
        info_.encrypted_headers = true;
        for (int attempt = 1;; ++attempt) {
            const std::string pw = ctx.password({}, attempt);
            try {
                buf = decode_header_folder(si, &pw);
                if (buf.empty() || buf[0] != kHeader) fail(ErrorCode::Corrupt, "bad header");
                good_pw_ = pw;
                ctx.password_ok(pw);
                break;
            } catch (const Error &e) {
                if (!password_like(e)) throw;
            }
        }
    }
    fail(ErrorCode::Corrupt, "7z header is nested too deep", name_);
}

std::vector<Entry> Reader::list(Context &) { return entries_; }

std::uint64_t Reader::folder_data_start(std::size_t folder) const
{
    std::uint64_t off = data_start();
    const auto &si = db_.streams;
    for (std::size_t i = 0; i < si.folders[folder].first_pack; ++i) off += si.pack_sizes[i];
    return off;
}

std::string Reader::password_for(std::size_t folder, Context &ctx, const std::string &entry)
{
    std::lock_guard l(pw_m_);
    if (good_pw_) return *good_pw_;
    const auto &si = db_.streams;
    const Folder &f = si.folders[folder];
    // Check the password on the start of the folder before anything reaches
    // the handler: 7z keeps no password check value.
    std::size_t first_sub = 0;
    for (std::size_t i = 0; i < folder; ++i) first_sub += std::size_t(si.folders[i].num_substreams);
    const std::uint64_t first_size = f.num_substreams ? si.sub_sizes[first_sub] : f.unpack_size();
    const auto first_crc = f.num_substreams ? si.sub_crcs[first_sub] : f.crc;
    for (int attempt = 1;; ++attempt) {
        const std::string pw = ctx.password(entry, attempt);
        try {
            FolderInput in{*src_, folder_data_start(folder), si, folder, &pw, keys_.get()};
            auto p = open_folder(in);
            std::vector<std::uint8_t> buf(1 << 16);
            const std::uint64_t n = std::min(first_size, kProbeBytes);
            std::uint32_t crc = 0;
            pump(*p, n, buf, &ctx, [&](const std::uint8_t *d, std::size_t k) { crc = crc32(crc, d, k); });
            if (n == first_size && first_crc && crc != *first_crc) fail(ErrorCode::Checksum, "wrong password");
            good_pw_ = pw;
            ctx.password_ok(pw);
            return pw;
        } catch (const Error &e) {
            if (!password_like(e)) throw;
        }
    }
}

std::unique_ptr<Pull> Reader::open_folder_checked(std::size_t folder, Context &ctx, const std::string &for_entry)
{
    std::string pw;
    const bool enc = db_.streams.folders[folder].encrypted();
    if (enc) pw = password_for(folder, ctx, for_entry);
    FolderInput in{*src_, folder_data_start(folder), db_.streams, folder, enc ? &pw : nullptr, keys_.get()};
    in.threads = folder_threads_;
    auto p = open_folder(in);
    secure_wipe(pw.data(), pw.size());
    return p;
}

void Reader::extract_folder(std::size_t folder, const std::vector<std::size_t> &wanted, EntryHandler &handler,
                            Context &ctx)
{
    const Folder &f = db_.streams.folders[folder];
    const auto &list = folder_entries_[folder];
    const std::size_t last_wanted = wanted.back();
    if (const std::string u = unsupported_coder(f); !u.empty()) {
        const Error err(ErrorCode::UnsupportedMethod, "7z method " + u + " is not supported");
        for (auto i : wanted) handler.failed(entries_[i], nullptr, err);
        return;
    }
    auto p = open_folder_checked(folder, ctx, entries_[wanted.front()].path);
    std::vector<std::uint8_t> buf(1 << 18);
    for (std::size_t idx : list) {
        if (idx > last_wanted) break;
        Entry e = entries_[idx];
        const bool want = std::binary_search(wanted.begin(), wanted.end(), idx);
        if (!want) {
            pump(*p, e.size, buf, &ctx, [](const std::uint8_t *, std::size_t) {});
            continue;
        }
        Sink *sink = nullptr;
        try {
            std::uint32_t crc = 0;
            if (e.type == EntryType::Symlink) {
                if (e.size > 65536) fail(ErrorCode::Corrupt, "symbolic link target is too long", e.path);
                std::string target;
                pump(*p, e.size, buf, &ctx, [&](const std::uint8_t *d, std::size_t k) {
                    target.append(reinterpret_cast<const char *>(d), k);
                    crc = crc32(crc, d, k);
                });
                if (e.crc32 && crc != *e.crc32) fail(ErrorCode::Checksum, "checksum does not match", e.path);
                e.link_target = target;
                sink = handler.begin(e);
                handler.end(e, sink);
                continue;
            }
            sink = handler.begin(e);
            pump(*p, e.size, buf, &ctx, [&](const std::uint8_t *d, std::size_t k) {
                crc = crc32(crc, d, k);
                if (sink) sink->write(d, k);
                ctx.add_bytes(k);
            });
            if (e.crc32 && crc != *e.crc32) {
                fail(ErrorCode::Checksum, f.encrypted() ? "checksum does not match (wrong password?)"
                                                         : "checksum does not match", e.path);
            }
            handler.end(e, sink);
        } catch (const Error &err) {
            if (err.code() == ErrorCode::Cancelled) throw;
            handler.failed(e, sink, Error(err.code(), err.message(), e.path));
            // The rest of a solid folder can no longer be trusted.
            const Error after(err.code(), "an earlier file in the same solid block is damaged");
            for (std::size_t j : wanted)
                if (j > idx) handler.failed(entries_[j], nullptr, after);
            return;
        }
    }
}

void Reader::extract(const std::vector<std::size_t> &indexes, EntryHandler &handler, Context &ctx)
{
    std::vector<std::vector<std::size_t>> per_folder(db_.streams.folders.size());
    for (std::size_t i : indexes) {
        if (i >= entries_.size()) fail(ErrorCode::NotFound, "no entry number " + std::to_string(i));
        const Where &w = where_[i];
        if (w.folder == SIZE_MAX) {
            const Entry &e = entries_[i];
            Sink *s = handler.begin(e);
            handler.end(e, s);
            continue;
        }
        per_folder[w.folder].push_back(i);
    }
    std::vector<std::size_t> todo;
    for (std::size_t f = 0; f < per_folder.size(); ++f)
        if (!per_folder[f].empty()) todo.push_back(f);
    if (todo.empty()) return;
    // Ask for the password once, before the workers start.
    for (std::size_t f : todo)
        if (db_.streams.folders[f].encrypted() && unsupported_coder(db_.streams.folders[f]).empty()) {
            password_for(f, ctx, entries_[per_folder[f].front()].path);
            break;
        }
    if (todo.size() == 1 || ctx.threads() <= 1) {
        // one folder at a time: its own LZMA2 pieces may use the cores
        struct Reset {
            unsigned &t;
            ~Reset() { t = 1; }
        } reset{folder_threads_};
        folder_threads_ = unsigned(std::max(1, ctx.threads()));
        for (std::size_t f : todo) extract_folder(f, per_folder[f], handler, ctx);
        return;
    }
    // Biggest folders first so the last worker is not left alone with a giant.
    std::sort(todo.begin(), todo.end(), [&](std::size_t a, std::size_t b) {
        return db_.streams.folders[a].unpack_size() > db_.streams.folders[b].unpack_size();
    });
    ctx.pool().parallel_for(todo.size(), [&](std::size_t k) {
        const std::size_t f = todo[k];
        extract_folder(f, per_folder[f], handler, ctx);
    });
}

} // namespace raye::archive::detail::sevenz
