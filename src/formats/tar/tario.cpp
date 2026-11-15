// SPDX-License-Identifier: GPL-3.0-or-later
// Readers and writers for tar, compressed tar and single compressed files.
#include "tario.h"
#include "stream.h"

#include "tar.h"

#include "../../core/context.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <map>
#include <pwd.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

namespace raye::archive::detail {

namespace {

const char *ext_of(Format f)
{
    switch (f) {
    case Format::Gzip: return "gz";
    case Format::Bzip2: return "bz2";
    case Format::Xz: return "xz";
    case Format::Lzma: return "lzma";
    case Format::Zstd: return "zst";
    case Format::Lz4: return "lz4";
    case Format::Lzip: return "lz";
    case Format::Brotli: return "br";
    case Format::Compress: return "Z";
    default: return "";
    }
}

std::string lower(std::string s)
{
    for (auto &c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string base_name(const std::string &p)
{
    const auto cut = p.find_last_of("/\\");
    return cut == std::string::npos ? p : p.substr(cut + 1);
}

// Captures what a stream hands out, up to a limit.
class TeeStream final : public InStream {
public:
    TeeStream(InStream &base, std::uint64_t limit) : base_(base), limit_(limit) {}
    std::size_t read(void *buf, std::size_t n) override
    {
        const std::size_t r = base_.read(buf, n);
        if (keep_) {
            if (copy_.size() + r > limit_) { keep_ = false; copy_.clear(); copy_.shrink_to_fit(); }
            else copy_.insert(copy_.end(), static_cast<std::uint8_t *>(buf), static_cast<std::uint8_t *>(buf) + r);
        }
        pos_ += r;
        return r;
    }
    bool kept() const { return keep_; }
    std::vector<std::uint8_t> take() { return std::move(copy_); }

private:
    InStream &base_;
    std::uint64_t limit_;
    std::vector<std::uint8_t> copy_;
    bool keep_ = true;
};

} // namespace

// ================================================================ TarReader

TarReader::TarReader(std::shared_ptr<Source> src, std::uint64_t start, Format outer)
    : src_(std::move(src)), start_(start), outer_(outer)
{
}

TarReader::~TarReader() = default;

ArchiveInfo TarReader::info() const
{
    ArchiveInfo i;
    i.detail = outer_ == Format::Tar ? "tar" : std::string("tar.") + ext_of(outer_);
    i.solid = outer_ != Format::Tar;
    return i;
}

std::vector<Entry> TarReader::list(Context &ctx)
{
    auto s = open_stream(outer_, *src_, start_, ctx.threads(), &ctx);
    std::unique_ptr<TeeStream> tee;
    InStream *in = s.get();
    if (outer_ != Format::Tar) {
        tee = std::make_unique<TeeStream>(*s, std::min<std::uint64_t>(memory_budget() / 2, 512u << 20));
        in = tee.get();
    }
    TarParser p(*in);
    items_.clear();
    TarItem it;
    const std::string method = outer_ == Format::Tar ? "Store" : ext_of(outer_);
    while (p.next(it)) {
        if ((items_.size() & 255) == 0) ctx.checkpoint();
        it.entry.index = items_.size();
        it.entry.method = method;
        it.entry.solid = outer_ != Format::Tar;
        it.entry.packed_size = outer_ == Format::Tar ? it.stored : 0;
        items_.push_back(std::move(it));
    }
    if (tee && tee->kept()) {
        // Small enough to keep: extraction then reads it in parallel without
        // decoding the whole stream a second time.
        cache_ = memory_source(tee->take());
    }
    std::vector<Entry> out;
    out.reserve(items_.size());
    for (auto &i : items_) out.push_back(i.entry);
    return out;
}

void TarReader::one(const TarItem &it, EntryHandler &h, Context &ctx, const std::function<void(void *, std::size_t)> &read)
{
    const Entry &e = it.entry;
    Sink *s = h.begin(e);
    if (!s || e.type != EntryType::File) { h.end(e, s); return; }
    ctx.file_started(e.path);
    try {
        if (it.sparse) {
            expand_sparse(it, read, [&](const void *d, std::size_t n) { s->write(d, n); ctx.add_bytes(n); });
        } else {
            std::vector<std::uint8_t> buf(std::size_t(std::min<std::uint64_t>(it.stored, 1 << 20)));
            std::uint64_t left = it.stored;
            while (left) {
                ctx.checkpoint();
                const std::size_t k = std::size_t(std::min<std::uint64_t>(left, buf.size()));
                read(buf.data(), k);
                s->write(buf.data(), k);
                ctx.add_bytes(k);
                left -= k;
            }
        }
    } catch (const Error &err) {
        h.failed(e, s, err);
        return;
    }
    h.end(e, s);
    ctx.file_done();
}

void TarReader::extract(const std::vector<std::size_t> &indexes, EntryHandler &h, Context &ctx)
{
    if (items_.empty() && !indexes.empty()) list(ctx);
    for (auto i : indexes)
        if (i >= items_.size()) fail(ErrorCode::NotFound, "no entry number " + std::to_string(i));
    const Source *ra = cache_ ? cache_.get() : outer_ == Format::Tar ? src_.get() : nullptr;
    const std::uint64_t base = cache_ ? 0 : start_;
    const bool ordered = dynamic_cast<OrderedHandler *>(&h) != nullptr;
    if (!ra) return extract_stream(indexes, h, ctx);

    auto from = [&](const TarItem &it) {
        auto off = std::make_shared<std::uint64_t>(base + it.data_pos);
        return [ra, off](void *b, std::size_t n) { ra->read_exact(*off, b, n); *off += n; };
    };
    std::vector<std::size_t> files, rest;
    std::set<std::string> seen;
    bool dup = ordered;
    for (auto i : indexes) {
        if (!seen.insert(items_[i].entry.path).second) dup = true;
        (items_[i].entry.type == EntryType::File ? files : rest).push_back(i);
    }
    if (dup || ctx.threads() <= 1 || files.size() < 2) {
        for (auto i : indexes) one(items_[i], h, ctx, from(items_[i]));
        return;
    }
    // Folders first, then the files side by side, links last (a link made
    // early could otherwise steer a later file somewhere else).
    for (auto i : rest)
        if (items_[i].entry.type == EntryType::Directory) one(items_[i], h, ctx, from(items_[i]));
    ctx.pool().parallel_for(files.size(), [&](std::size_t k) { one(items_[files[k]], h, ctx, from(items_[files[k]])); });
    for (auto i : rest)
        if (items_[i].entry.type != EntryType::Directory) one(items_[i], h, ctx, from(items_[i]));
}

void TarReader::extract_stream(const std::vector<std::size_t> &indexes, EntryHandler &h, Context &ctx)
{
    auto s = open_stream(outer_, *src_, start_, ctx.threads(), &ctx);
    TarParser p(*s);
    TarItem it;
    std::size_t want = 0, idx = 0;
    auto read = [&](void *b, std::size_t n) {
        auto *q = static_cast<std::uint8_t *>(b);
        while (n) {
            const std::size_t r = p.read_data(q, n);
            if (!r) fail(ErrorCode::Truncated, "tar archive ends in the middle of an entry");
            q += r;
            n -= r;
        }
    };
    while (want < indexes.size() && p.next(it)) {
        if (idx == indexes[want]) {
            // Keep our own copy of the entry fields: the list is the reference.
            it.entry = items_[idx].entry;
            one(it, h, ctx, read);
            ++want;
        }
        ++idx;
    }
    if (want < indexes.size()) fail(ErrorCode::Truncated, "tar archive ends early");
}

const TarItem *TarReader::item(std::size_t i) const { return i < items_.size() ? &items_[i] : nullptr; }

// ================================================================ StreamReader

StreamReader::StreamReader(std::shared_ptr<Source> src, std::uint64_t start, Format f, const std::string &archive_name)
    : src_(std::move(src)), start_(start), f_(f)
{
    const StreamMeta m = stream_meta(f, *src_, start_);
    e_.index = 0;
    e_.type = EntryType::File;
    e_.method = ext_of(f);
    e_.size = m.size;
    e_.size_known = m.size_known;
    if (m.mtime > 0) e_.mtime = Timestamp{m.mtime, 0};
    std::string name = base_name(m.name);
    if (name.empty() || name == "." || name == "..") {
        name = base_name(archive_name);
        const std::string l = lower(name), ext = std::string(".") + lower(ext_of(f));
        bool cut = false;
        if (l.size() > ext.size() && l.compare(l.size() - ext.size(), ext.size(), ext) == 0) {
            name.resize(name.size() - ext.size());
            cut = true;
        }
        if (!cut) name += ".out";
    }
    e_.path = name.empty() ? "data" : name;
}

ArchiveInfo StreamReader::info() const
{
    ArchiveInfo i;
    i.detail = ext_of(f_);
    return i;
}

std::vector<Entry> StreamReader::list(Context &) { return {e_}; }

void StreamReader::extract(const std::vector<std::size_t> &indexes, EntryHandler &h, Context &ctx)
{
    if (indexes.empty()) return;
    if (indexes.size() != 1 || indexes[0] != 0) fail(ErrorCode::NotFound, "no such entry");
    Sink *s = h.begin(e_);
    if (!s) { h.end(e_, s); return; }
    try {
        auto in = open_stream(f_, *src_, start_, ctx.threads(), &ctx);
        std::vector<std::uint8_t> buf(1 << 20);
        for (;;) {
            ctx.checkpoint();
            const std::size_t r = in->read(buf.data(), buf.size());
            if (!r) break;
            s->write(buf.data(), r);
            ctx.add_bytes(r);
        }
    } catch (const Error &err) {
        h.failed(e_, s, err);
        return;
    }
    h.end(e_, s);
}

std::unique_ptr<ReaderImpl> open_tar_family(const OpenRequest &req, Format f, Context &)
{
    const std::uint64_t start = req.detection.offset;
    if (f == Format::Tar) return std::make_unique<TarReader>(req.source, start, f);
    // A compressed stream holding a tar lists the tar entries.
    auto s = open_stream(f, *req.source, start, 1);
    std::uint8_t b[512];
    std::size_t got = 0;
    while (got < 512) {
        const std::size_t r = s->read(b + got, 512 - got);
        if (!r) break;
        got += r;
    }
    if (got == 512 && tar_header_ok(b)) return std::make_unique<TarReader>(req.source, start, f);
    return std::make_unique<StreamReader>(req.source, start, f, req.name);
}

// ================================================================ writing

namespace {

bool tar_like_name(const std::string &n)
{
    const std::string l = lower(n);
    if (l.find(".tar") != std::string::npos) return true;
    for (const char *e : {".tgz", ".taz", ".tbz", ".tbz2", ".txz", ".tzst", ".tlz", ".tz"})
        if (l.size() >= std::strlen(e) && l.compare(l.size() - std::strlen(e), std::strlen(e), e) == 0) return true;
    return false;
}

Format stream_for_method(Method m)
{
    switch (m) {
    case Method::Deflate: return Format::Gzip;
    case Method::Bzip2: return Format::Bzip2;
    case Method::Xz: case Method::Lzma2: return Format::Xz;
    case Method::Lzma: return Format::Lzma;
    case Method::Zstd: return Format::Zstd;
    case Method::Lz4: return Format::Lz4;
    case Method::Brotli: return Format::Brotli;
    case Method::Lzip: return Format::Lzip;
    default: return Format::Tar;
    }
}

class Names {
public:
    std::string user(std::uint64_t uid)
    {
        auto it = users_.find(uid);
        if (it != users_.end()) return it->second;
        std::string n;
        struct passwd pw, *res = nullptr;
        std::vector<char> buf(16384);
        if (getpwuid_r(uid_t(uid), &pw, buf.data(), buf.size(), &res) == 0 && res) n = res->pw_name;
        return users_[uid] = n;
    }
    std::string group(std::uint64_t gid)
    {
        auto it = groups_.find(gid);
        if (it != groups_.end()) return it->second;
        std::string n;
        struct group gr, *res = nullptr;
        std::vector<char> buf(16384);
        if (getgrgid_r(gid_t(gid), &gr, buf.data(), buf.size(), &res) == 0 && res) n = res->gr_name;
        return groups_[gid] = n;
    }

private:
    std::map<std::uint64_t, std::string> users_, groups_;
};

// Writes tar entries into out, counting bytes for the end padding.
class TarOut {
public:
    explicit TarOut(Sink &out) : out_(out) {}
    void raw(const void *d, std::size_t n) { out_.write(d, n); written_ += n; }
    void header(const TarHeaderIn &h) { auto b = tar_header(h); raw(b.data(), b.size()); }
    void pad()
    {
        static const std::uint8_t zero[512] = {};
        if (written_ % 512) raw(zero, 512 - written_ % 512);
    }
    void end()
    {
        static const std::uint8_t zero[10240] = {};
        raw(zero, 1024);
        if (written_ % 10240) raw(zero, 10240 - written_ % 10240);
    }

private:
    Sink &out_;
    std::uint64_t written_ = 0;
};

TarHeaderIn header_for(const Entry &e, const TarItem *old)
{
    TarHeaderIn h;
    h.path = e.path;
    if (e.type == EntryType::Directory && (h.path.empty() || h.path.back() != '/')) h.path += '/';
    h.type = e.type;
    h.size = e.size;
    h.mtime = e.mtime.value_or(Timestamp{});
    h.mode = e.mode.value_or(e.type == EntryType::Directory ? 0755 : 0644);
    h.link = e.link_target;
    if (old) { h.uid = old->uid; h.gid = old->gid; h.uname = old->uname; h.gname = old->gname; }
    return h;
}

// Re-stores kept entries of the old archive, in order.
class KeepHandler final : public OrderedHandler {
public:
    KeepHandler(TarOut &out, const TarReader *old) : out_(out), old_(old) {}
    bool wants(std::size_t) const override { return true; }
    Sink *begin(const Entry &e) override
    {
        if (e.type == EntryType::Other) return nullptr;
        TarHeaderIn h = header_for(e, old_ ? old_->item(e.index) : nullptr);
        out_.header(h);
        count_ = 0;
        return e.type == EntryType::File ? &sink_ : nullptr;
    }
    void end(const Entry &e, Sink *s) override
    {
        if (!s) return;
        if (count_ != e.size) fail(ErrorCode::Corrupt, "kept entry changed size", e.path);
        out_.pad();
    }
    void failed(const Entry &, Sink *, const Error &err) override { throw err; }

private:
    class Counter final : public Sink {
    public:
        explicit Counter(KeepHandler &k) : k_(k) {}
        void write(const void *d, std::size_t n) override { k_.out_.raw(d, n); k_.count_ += n; }

    private:
        KeepHandler &k_;
    };
    TarOut &out_;
    const TarReader *old_;
    std::uint64_t count_ = 0;
    Counter sink_{*this};
};

void add_file(TarOut &out, const PlanItem &p, TarHeaderIn &h, Context &ctx)
{
    // a link here was already resolved by the walk (links are followed)
    const int fd = ::open(p.disk.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) fail(ErrorCode::Io, std::string("cannot read: ") + std::strerror(errno), p.disk.string());
    std::vector<std::uint8_t> buf(std::size_t(std::min<std::uint64_t>(std::max<std::uint64_t>(h.size, 1), 1 << 20)));
    out.header(h);
    std::uint64_t left = h.size;
    try {
        while (left) {
            ctx.checkpoint();
            const ssize_t r = ::read(fd, buf.data(), std::size_t(std::min<std::uint64_t>(left, buf.size())));
            if (r < 0) {
                if (errno == EINTR) continue;
                fail(ErrorCode::Io, std::string("read failed: ") + std::strerror(errno), p.disk.string());
            }
            if (r == 0) fail(ErrorCode::Io, "file shrank while it was being archived", p.disk.string());
            out.raw(buf.data(), std::size_t(r));
            ctx.add_bytes(std::uint64_t(r));
            left -= std::uint64_t(r);
        }
    } catch (...) {
        ::close(fd);
        throw;
    }
    ::close(fd);
    out.pad();
}

} // namespace

void TarWriter::write(const std::vector<PlanItem> &plan, ReaderImpl *existing, Sink &out, const WriteOptions &opts,
                      Context &ctx)
{
    Format comp = f_ == Format::Tar ? stream_for_method(opts.method) : f_;
    const std::string arch = ctx.archive_name();

    // One plain file into a .gz/.xz/... that is not named like a tar: just the stream.
    if (comp != Format::Tar && plan.size() == 1 && plan[0].kind == PlanItem::Kind::Add &&
        plan[0].stat.type == EntryType::File && !tar_like_name(arch) && f_ != Format::Tar) {
        const PlanItem &p = plan[0];
        auto cs = compress_sink(comp, out, opts, ctx, base_name(p.archive_path),
                                opts.store_mtime && p.stat.mtime ? p.stat.mtime->seconds : 0);
        TarOut raw(*cs);
        const int fd = ::open(p.disk.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) fail(ErrorCode::Io, std::string("cannot read: ") + std::strerror(errno), p.disk.string());
        std::vector<std::uint8_t> buf(1 << 20);
        for (;;) {
            ctx.checkpoint();
            const ssize_t r = ::read(fd, buf.data(), buf.size());
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) { const int e = errno; ::close(fd); fail(ErrorCode::Io, std::strerror(e), p.disk.string()); }
            if (r == 0) break;
            raw.raw(buf.data(), std::size_t(r));
            ctx.add_bytes(std::uint64_t(r));
        }
        ::close(fd);
        cs->finish();
        return;
    }

    std::unique_ptr<Sink> cs;
    Sink *dst = &out;
    if (comp != Format::Tar) {
        cs = compress_sink(comp, out, opts, ctx);
        dst = cs.get();
    }
    TarOut tar(*dst);
    Names names;
    std::map<std::pair<dev_t, ino_t>, std::string> links;
    const TarReader *old = dynamic_cast<const TarReader *>(existing);

    for (std::size_t i = 0; i < plan.size();) {
        if (plan[i].kind == PlanItem::Kind::Keep) {
            std::vector<std::size_t> batch;
            while (i < plan.size() && plan[i].kind == PlanItem::Kind::Keep) batch.push_back(plan[i++].keep_index);
            if (!existing) fail(ErrorCode::Internal, "nothing to keep entries from");
            KeepHandler k(tar, old);
            existing->extract(batch, k, ctx);
            continue;
        }
        const PlanItem &p = plan[i++];
        ctx.file_started(p.archive_path);
        Entry e = p.stat;
        e.path = p.archive_path;
        TarHeaderIn h = header_for(e, nullptr);
        if (!opts.store_mtime) h.mtime = {};
        else if (h.mtime.nanoseconds && !opts.store_atime && !opts.store_ctime) h.mtime.nanoseconds = 0;
        struct stat st{};
        if (!p.disk.empty() && ::lstat(p.disk.c_str(), &st) == 0) {
            h.uid = st.st_uid;
            h.gid = st.st_gid;
            h.uname = names.user(st.st_uid);
            h.gname = names.group(st.st_gid);
            if (opts.store_atime) h.atime = Timestamp{st.st_atim.tv_sec, std::uint32_t(st.st_atim.tv_nsec)};
            if (opts.store_ctime) h.ctime = Timestamp{st.st_ctim.tv_sec, std::uint32_t(st.st_ctim.tv_nsec)};
            if (e.type == EntryType::File && st.st_nlink > 1 && opts.store_links) {
                auto [it, fresh] = links.emplace(std::make_pair(st.st_dev, st.st_ino), p.archive_path);
                if (!fresh) {
                    h.type = EntryType::Hardlink;
                    h.link = it->second;
                    h.size = 0;
                    tar.header(h);
                    ctx.file_done();
                    continue;
                }
            }
        }
        if (e.type == EntryType::File && !p.disk.empty()) add_file(tar, p, h, ctx);
        else { h.size = 0; tar.header(h); }
        ctx.file_done();
    }
    tar.end();
    if (cs) cs->finish();
}

} // namespace raye::archive::detail
