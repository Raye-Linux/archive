// SPDX-License-Identifier: GPL-3.0-or-later
#include <raye/archive/archive.h>

#include "context.h"
#include "driver.h"
#include "extract.h"
#include "walk.h"

#include <algorithm>
#include <map>
#include <mutex>
#include <numeric>
#include <set>

#ifndef RAYE_ARCHIVE_VERSION
#define RAYE_ARCHIVE_VERSION "0.5~beta1"
#endif

namespace raye::archive {

namespace fs = std::filesystem;
using namespace detail;

const char *version() noexcept { return RAYE_ARCHIVE_VERSION; }

struct Archive::State {
    std::shared_ptr<Source> source;
    std::unique_ptr<ReaderImpl> impl;
    ArchiveInfo info;
    std::optional<std::vector<Entry>> entries;
    OpenOptions opts;
    std::string name;
};

Archive::Archive() : s_(std::make_unique<State>()) {}
Archive::Archive(Archive &&) noexcept = default;
Archive &Archive::operator=(Archive &&) noexcept = default;
Archive::~Archive() = default;

namespace {

Archive::State &open_into(Archive::State &s, std::shared_ptr<Source> src, std::vector<fs::path> volumes,
                          const OpenOptions &opts)
{
    s.opts = opts;
    s.source = std::move(src);
    s.name = s.source->name();
    Detection det;
    if (opts.force_format) {
        det.format = *opts.force_format;
        det.score = 100;
    } else {
        det = detect(*s.source, fs::path(s.name).filename().string());
        if (det.format == Format::Unknown) fail(ErrorCode::UnknownFormat, "this file is not an archive Raye can open", s.name);
    }
    const Driver *d = driver_for(det.format);
    if (!d) fail(ErrorCode::UnknownFormat, "no reader for this format", s.name);
    Context ctx(opts.callbacks, 0, opts.password, fs::path(s.name).filename().string());
    OpenRequest req{s.source, det, std::move(volumes), s.name};
    s.impl = d->open(req, ctx);
    s.info = s.impl->info();
    s.info.format = det.format;
    s.info.offset = det.offset;
    s.info.self_extracting = det.self_extracting;
    if (s.info.detail.empty()) s.info.detail = det.detail;
    return s;
}

std::uint64_t source_size(const Archive::State &s) { return s.source ? s.source->size() : 0; }

} // namespace

Archive Archive::open(const fs::path &path, const OpenOptions &opts)
{
    Archive a;
    VolumeSet vs = find_volumes(path);
    std::shared_ptr<Source> src;
    if ((vs.kind == VolumeSet::Kind::Split || vs.kind == VolumeSet::Kind::ZipSplit) && vs.volumes.size() > 1)
        src = concat_source(vs.volumes);
    else
        src = open_file_source(vs.volumes.front());
    if (!vs.complete && vs.kind != VolumeSet::Kind::Single && vs.kind != VolumeSet::Kind::RarNew)
        fail(ErrorCode::MissingVolume, "a volume of this archive is missing", path.string());
    open_into(*a.s_, std::move(src), vs.volumes, opts);
    a.s_->info.volume_count = std::max<std::size_t>(a.s_->info.volume_count, vs.volumes.size());
    return a;
}

Archive Archive::open(std::shared_ptr<Source> source, const OpenOptions &opts)
{
    Archive a;
    open_into(*a.s_, std::move(source), {}, opts);
    return a;
}

const ArchiveInfo &Archive::info() const { return s_->info; }
detail::ReaderImpl &Archive::impl() { return *s_->impl; }

const std::vector<Entry> &Archive::entries()
{
    if (!s_->entries) {
        Context ctx(s_->opts.callbacks, 0, s_->opts.password, fs::path(s_->name).filename().string());
        auto v = s_->impl->list(ctx);
        for (std::size_t i = 0; i < v.size(); ++i)
            if (v[i].index != i) fail(ErrorCode::Internal, "reader returned entries out of order", s_->name);
        s_->entries = std::move(v);
    }
    return *s_->entries;
}

namespace {

class DiskHandler final : public EntryHandler {
public:
    DiskHandler(Extractor &x, const std::vector<std::size_t> &want) : x_(x), want_(want.begin(), want.end()) {}
    bool wants(std::size_t i) const override { return want_.count(i) != 0; }
    Sink *begin(const Entry &e) override
    {
        auto sink = x_.begin(e);
        if (!sink) return nullptr;
        std::lock_guard l(m_);
        Sink *raw = sink.get();
        open_[raw] = std::move(sink);
        return raw;
    }
    void end(const Entry &e, Sink *s) override
    {
        if (!s) return;
        x_.commit(e, take(s));
    }
    void failed(const Entry &, Sink *s, const Error &err) override
    {
        if (s) take(s); // drops the temporary file
        throw err;
    }

private:
    std::unique_ptr<Sink> take(Sink *s)
    {
        std::lock_guard l(m_);
        auto it = open_.find(s);
        if (it == open_.end()) return nullptr;
        auto p = std::move(it->second);
        open_.erase(it);
        return p;
    }
    Extractor &x_;
    std::set<std::size_t> want_;
    std::mutex m_;
    std::map<Sink *, std::unique_ptr<Sink>> open_;
};

class StreamHandler final : public EntryHandler {
public:
    StreamHandler(std::size_t idx, Sink &out) : idx_(idx), out_(out) {}
    bool wants(std::size_t i) const override { return i == idx_; }
    Sink *begin(const Entry &e) override { return e.type == EntryType::File ? &out_ : nullptr; }
    void end(const Entry &, Sink *) override { done = true; }
    void failed(const Entry &, Sink *, const Error &err) override { throw err; }
    bool done = false;

private:
    std::size_t idx_;
    Sink &out_;
};

class TestHandler final : public EntryHandler {
public:
    explicit TestHandler(TestResult &r) : r_(r) {}
    bool wants(std::size_t) const override { return true; }
    Sink *begin(const Entry &e) override
    {
        if (e.type != EntryType::File) return nullptr;
        std::lock_guard l(m_);
        sinks_.push_back(std::make_unique<NullSink>());
        return sinks_.back().get();
    }
    void end(const Entry &, Sink *) override
    {
        std::lock_guard l(m_);
        ++r_.entries_ok;
    }
    void failed(const Entry &e, Sink *, const Error &err) override
    {
        if (err.code() == ErrorCode::Cancelled) throw err;
        std::lock_guard l(m_);
        r_.failures.emplace_back(e.path, err);
    }

private:
    TestResult &r_;
    std::mutex m_;
    std::vector<std::unique_ptr<NullSink>> sinks_;
};

} // namespace

void Archive::extract(const std::vector<std::size_t> &indexes, const fs::path &dest, const ExtractOptions &opts,
                      const Callbacks &cb)
{
    const auto &all = entries();
    std::vector<std::size_t> sel(indexes);
    std::sort(sel.begin(), sel.end());
    sel.erase(std::unique(sel.begin(), sel.end()), sel.end());
    std::uint64_t total = 0;
    for (auto i : sel) {
        if (i >= all.size()) fail(ErrorCode::NotFound, "no entry number " + std::to_string(i));
        total += all[i].size;
        // Fail on a bad name before anything is written.
        sanitize_path(all[i].path, opts.safety);
    }
    auto pw = opts.password ? opts.password : s_->opts.password;
    Context ctx(cb, opts.threads, pw, fs::path(s_->name).filename().string());
    ctx.set_totals(total, sel.size());
    Extractor x(dest, opts, cb, ctx, source_size(*s_));
    x.check_space(total);
    DiskHandler h(x, sel);
    s_->impl->extract(sel, h, ctx);
    x.finish();
}

void Archive::extract_all(const fs::path &dest, const ExtractOptions &opts, const Callbacks &cb)
{
    std::vector<std::size_t> all(entries().size());
    std::iota(all.begin(), all.end(), std::size_t(0));
    extract(all, dest, opts, cb);
}

void Archive::extract_to(std::size_t index, Sink &sink, const ExtractOptions &opts, const Callbacks &cb)
{
    const auto &all = entries();
    if (index >= all.size()) fail(ErrorCode::NotFound, "no entry number " + std::to_string(index));
    auto pw = opts.password ? opts.password : s_->opts.password;
    Context ctx(cb, opts.threads, pw, fs::path(s_->name).filename().string());
    ctx.set_totals(all[index].size, 1);
    StreamHandler h(index, sink);
    s_->impl->extract({index}, h, ctx);
    sink.finish();
}

TestResult Archive::test(const ExtractOptions &opts, const Callbacks &cb)
{
    const auto &all = entries();
    std::vector<std::size_t> sel(all.size());
    std::iota(sel.begin(), sel.end(), std::size_t(0));
    std::uint64_t total = 0;
    for (auto &e : all) total += e.size;
    auto pw = opts.password ? opts.password : s_->opts.password;
    Context ctx(cb, opts.threads, pw, fs::path(s_->name).filename().string());
    ctx.set_totals(total, all.size());
    TestResult r;
    TestHandler h(r);
    try {
        s_->impl->extract(sel, h, ctx);
    } catch (const Error &e) {
        if (e.code() == ErrorCode::Cancelled) throw;
        r.failures.emplace_back(std::string{}, e);
    }
    return r;
}

// ---------------------------------------------------------------- writing

namespace {

enum class Op { Create, Add, Update, Sync, Remove };

const Driver &writer_for(Format f)
{
    if (f == Format::Rar || f == Format::Rar5)
        fail(ErrorCode::ReadOnlyFormat, "RAR archives can be opened but not created; use 7z or ZIP");
    const Driver *d = driver_for(f);
    if (!d) fail(ErrorCode::InvalidOption, "unknown format");
    return *d;
}

bool newer(const PlanItem &disk, const Entry &old)
{
    if (disk.stat.type != old.type) return true;
    if (disk.stat.size != old.size) return true;
    if (!old.mtime || !disk.stat.mtime) return true;
    // Some formats keep 2-second DOS times: allow that much slack.
    return disk.stat.mtime->seconds > old.mtime->seconds + 1;
}

void run(Op op, const fs::path &archive, const std::vector<InputItem> &items, const std::vector<std::string> &removed,
         const WriteOptions &opts, const Callbacks &cb)
{
    std::error_code ec;
    const bool exists = fs::exists(archive, ec);
    std::optional<Archive> old;
    Format fmt = opts.format;
    if (op != Op::Create && exists) {
        old.emplace(Archive::open(archive, OpenOptions{opts.password, {}, cb}));
        fmt = old->info().format;
    } else if (op == Op::Remove) {
        fail(ErrorCode::NotFound, "archive does not exist", archive.string());
    }
    const Driver &d = writer_for(fmt);
    if (!d.can_write()) fail(ErrorCode::NotImplemented, std::string(format_name(fmt)) + " writing is not ready yet");

    std::vector<PlanItem> fresh = op == Op::Remove ? std::vector<PlanItem>{} : walk_inputs(items, opts);
    std::vector<PlanItem> plan;
    std::set<std::string> fresh_paths;
    for (auto &p : fresh) fresh_paths.insert(p.archive_path);

    if (old) {
        const auto &ents = old->entries();
        auto under = [](const std::string &path, const std::string &root) {
            return path == root || (path.size() > root.size() && path.compare(0, root.size(), root) == 0 && path[root.size()] == '/');
        };
        std::set<std::string> covered_roots;
        for (auto &it : items) covered_roots.insert(it.archive_path.empty() ? it.source.filename().string() : it.archive_path);
        for (auto &e : ents) {
            bool keep = true;
            if (op == Op::Remove) {
                for (auto &r : removed) keep = keep && !under(e.path, r);
            } else if (fresh_paths.count(e.path)) {
                keep = false; // replaced below (or kept if not newer, for update/sync)
                if (op == Op::Update || op == Op::Sync) {
                    auto f = std::find_if(fresh.begin(), fresh.end(), [&](auto &p) { return p.archive_path == e.path; });
                    if (!newer(*f, e)) { keep = true; fresh.erase(f); }
                }
            } else if (op == Op::Sync) {
                for (auto &r : covered_roots) keep = keep && !under(e.path, r);
            }
            if (keep) {
                PlanItem k;
                k.kind = PlanItem::Kind::Keep;
                k.archive_path = e.path;
                k.stat = e;
                k.keep_index = e.index;
                plan.push_back(std::move(k));
            }
        }
    }
    for (auto &p : fresh) plan.push_back(std::move(p));

    Context ctx(cb, opts.threads, opts.password, archive.filename().string());
    std::uint64_t total = 0;
    for (auto &p : plan)
        if (p.kind == PlanItem::Kind::Add) total += p.stat.size;
    ctx.set_totals(total, plan.size());

    auto writer = d.writer();
    std::unique_ptr<Sink> out = opts.volume_size ? volume_sink(archive, opts.volume_size) : atomic_file_sink(archive);
    writer->write(plan, old ? &old->impl() : nullptr, *out, opts, ctx);
    out->finish();
}

} // namespace

void create(const fs::path &a, const std::vector<InputItem> &i, const WriteOptions &o, const Callbacks &c) { run(Op::Create, a, i, {}, o, c); }
void add(const fs::path &a, const std::vector<InputItem> &i, const WriteOptions &o, const Callbacks &c) { run(Op::Add, a, i, {}, o, c); }
void update(const fs::path &a, const std::vector<InputItem> &i, const WriteOptions &o, const Callbacks &c) { run(Op::Update, a, i, {}, o, c); }
void sync(const fs::path &a, const std::vector<InputItem> &i, const WriteOptions &o, const Callbacks &c) { run(Op::Sync, a, i, {}, o, c); }
void remove(const fs::path &a, const std::vector<std::string> &p, const WriteOptions &o, const Callbacks &c) { run(Op::Remove, a, {}, p, o, c); }

} // namespace raye::archive
