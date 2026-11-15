// SPDX-License-Identifier: GPL-3.0-or-later
#include "extract.h"

#include "context.h"

#include <raye/archive/error.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <random>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

namespace raye::archive::detail {

namespace fs = std::filesystem;

namespace {

std::vector<std::string> split(std::string_view s)
{
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i <= s.size()) {
        std::size_t j = s.find('/', i);
        if (j == std::string_view::npos) j = s.size();
        out.emplace_back(s.substr(i, j - i));
        i = j + 1;
    }
    return out;
}

[[noreturn]] void sys_fail(const std::string &what, const std::string &path)
{
    const int e = errno;
    fail(e == ENOSPC ? ErrorCode::NoSpace : e == EEXIST ? ErrorCode::Exists : ErrorCode::Io,
         what + ": " + std::strerror(e), path);
}

struct Fd {
    int fd = -1;
    Fd() = default;
    explicit Fd(int f) : fd(f) {}
    Fd(Fd &&o) noexcept : fd(o.fd) { o.fd = -1; }
    Fd &operator=(Fd &&o) noexcept { std::swap(fd, o.fd); return *this; }
    ~Fd() { if (fd >= 0) ::close(fd); }
};

mode_t current_umask()
{
    static const mode_t m = [] { mode_t u = ::umask(022); ::umask(u); return u; }();
    return m;
}

} // namespace

bool is_windows_reserved(std::string_view c)
{
    // Trailing dots and spaces are dropped by Windows, so "NUL. " is NUL.
    while (!c.empty() && (c.back() == '.' || c.back() == ' ')) c.remove_suffix(1);
    std::string base(c.substr(0, c.find('.')));
    for (auto &ch : base) ch = char(std::toupper(static_cast<unsigned char>(ch)));
    while (!base.empty() && base.back() == ' ') base.pop_back();
    if (base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$")
        return true;
    if (base.size() == 4 && (base.starts_with("COM") || base.starts_with("LPT")) &&
        ((base[3] >= '0' && base[3] <= '9')))
        return true;
    return false;
}

std::string sanitize_path(std::string_view stored, const SafetyPolicy &p)
{
    if (stored.find('\0') != std::string_view::npos) fail(ErrorCode::UnsafePath, "name contains a NUL byte", std::string(stored));
    std::string s(stored);
    std::replace(s.begin(), s.end(), '\\', '/');
    const bool drive = s.size() >= 2 && s[1] == ':' && std::isalpha(static_cast<unsigned char>(s[0]));
    if (drive) {
        if (!p.allow_absolute) fail(ErrorCode::UnsafePath, "absolute path", std::string(stored));
        s.erase(0, 2);
    }
    if (!s.empty() && s.front() == '/') {
        if (!p.allow_absolute) fail(ErrorCode::UnsafePath, "absolute path", std::string(stored));
        s.erase(0, s.find_first_not_of('/'));
    }
    std::vector<std::string> parts;
    for (auto &c : split(s)) {
        if (c.empty() || c == ".") continue;
        if (c == "..") {
            if (!p.allow_dotdot || parts.empty()) fail(ErrorCode::UnsafePath, "path goes up out of the folder", std::string(stored));
            parts.pop_back();
            continue;
        }
        if (p.refuse_windows_reserved && is_windows_reserved(c))
            fail(ErrorCode::UnsafePath, "reserved device name '" + c + "'", std::string(stored));
        parts.push_back(std::move(c));
    }
    if (parts.empty()) fail(ErrorCode::UnsafePath, "empty name", std::string(stored));
    std::string out;
    for (auto &c : parts) {
        if (!out.empty()) out += '/';
        out += c;
    }
    return out;
}

bool link_escapes(std::string_view link_path, std::string_view target)
{
    std::string t(target);
    std::replace(t.begin(), t.end(), '\\', '/');
    if (t.empty() || t.front() == '/' || (t.size() >= 2 && t[1] == ':')) return true;
    auto base = split(link_path);
    base.pop_back(); // the link itself
    int depth = 0;
    for (auto &c : base)
        if (!c.empty() && c != ".") ++depth;
    for (auto &c : split(t)) {
        if (c.empty() || c == ".") continue;
        if (c == "..") {
            if (--depth < 0) return true;
        } else {
            ++depth;
        }
    }
    return false;
}

void BombGuard::add(std::uint64_t n)
{
    std::lock_guard l(m_);
    out_ += n;
    if (p_.max_total_size && out_ > p_.max_total_size)
        fail(ErrorCode::Bomb, "output is bigger than the " + std::to_string(p_.max_total_size) + " byte limit");
    if (out_ > p_.ratio_grace && in_ && double(out_) > p_.max_ratio * double(in_))
        fail(ErrorCode::Bomb, "archive expands more than " + std::to_string(int(p_.max_ratio)) + " times");
}

// ---------------------------------------------------------------- Extractor

namespace {

class FileOut final : public Sink {
public:
    FileOut(Fd fd, int dirfd, std::string tmp, BombGuard &g, std::string path)
        : fd_(std::move(fd)), dirfd_(dirfd), tmp_(std::move(tmp)), guard_(g), path_(std::move(path)) {}
    ~FileOut() override
    {
        if (!tmp_.empty()) ::unlinkat(dirfd_, tmp_.c_str(), 0);
        if (dirfd_ >= 0) ::close(dirfd_);
    }
    void write(const void *data, std::size_t n) override
    {
        guard_.add(n);
        const char *p = static_cast<const char *>(data);
        while (n) {
            ssize_t w = ::write(fd_.fd, p, n);
            if (w < 0) {
                if (errno == EINTR) continue;
                sys_fail("write failed", path_);
            }
            p += w;
            n -= std::size_t(w);
        }
    }
    Fd fd_;
    int dirfd_;
    std::string tmp_;
    BombGuard &guard_;
    std::string path_;
};

} // namespace

struct Extractor::Impl {
    fs::path dest;
    const ExtractOptions &opts;
    const Callbacks &cb;
    Context &ctx;
    BombGuard guard;
    Fd root;
    std::mutex m; // directory creation and conflict prompts
    std::optional<ConflictChoice> sticky;
    std::vector<std::pair<std::string, Timestamp>> dir_times;
    std::uint64_t entries = 0;
    std::uint64_t archive_size = 0;

    Impl(const fs::path &d, const ExtractOptions &o, const Callbacks &c, Context &cx, std::uint64_t in)
        : dest(d), opts(o), cb(c), ctx(cx), guard(o.safety, in), archive_size(in)
    {
        std::error_code ec;
        fs::create_directories(dest, ec);
        root = Fd(::open(dest.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (root.fd < 0) sys_fail("cannot open destination", dest.string());
    }

    // Opens the folder holding rel (creating it), never following a link.
    Fd open_parent(const std::string &rel, bool create)
    {
        auto parts = split(rel);
        parts.pop_back();
        Fd cur(::dup(root.fd));
        for (auto &c : parts) {
            int fd = ::openat(cur.fd, c.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0 && errno == ENOENT && create) {
                if (::mkdirat(cur.fd, c.c_str(), 0777) != 0 && errno != EEXIST) sys_fail("cannot create folder", rel);
                fd = ::openat(cur.fd, c.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            }
            if (fd < 0) {
                if (errno == ELOOP || errno == ENOTDIR)
                    fail(ErrorCode::LinkOutside, "path goes through a link or a file", rel);
                sys_fail("cannot open folder", rel);
            }
            cur = Fd(fd);
        }
        return cur;
    }

    static std::string leaf(const std::string &rel) { return rel.substr(rel.rfind('/') + 1); }

    ConflictChoice ask(const std::string &rel, const Entry &e)
    {
        if (sticky) return *sticky;
        switch (opts.overwrite) {
        case OverwriteMode::Replace: return ConflictChoice::Replace;
        case OverwriteMode::Skip: return ConflictChoice::Skip;
        case OverwriteMode::KeepBoth: return ConflictChoice::KeepBoth;
        case OverwriteMode::Fail: fail(ErrorCode::Exists, "already exists", rel);
        case OverwriteMode::Ask: break;
        }
        if (!cb.conflict) fail(ErrorCode::Exists, "already exists", rel);
        auto c = cb.conflict(Conflict{(dest / rel).string(), &e});
        switch (c) {
        case ConflictChoice::ReplaceAll: sticky = ConflictChoice::Replace; return *sticky;
        case ConflictChoice::SkipAll: sticky = ConflictChoice::Skip; return *sticky;
        case ConflictChoice::KeepBothAll: sticky = ConflictChoice::KeepBoth; return *sticky;
        case ConflictChoice::Cancel: fail(ErrorCode::Cancelled, "cancelled");
        default: return c;
        }
    }

    static std::string numbered(const std::string &name, int n)
    {
        const auto dot = name.find('.', 1);
        const std::string stem = dot == std::string::npos ? name : name.substr(0, dot);
        const std::string ext = dot == std::string::npos ? "" : name.substr(dot);
        return stem + " (" + std::to_string(n) + ")" + ext;
    }

    std::string rel_of(const Entry &e)
    {
        std::string rel = sanitize_path(e.path, opts.safety);
        if (opts.flat && e.type != EntryType::Directory) rel = leaf(rel);
        return rel;
    }

    void set_times(int dirfd, const std::string &name, const Entry &e, int fd = -1)
    {
        if (!opts.restore_mtime || !e.mtime) return;
        timespec ts[2];
        ts[0].tv_nsec = UTIME_OMIT;
        ts[1].tv_sec = e.mtime->seconds;
        ts[1].tv_nsec = long(e.mtime->nanoseconds);
        if (e.atime) { ts[0].tv_sec = e.atime->seconds; ts[0].tv_nsec = long(e.atime->nanoseconds); }
        if (fd >= 0) ::futimens(fd, ts);
        else ::utimensat(dirfd, name.c_str(), ts, AT_SYMLINK_NOFOLLOW);
    }

    mode_t mode_of(const Entry &e, mode_t fallback)
    {
        if (!opts.restore_permissions || !e.mode) return fallback & ~current_umask();
        mode_t m = mode_t(*e.mode) & 07777;
        if (!opts.safety.keep_setuid) m &= 0777;
        return m & ~current_umask();
    }
};

Extractor::Extractor(const fs::path &dest, const ExtractOptions &opts, const Callbacks &cb, Context &ctx,
                     std::uint64_t archive_size)
    : d_(std::make_unique<Impl>(dest, opts, cb, ctx, archive_size))
{
}

Extractor::~Extractor() = default;

void Extractor::check_space(std::uint64_t declared)
{
    const auto &p = d_->opts.safety;
    if (p.max_total_size && declared > p.max_total_size)
        fail(ErrorCode::Bomb, "archive says it holds " + std::to_string(declared) + " bytes, over the limit");
    const std::uint64_t in = d_->archive_size;
    if (declared > p.ratio_grace && in && double(declared) > p.max_ratio * double(in))
        fail(ErrorCode::Bomb, "archive says it expands more than " + std::to_string(int(p.max_ratio)) + " times");
    if (!p.check_free_space) return;
    struct statvfs sv{};
    if (::fstatvfs(d_->root.fd, &sv) != 0) return;
    const std::uint64_t free_bytes = std::uint64_t(sv.f_bavail) * sv.f_frsize;
    if (declared > free_bytes)
        fail(ErrorCode::NoSpace, "needs " + std::to_string(declared) + " bytes, only " + std::to_string(free_bytes) + " free",
             d_->dest.string());
}

std::unique_ptr<Sink> Extractor::begin(const Entry &e)
{
    auto &d = *d_;
    if (++d.entries > d.opts.safety.max_entries) fail(ErrorCode::Bomb, "too many entries");
    const std::string rel = d.rel_of(e);
    std::unique_lock lock(d.m);
    Fd parent = d.open_parent(rel, true);
    const std::string name = Impl::leaf(rel);

    switch (e.type) {
    case EntryType::Directory: {
        if (d.opts.flat) return nullptr;
        if (::mkdirat(parent.fd, name.c_str(), 0777) != 0 && errno != EEXIST) sys_fail("cannot create folder", rel);
        struct stat st{};
        if (::fstatat(parent.fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(st.st_mode))
            fail(ErrorCode::Exists, "a file with this name is in the way", rel);
        if (e.mode && d.opts.restore_permissions) (void)!::fchmodat(parent.fd, name.c_str(), d.mode_of(e, 0777) | 0700, 0);
        if (e.mtime) d.dir_times.emplace_back(rel, *e.mtime);
        return nullptr;
    }
    case EntryType::Symlink: {
        if (!d.opts.safety.create_symlinks) return nullptr;
        if (!d.opts.safety.allow_links_outside && link_escapes(rel, e.link_target))
            fail(ErrorCode::LinkOutside, "link points outside the folder (" + e.link_target + ")", rel);
        struct stat st{};
        if (::fstatat(parent.fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
            auto c = d.ask(rel, e);
            if (c == ConflictChoice::Skip) return nullptr;
            if (c == ConflictChoice::Replace && !S_ISDIR(st.st_mode)) ::unlinkat(parent.fd, name.c_str(), 0);
            else if (c == ConflictChoice::KeepBoth) {
                for (int n = 2;; ++n)
                    if (::fstatat(parent.fd, Impl::numbered(name, n).c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
                        if (::symlinkat(e.link_target.c_str(), parent.fd, Impl::numbered(name, n).c_str()) != 0)
                            sys_fail("cannot create link", rel);
                        return nullptr;
                    }
            }
        }
        if (::symlinkat(e.link_target.c_str(), parent.fd, name.c_str()) != 0) sys_fail("cannot create link", rel);
        d.set_times(parent.fd, name, e);
        return nullptr;
    }
    case EntryType::Hardlink: {
        const std::string target = sanitize_path(e.link_target, d.opts.safety);
        Fd tparent = d.open_parent(target, false);
        const std::string tname = Impl::leaf(target);
        struct stat st{};
        if (::fstatat(tparent.fd, tname.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode))
            fail(ErrorCode::LinkOutside, "hard link target is not a file extracted here", rel);
        if (::fstatat(parent.fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
            auto c = d.ask(rel, e);
            if (c != ConflictChoice::Replace) return nullptr;
            ::unlinkat(parent.fd, name.c_str(), 0);
        }
        if (::linkat(tparent.fd, tname.c_str(), parent.fd, name.c_str(), 0) != 0) sys_fail("cannot create hard link", rel);
        return nullptr;
    }
    case EntryType::Other: return nullptr; // devices and fifos are never made
    case EntryType::File: break;
    }

    lock.unlock();
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    for (int tries = 0; tries < 100; ++tries) {
        char tmp[40];
        std::snprintf(tmp, sizeof tmp, ".raye-%016llx.part", static_cast<unsigned long long>(rng()));
        int fd = ::openat(parent.fd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0) {
            d.ctx.file_started(e.path);
            return std::make_unique<FileOut>(Fd(fd), ::dup(parent.fd), tmp, d.guard, rel);
        }
        if (errno != EEXIST) sys_fail("cannot create", rel);
    }
    fail(ErrorCode::Io, "cannot create a temporary file", rel);
}

void Extractor::commit(const Entry &e, std::unique_ptr<Sink> sink)
{
    auto &d = *d_;
    auto *out = dynamic_cast<FileOut *>(sink.get());
    if (!out) return;
    const std::string rel = d.rel_of(e);
    const std::string name = Impl::leaf(rel);
    ::fchmod(out->fd_.fd, d.mode_of(e, 0666));
    d.set_times(-1, {}, e, out->fd_.fd);
    if (::close(out->fd_.fd) != 0) { out->fd_.fd = -1; sys_fail("write failed", rel); }
    out->fd_.fd = -1;

    std::lock_guard lock(d.m);
    std::string final_name = name;
    struct stat st{};
    if (::fstatat(out->dirfd_, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
        auto c = d.ask(rel, e);
        if (c == ConflictChoice::Skip) return; // FileOut removes the temp file
        if (c == ConflictChoice::KeepBoth) {
            for (int n = 2;; ++n) {
                final_name = Impl::numbered(name, n);
                if (::fstatat(out->dirfd_, final_name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) break;
            }
        } else if (S_ISDIR(st.st_mode)) {
            fail(ErrorCode::Exists, "a folder with this name is in the way", rel);
        }
    }
    if (::renameat(out->dirfd_, out->tmp_.c_str(), out->dirfd_, final_name.c_str()) != 0) sys_fail("cannot rename", rel);
    out->tmp_.clear();
    d.ctx.file_done();
}

void Extractor::finish()
{
    auto &d = *d_;
    if (!d.opts.restore_mtime) return;
    std::sort(d.dir_times.begin(), d.dir_times.end(),
              [](auto &a, auto &b) { return std::count(a.first.begin(), a.first.end(), '/') > std::count(b.first.begin(), b.first.end(), '/'); });
    for (auto &[rel, t] : d.dir_times) {
        Fd parent = d.open_parent(rel, false);
        timespec ts[2]{{0, UTIME_OMIT}, {t.seconds, long(t.nanoseconds)}};
        ::utimensat(parent.fd, Impl::leaf(rel).c_str(), ts, AT_SYMLINK_NOFOLLOW);
    }
}

} // namespace raye::archive::detail
