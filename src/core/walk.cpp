// SPDX-License-Identifier: GPL-3.0-or-later
#include "walk.h"

#include <raye/archive/error.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <fnmatch.h>
#include <sys/stat.h>
#include <unistd.h>

namespace raye::archive {

namespace {
struct MName { Method m; const char *n; };
constexpr std::array kMethods = {
    MName{Method::Default, "default"}, MName{Method::Store, "store"},   MName{Method::Deflate, "deflate"},
    MName{Method::Deflate64, "deflate64"}, MName{Method::Bzip2, "bzip2"}, MName{Method::Lzma, "lzma"},
    MName{Method::Lzma2, "lzma2"},     MName{Method::Ppmd, "ppmd"},     MName{Method::Zstd, "zstd"},
    MName{Method::Xz, "xz"},           MName{Method::Lz4, "lz4"},       MName{Method::Brotli, "brotli"},
    MName{Method::Lzip, "lzip"},
};
} // namespace

const char *method_name(Method m) noexcept
{
    for (auto &x : kMethods)
        if (x.m == m) return x.n;
    return "default";
}

std::optional<Method> method_from_name(std::string_view s) noexcept
{
    std::string l(s);
    for (auto &c : l) c = char(std::tolower(static_cast<unsigned char>(c)));
    if (l == "copy") return Method::Store;
    for (auto &x : kMethods)
        if (l == x.n) return x.m;
    return std::nullopt;
}

namespace detail {

namespace fs = std::filesystem;

bool glob_match(std::string_view pattern, std::string_view path)
{
    const std::string pat(pattern), p(path);
    if (pattern.find('/') != std::string_view::npos) return fnmatch(pat.c_str(), p.c_str(), 0) == 0;
    std::size_t i = 0;
    while (i <= p.size()) {
        std::size_t j = p.find('/', i);
        if (j == std::string::npos) j = p.size();
        if (fnmatch(pat.c_str(), p.substr(i, j - i).c_str(), 0) == 0) return true;
        i = j + 1;
    }
    return false;
}

namespace {

Entry stat_entry(const fs::path &p, bool follow)
{
    struct stat st{};
    int r = follow ? ::stat(p.c_str(), &st) : ::lstat(p.c_str(), &st);
    // a dangling link is kept as the link when following
    if (r != 0 && follow) r = ::lstat(p.c_str(), &st);
    if (r != 0) fail(ErrorCode::NotFound, "cannot read", p.string());
    Entry e;
    e.mode = std::uint32_t(st.st_mode & 07777);
    e.mtime = Timestamp{st.st_mtim.tv_sec, std::uint32_t(st.st_mtim.tv_nsec)};
    e.atime = Timestamp{st.st_atim.tv_sec, std::uint32_t(st.st_atim.tv_nsec)};
    e.ctime = Timestamp{st.st_ctim.tv_sec, std::uint32_t(st.st_ctim.tv_nsec)};
    if (S_ISDIR(st.st_mode)) e.type = EntryType::Directory;
    else if (S_ISLNK(st.st_mode)) {
        e.type = EntryType::Symlink;
        std::error_code ec;
        e.link_target = fs::read_symlink(p, ec).string();
    } else if (S_ISREG(st.st_mode)) {
        e.type = EntryType::File;
        e.size = std::uint64_t(st.st_size);
    } else {
        e.type = EntryType::Other;
    }
    return e;
}

std::string clean(std::string s)
{
    std::replace(s.begin(), s.end(), '\\', '/');
    while (!s.empty() && s.front() == '/') s.erase(0, 1);
    while (!s.empty() && s.back() == '/') s.pop_back();
    return s;
}

} // namespace

std::vector<PlanItem> walk_inputs(const std::vector<InputItem> &items, const WriteOptions &opts)
{
    const bool follow = !opts.store_links;
    std::vector<PlanItem> out;
    auto excluded = [&](const std::string &ap) {
        return std::any_of(opts.exclude.begin(), opts.exclude.end(), [&](auto &g) { return glob_match(g, ap); });
    };
    auto push = [&](const fs::path &disk, const std::string &ap) {
        if (excluded(ap)) return false;
        PlanItem it;
        it.archive_path = ap;
        it.disk = disk;
        it.stat = stat_entry(disk, follow);
        it.stat.path = ap;
        if (it.stat.type == EntryType::Other) return false; // sockets, fifos, devices
        out.push_back(std::move(it));
        return true;
    };
    for (const auto &item : items) {
        std::string root = clean(item.archive_path.empty() ? item.source.filename().string() : item.archive_path);
        if (root.empty() || root == "." || root == "..") root = clean(fs::absolute(item.source).lexically_normal().filename().string());
        if (!push(item.source, root)) continue;
        if (out.back().stat.type != EntryType::Directory) continue;
        std::vector<std::pair<std::string, fs::path>> found;
        // Folders on the way down, to cut a link that points back up.
        std::vector<std::pair<dev_t, ino_t>> up;
        if (follow) {
            struct stat st{};
            if (::stat(item.source.c_str(), &st) == 0) up.emplace_back(st.st_dev, st.st_ino);
        }
        std::error_code ec;
        auto opt = follow ? fs::directory_options::follow_directory_symlink : fs::directory_options::none;
        for (fs::recursive_directory_iterator it(item.source, opt | fs::directory_options::skip_permission_denied, ec), end;
             it != end; it.increment(ec)) {
            if (ec) fail(ErrorCode::Io, "cannot read folder: " + ec.message(), item.source.string());
            const auto rel = it->path().lexically_relative(item.source).generic_string();
            const std::string ap = root + "/" + rel;
            if (excluded(ap)) {
                if (it->is_directory()) it.disable_recursion_pending();
                continue;
            }
            if (follow && !up.empty()) {
                struct stat st{};
                if (::stat(it->path().c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                    up.resize(std::size_t(it.depth()) + 1);
                    const std::pair<dev_t, ino_t> id{st.st_dev, st.st_ino};
                    if (std::find(up.begin(), up.end(), id) != up.end()) {
                        it.disable_recursion_pending();
                        continue;
                    }
                    up.push_back(id);
                }
            }
            found.emplace_back(ap, it->path());
        }
        std::sort(found.begin(), found.end());
        for (auto &[ap, disk] : found) push(disk, ap);
    }
    return out;
}

} // namespace detail
} // namespace raye::archive
