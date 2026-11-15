// SPDX-License-Identifier: GPL-3.0-or-later
#include <raye/archive/error.h>
#include <raye/archive/io.h>

#include "bytes.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace raye::archive {

namespace fs = std::filesystem;

void Source::read_exact(std::uint64_t offset, void *buf, std::size_t n) const
{
    if (read_at(offset, buf, n) != n) fail(ErrorCode::Truncated, "unexpected end of archive", name());
}

namespace {

[[noreturn]] void fail_errno(const std::string &what, const std::string &path, int err)
{
    const ErrorCode code = err == ENOENT ? ErrorCode::NotFound : err == ENOSPC ? ErrorCode::NoSpace : ErrorCode::Io;
    fail(code, what + ": " + std::strerror(err), path);
}

class FileSource final : public Source {
public:
    explicit FileSource(const fs::path &p) : path_(p.string())
    {
        fd_ = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd_ < 0) fail_errno("cannot open", path_, errno);
        struct stat st{};
        if (::fstat(fd_, &st) != 0) { int e = errno; ::close(fd_); fail_errno("cannot stat", path_, e); }
        if (S_ISDIR(st.st_mode)) { ::close(fd_); fail(ErrorCode::Io, "is a folder", path_); }
        size_ = std::uint64_t(st.st_size);
    }
    ~FileSource() override { ::close(fd_); }
    std::uint64_t size() const override { return size_; }
    std::string name() const override { return path_; }
    std::size_t read_at(std::uint64_t off, void *buf, std::size_t n) const override
    {
        if (off >= size_) return 0;
        n = std::size_t(std::min<std::uint64_t>(n, size_ - off));
        std::size_t done = 0;
        while (done < n) {
            ssize_t r = ::pread(fd_, static_cast<char *>(buf) + done, n - done, off_t(off + done));
            if (r < 0) {
                if (errno == EINTR) continue;
                fail_errno("read failed", path_, errno);
            }
            if (r == 0) break;
            done += std::size_t(r);
        }
        return done;
    }

private:
    std::string path_;
    int fd_ = -1;
    std::uint64_t size_ = 0;
};

class MemSource final : public Source {
public:
    MemSource(std::vector<std::uint8_t> b, std::string n) : b_(std::move(b)), n_(std::move(n)) {}
    std::uint64_t size() const override { return b_.size(); }
    std::string name() const override { return n_; }
    std::size_t read_at(std::uint64_t off, void *buf, std::size_t n) const override
    {
        if (off >= b_.size()) return 0;
        n = std::size_t(std::min<std::uint64_t>(n, b_.size() - off));
        if (n) std::memcpy(buf, b_.data() + off, n);
        return n;
    }

private:
    std::vector<std::uint8_t> b_;
    std::string n_;
};

class SubSource final : public Source {
public:
    SubSource(std::shared_ptr<Source> b, std::uint64_t off, std::uint64_t len) : b_(std::move(b)), off_(off)
    {
        const std::uint64_t total = b_->size();
        off_ = std::min(off, total);
        len_ = std::min(len, total - off_);
    }
    std::uint64_t size() const override { return len_; }
    std::string name() const override { return b_->name(); }
    std::size_t read_at(std::uint64_t off, void *buf, std::size_t n) const override
    {
        if (off >= len_) return 0;
        n = std::size_t(std::min<std::uint64_t>(n, len_ - off));
        return b_->read_at(off_ + off, buf, n);
    }

private:
    std::shared_ptr<Source> b_;
    std::uint64_t off_, len_ = 0;
};

class ConcatSource final : public Source {
public:
    explicit ConcatSource(const std::vector<fs::path> &parts)
    {
        std::uint64_t at = 0;
        for (const auto &p : parts) {
            auto s = open_file_source(p);
            starts_.push_back(at);
            at += s->size();
            parts_.push_back(std::move(s));
        }
        size_ = at;
        if (!parts.empty()) name_ = parts.front().string();
    }
    std::uint64_t size() const override { return size_; }
    std::string name() const override { return name_; }
    std::size_t read_at(std::uint64_t off, void *buf, std::size_t n) const override
    {
        std::size_t done = 0;
        while (done < n && off < size_) {
            auto it = std::upper_bound(starts_.begin(), starts_.end(), off) - 1;
            const std::size_t i = std::size_t(it - starts_.begin());
            const std::uint64_t in = off - starts_[i];
            std::size_t got = parts_[i]->read_at(in, static_cast<char *>(buf) + done, n - done);
            if (got == 0) break;
            done += got;
            off += got;
        }
        return done;
    }

private:
    std::vector<std::unique_ptr<Source>> parts_;
    std::vector<std::uint64_t> starts_;
    std::uint64_t size_ = 0;
    std::string name_;
};

class AtomicFileSink final : public Sink {
public:
    AtomicFileSink(const fs::path &p, unsigned mode) : path_(p), mode_(mode)
    {
        fs::path dir = p.parent_path().empty() ? fs::path(".") : p.parent_path();
        tmp_ = (dir / ("." + p.filename().string() + ".XXXXXX")).string();
        fd_ = ::mkostemp(tmp_.data(), O_CLOEXEC);
        if (fd_ < 0) fail_errno("cannot create", p.string(), errno);
    }
    ~AtomicFileSink() override
    {
        if (fd_ >= 0) { ::close(fd_); ::unlink(tmp_.c_str()); }
    }
    void write(const void *data, std::size_t n) override
    {
        const char *p = static_cast<const char *>(data);
        while (n) {
            ssize_t w = ::write(fd_, p, n);
            if (w < 0) {
                if (errno == EINTR) continue;
                fail_errno("write failed", path_.string(), errno);
            }
            p += w;
            n -= std::size_t(w);
        }
    }
    bool rewrite(std::uint64_t off, const void *data, std::size_t n) override
    {
        const char *p = static_cast<const char *>(data);
        while (n) {
            ssize_t w = ::pwrite(fd_, p, n, off_t(off));
            if (w < 0) {
                if (errno == EINTR) continue;
                fail_errno("write failed", path_.string(), errno);
            }
            p += w;
            off += std::uint64_t(w);
            n -= std::size_t(w);
        }
        return true;
    }
    void finish() override
    {
        ::fchmod(fd_, mode_);
        if (::close(fd_) != 0) { fd_ = -1; ::unlink(tmp_.c_str()); fail_errno("close failed", path_.string(), errno); }
        fd_ = -1;
        if (::rename(tmp_.c_str(), path_.c_str()) != 0) { int e = errno; ::unlink(tmp_.c_str()); fail_errno("cannot rename", path_.string(), e); }
    }

private:
    fs::path path_;
    std::string tmp_;
    unsigned mode_;
    int fd_ = -1;
};

class VolumeSink final : public Sink {
public:
    VolumeSink(const fs::path &p, std::uint64_t vol) : base_(p.string()), vol_(vol)
    {
        if (vol == 0) fail(ErrorCode::InvalidOption, "volume size must be more than 0");
    }
    void write(const void *data, std::size_t n) override
    {
        const char *p = static_cast<const char *>(data);
        while (n) {
            if (!cur_ || in_cur_ == vol_) next();
            std::size_t take = std::size_t(std::min<std::uint64_t>(n, vol_ - in_cur_));
            cur_->write(p, take);
            in_cur_ += take;
            p += take;
            n -= take;
        }
    }
    bool rewrite(std::uint64_t off, const void *data, std::size_t n) override
    {
        const char *p = static_cast<const char *>(data);
        while (n) {
            const std::uint64_t vi = off / vol_;
            Sink *s = vi < done_.size() ? done_[vi].get() : vi == done_.size() ? cur_.get() : nullptr;
            const std::size_t take = std::size_t(std::min<std::uint64_t>(n, vol_ - off % vol_));
            if (!s || !s->rewrite(off % vol_, p, take)) return false;
            p += take;
            off += take;
            n -= take;
        }
        return true;
    }
    void finish() override
    {
        if (!cur_) next();
        for (auto &s : done_) s->finish();
        cur_->finish();
    }

private:
    void next()
    {
        if (cur_) done_.push_back(std::move(cur_));
        std::string num = std::to_string(++count_);
        while (num.size() < 3) num.insert(num.begin(), '0');
        cur_ = atomic_file_sink(base_ + "." + num);
        in_cur_ = 0;
    }
    std::string base_;
    std::uint64_t vol_, in_cur_ = 0;
    unsigned count_ = 0;
    std::unique_ptr<Sink> cur_;
    std::vector<std::unique_ptr<Sink>> done_;
};

} // namespace

std::unique_ptr<Source> open_file_source(const fs::path &p) { return std::make_unique<FileSource>(p); }
std::unique_ptr<Source> memory_source(std::vector<std::uint8_t> b, std::string n)
{
    return std::make_unique<MemSource>(std::move(b), std::move(n));
}
std::unique_ptr<Source> sub_source(std::shared_ptr<Source> b, std::uint64_t off, std::uint64_t len)
{
    return std::make_unique<SubSource>(std::move(b), off, len);
}
std::unique_ptr<Source> concat_source(const std::vector<fs::path> &parts) { return std::make_unique<ConcatSource>(parts); }
std::unique_ptr<Sink> atomic_file_sink(const fs::path &p, unsigned mode) { return std::make_unique<AtomicFileSink>(p, mode); }
std::unique_ptr<Sink> volume_sink(const fs::path &p, std::uint64_t v) { return std::make_unique<VolumeSink>(p, v); }

void MemorySink::write(const void *data, std::size_t n)
{
    const auto *p = static_cast<const std::uint8_t *>(data);
    bytes_.insert(bytes_.end(), p, p + n);
}

bool MemorySink::rewrite(std::uint64_t offset, const void *data, std::size_t n)
{
    if (offset > bytes_.size() || n > bytes_.size() - offset) return false;
    std::memcpy(bytes_.data() + offset, data, n);
    return true;
}

// ---------------------------------------------------------------- detail

namespace detail {

std::uint64_t ByteReader::vint()
{
    std::uint64_t v = 0;
    for (int shift = 0; shift < 70; shift += 7) {
        const std::uint8_t b = u8();
        v |= std::uint64_t(b & 0x7f) << shift;
        if (!(b & 0x80)) return v;
    }
    fail(ErrorCode::Corrupt, "bad variable-length number in header");
}

SourceReader::SourceReader(const Source &src, std::uint64_t start, std::uint64_t end, std::size_t buffer)
    : src_(src), pos_(start), end_(std::min(end, src.size())), buf_(std::max<std::size_t>(buffer, 16))
{
    if (pos_ > end_) pos_ = end_;
}

void SourceReader::seek(std::uint64_t p)
{
    if (p > end_) fail(ErrorCode::Corrupt, "offset past the end of the archive", src_.name());
    pos_ = p;
}

void SourceReader::fill()
{
    if (pos_ >= buf_pos_ && pos_ < buf_pos_ + buf_len_) return;
    buf_pos_ = pos_;
    const std::size_t want = std::size_t(std::min<std::uint64_t>(buf_.size(), end_ - pos_));
    buf_len_ = src_.read_at(pos_, buf_.data(), want);
}

std::span<const std::uint8_t> SourceReader::peek()
{
    if (pos_ >= end_) return {};
    fill();
    const std::size_t off = std::size_t(pos_ - buf_pos_);
    if (off >= buf_len_) return {};
    return {buf_.data() + off, buf_len_ - off};
}

void SourceReader::consume(std::size_t n)
{
    if (n > left()) fail(ErrorCode::Internal, "consume past end");
    pos_ += n;
}

std::size_t SourceReader::read(void *out, std::size_t n)
{
    std::size_t done = 0;
    auto *o = static_cast<std::uint8_t *>(out);
    while (done < n) {
        if (n - done >= buf_.size() && pos_ < end_) { // big read: skip the buffer
            std::size_t want = std::size_t(std::min<std::uint64_t>(n - done, end_ - pos_));
            std::size_t got = src_.read_at(pos_, o + done, want);
            pos_ += got;
            done += got;
            if (got < want) break;
            continue;
        }
        auto s = peek();
        if (s.empty()) break;
        std::size_t take = std::min(s.size(), n - done);
        std::memcpy(o + done, s.data(), take);
        pos_ += take;
        done += take;
    }
    return done;
}

void SourceReader::read_exact(void *out, std::size_t n)
{
    if (read(out, n) != n) fail(ErrorCode::Truncated, "unexpected end of archive", src_.name());
}

std::vector<std::uint8_t> SourceReader::read_vec(std::size_t n)
{
    check_alloc(n, src_.size());
    std::vector<std::uint8_t> v(n);
    read_exact(v.data(), n);
    return v;
}

void check_alloc(std::uint64_t wanted, std::uint64_t archive_size, std::uint64_t slack)
{
    if (wanted > archive_size + slack)
        fail(ErrorCode::Corrupt, "header asks for " + std::to_string(wanted) + " bytes, more than the archive holds");
}

} // namespace detail
} // namespace raye::archive
