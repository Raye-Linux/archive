// SPDX-License-Identifier: GPL-3.0-or-later
#include "stream.h"

#include "lzw.h"

#include "../../core/bytes.h"
#include "../../core/checksum.h"
#include "../../core/codec.h"
#include "../../core/context.h"

#include <bzlib.h>
#include <lzma.h>
#include <zlib.h>
#include <zstd.h>
#include <zstd_errors.h>

#include <algorithm>
#include <cstring>
#include <condition_variable>
#include <deque>
#include <exception>
#include <mutex>
#include <thread>
#include <fstream>
#include <future>
#include <unistd.h>

namespace raye::archive::detail {

namespace {

constexpr std::size_t kInBuf = 1 << 18;

[[noreturn]] void damaged(const char *what) { fail(ErrorCode::Corrupt, std::string(what) + " data is damaged"); }
[[noreturn]] void ends_early() { fail(ErrorCode::Truncated, "compressed data ends early"); }

std::uint64_t cgroup_limit()
{
    std::ifstream cg("/proc/self/cgroup");
    std::string line, path;
    while (std::getline(cg, line))
        if (line.rfind("0::", 0) == 0) path = line.substr(3);
    if (path.empty()) return UINT64_MAX;
    std::ifstream f("/sys/fs/cgroup" + path + "/memory.max");
    std::string v;
    if (!(f >> v) || v == "max") return UINT64_MAX;
    try { return std::stoull(v); } catch (...) { return UINT64_MAX; }
}

} // namespace

std::uint64_t memory_budget()
{
    static const std::uint64_t budget = [] {
        std::uint64_t phys = std::uint64_t(::sysconf(_SC_PHYS_PAGES)) * std::uint64_t(::sysconf(_SC_PAGESIZE));
        phys = std::min(phys, cgroup_limit());
        return std::clamp<std::uint64_t>(phys / 4, 256ull << 20, 4ull << 30);
    }();
    return budget;
}

std::uint64_t decode_memlimit() { return 1600ull << 20; } // xz dictionaries stop at 1.5 GiB

void InStream::read_exact(void *buf, std::size_t n)
{
    auto *p = static_cast<std::uint8_t *>(buf);
    while (n) {
        std::size_t r = read(p, n);
        if (!r) fail(ErrorCode::Truncated, "archive ends in the middle of an entry");
        p += r;
        n -= r;
    }
}

std::uint64_t InStream::skip(std::uint64_t n) { return skip_impl(n); }

std::uint64_t InStream::skip_impl(std::uint64_t n)
{
    std::uint8_t buf[1 << 15];
    std::uint64_t done = 0;
    while (done < n) {
        std::size_t r = read(buf, std::size_t(std::min<std::uint64_t>(sizeof buf, n - done)));
        if (!r) break;
        done += r;
    }
    return done;
}

namespace {

// ---------------------------------------------------------------- plain bytes
class RangeStream final : public InStream {
public:
    RangeStream(const Source &s, std::uint64_t start) : s_(s), off_(start) {}
    std::size_t read(void *buf, std::size_t n) override
    {
        std::size_t r = s_.read_at(off_, buf, n);
        off_ += r;
        pos_ += r;
        return r;
    }
    bool can_seek() const override { return true; }

protected:
    std::uint64_t skip_impl(std::uint64_t n) override
    {
        const std::uint64_t left = s_.size() > off_ ? s_.size() - off_ : 0;
        n = std::min(n, left);
        off_ += n;
        pos_ += n;
        return n;
    }

private:
    const Source &s_;
    std::uint64_t off_;
};

// ---------------------------------------------------------------- gzip
// Our own member parser over raw inflate: several members, FNAME, and the
// zero padding some tools leave after the last one.
class GzipStream final : public InStream {
public:
    GzipStream(const Source &s, std::uint64_t start) : in_(s, start, s.size(), kInBuf)
    {
        if (inflateInit2(&z_, -15) != Z_OK) fail(ErrorCode::Internal, "zlib init failed");
        try {
            member();
        } catch (...) {
            inflateEnd(&z_); // the destructor does not run when the constructor throws
            throw;
        }
    }
    ~GzipStream() override { inflateEnd(&z_); }

    std::size_t read(void *buf, std::size_t n) override
    {
        while (!end_) {
            auto view = in_.peek();
            if (view.empty()) ends_early();
            z_.next_in = const_cast<Bytef *>(view.data());
            z_.avail_in = uInt(std::min<std::size_t>(view.size(), 1u << 30));
            z_.next_out = static_cast<Bytef *>(buf);
            z_.avail_out = uInt(std::min<std::size_t>(n, 1u << 30));
            const uInt ai = z_.avail_in, ao = z_.avail_out;
            const int r = inflate(&z_, Z_NO_FLUSH);
            in_.consume(ai - z_.avail_in);
            const std::size_t got = ao - z_.avail_out;
            crc_ = crc32(crc_, buf, got);
            size_ += got;
            if (r == Z_STREAM_END) {
                trailer();
            } else if (r != Z_OK && !(r == Z_BUF_ERROR && got)) {
                if (r == Z_BUF_ERROR) ends_early();
                damaged("gzip");
            }
            if (got) { pos_ += got; return got; }
        }
        return 0;
    }

private:
    std::uint8_t byte() { std::uint8_t b; in_.read_exact(&b, 1); return b; }
    void member()
    {
        std::uint8_t h[10];
        in_.read_exact(h, 10);
        if (h[0] != 0x1f || h[1] != 0x8b) damaged("gzip");
        if (h[2] != 8) fail(ErrorCode::UnsupportedMethod, "gzip member uses an unknown method");
        const std::uint8_t flg = h[3];
        if (flg & 0xe0) damaged("gzip");
        if (flg & 4) {
            std::uint8_t x[2];
            in_.read_exact(x, 2);
            std::uint16_t len = le16(x);
            while (len--) byte();
        }
        if (flg & 8) while (byte()) {}
        if (flg & 16) while (byte()) {}
        if (flg & 2) { byte(); byte(); }
        inflateReset(&z_);
        crc_ = 0;
        size_ = 0;
    }
    void trailer()
    {
        std::uint8_t t[8];
        in_.read_exact(t, 8);
        if (le32(t) != crc_) fail(ErrorCode::Checksum, "gzip data does not match its CRC");
        if (le32(t + 4) != std::uint32_t(size_)) fail(ErrorCode::Checksum, "gzip size does not match its trailer");
        auto view = in_.peek();
        if (view.size() >= 2 && view[0] == 0x1f && view[1] == 0x8b) member();
        else end_ = true; // end, or padding/garbage after the last member (gzip ignores it too)
    }

    SourceReader in_;
    z_stream z_{};
    std::uint32_t crc_ = 0;
    std::uint64_t size_ = 0;
    bool end_ = false;
};

// ---------------------------------------------------------------- bzip2
class Bz2Stream final : public InStream {
public:
    Bz2Stream(const Source &s, std::uint64_t start) : in_(s, start, s.size(), kInBuf) { init(); }
    ~Bz2Stream() override { BZ2_bzDecompressEnd(&b_); }
    std::size_t read(void *buf, std::size_t n) override
    {
        while (!end_) {
            auto view = in_.peek();
            if (view.empty()) ends_early();
            b_.next_in = reinterpret_cast<char *>(const_cast<std::uint8_t *>(view.data()));
            b_.avail_in = unsigned(std::min<std::size_t>(view.size(), 1u << 30));
            b_.next_out = static_cast<char *>(buf);
            b_.avail_out = unsigned(std::min<std::size_t>(n, 1u << 30));
            const unsigned ai = b_.avail_in, ao = b_.avail_out;
            const int r = BZ2_bzDecompress(&b_);
            in_.consume(ai - b_.avail_in);
            const std::size_t got = ao - b_.avail_out;
            if (r == BZ_STREAM_END) {
                auto next = in_.peek();
                if (next.size() >= 4 && next[0] == 'B' && next[1] == 'Z' && next[2] == 'h') {
                    BZ2_bzDecompressEnd(&b_);
                    init();
                } else {
                    end_ = true;
                }
            } else if (r != BZ_OK) {
                damaged("bzip2");
            }
            if (got) { pos_ += got; return got; }
        }
        return 0;
    }

private:
    void init()
    {
        b_ = {};
        if (BZ2_bzDecompressInit(&b_, 0, 0) != BZ_OK) fail(ErrorCode::Internal, "bzip2 init failed");
    }
    SourceReader in_;
    bz_stream b_{};
    bool end_ = false;
};

// ---------------------------------------------------------------- xz
// liblzma's threaded decoder: blocks of a multithreaded .xz decode in parallel.
class XzStream final : public InStream {
public:
    XzStream(const Source &s, std::uint64_t start, int threads) : in_(s, start, s.size(), kInBuf)
    {
        lzma_mt mt{};
        mt.flags = LZMA_CONCATENATED;
        mt.threads = std::uint32_t(std::max(1, threads));
        mt.memlimit_threading = memory_budget();
        mt.memlimit_stop = decode_memlimit();
        if (lzma_stream_decoder_mt(&s_, &mt) != LZMA_OK) fail(ErrorCode::Internal, "liblzma init failed");
    }
    ~XzStream() override { lzma_end(&s_); }
    std::size_t read(void *buf, std::size_t n) override
    {
        while (!end_) {
            auto view = in_.peek();
            s_.next_in = view.data();
            s_.avail_in = view.size();
            s_.next_out = static_cast<std::uint8_t *>(buf);
            s_.avail_out = n;
            const lzma_ret r = lzma_code(&s_, view.empty() ? LZMA_FINISH : LZMA_RUN);
            in_.consume(view.size() - s_.avail_in);
            const std::size_t got = n - s_.avail_out;
            if (r == LZMA_STREAM_END) end_ = true;
            else if (r == LZMA_BUF_ERROR) ends_early();
            else if (r == LZMA_MEMLIMIT_ERROR) fail(ErrorCode::Corrupt, "xz file asks for more memory than allowed");
            else if (r == LZMA_MEM_ERROR) fail(ErrorCode::Internal, "not enough memory for xz");
            else if (r == LZMA_OPTIONS_ERROR) fail(ErrorCode::UnsupportedMethod, "xz file uses unsupported settings");
            else if (r == LZMA_DATA_ERROR && got == 0 && s_.total_out == 0) damaged("xz");
            else if (r != LZMA_OK) damaged("xz");
            if (got) { pos_ += got; return got; }
        }
        return 0;
    }

private:
    SourceReader in_;
    lzma_stream s_ = LZMA_STREAM_INIT;
    bool end_ = false;
};

// ---------------------------------------------------------------- .lzma
// liblzma directly, for its memory limit: a 4 GiB dictionary in a 45-byte
// file must not turn into a 4 GiB allocation.
class LzmaAloneStream final : public InStream {
public:
    LzmaAloneStream(const Source &s, std::uint64_t start) : in_(s, start, s.size(), kInBuf)
    {
        if (lzma_alone_decoder(&s_, decode_memlimit()) != LZMA_OK) fail(ErrorCode::Internal, "liblzma init failed");
    }
    ~LzmaAloneStream() override { lzma_end(&s_); }
    std::size_t read(void *buf, std::size_t n) override
    {
        while (!end_) {
            auto view = in_.peek();
            s_.next_in = view.data();
            s_.avail_in = view.size();
            s_.next_out = static_cast<std::uint8_t *>(buf);
            s_.avail_out = n;
            const lzma_ret r = lzma_code(&s_, view.empty() ? LZMA_FINISH : LZMA_RUN);
            in_.consume(view.size() - s_.avail_in);
            const std::size_t got = n - s_.avail_out;
            if (r == LZMA_STREAM_END) end_ = true;
            else if (r == LZMA_BUF_ERROR) ends_early();
            else if (r == LZMA_MEMLIMIT_ERROR) fail(ErrorCode::Corrupt, "LZMA dictionary is bigger than allowed");
            else if (r != LZMA_OK) damaged("LZMA");
            if (got) { pos_ += got; return got; }
        }
        return 0;
    }

private:
    SourceReader in_;
    lzma_stream s_ = LZMA_STREAM_INIT;
    bool end_ = false;
};

// ---------------------------------------------------------------- zstd
class ZstdStream final : public InStream {
public:
    ZstdStream(const Source &s, std::uint64_t start) : in_(s, start, s.size(), kInBuf), d_(ZSTD_createDStream())
    {
        if (!d_) fail(ErrorCode::Internal, "zstd init failed");
        int wlog = 10;
        while (wlog < 31 && (2ull << wlog) <= decode_memlimit()) ++wlog;
        ZSTD_DCtx_setParameter(d_, ZSTD_d_windowLogMax, wlog);
    }
    ~ZstdStream() override { ZSTD_freeDStream(d_); }
    std::size_t read(void *buf, std::size_t n) override
    {
        for (;;) {
            auto view = in_.peek();
            if (view.empty()) {
                if (mid_frame_) ends_early();
                return 0;
            }
            ZSTD_inBuffer ib{view.data(), view.size(), 0};
            ZSTD_outBuffer ob{buf, n, 0};
            const size_t r = ZSTD_decompressStream(d_, &ob, &ib);
            in_.consume(ib.pos);
            if (ZSTD_isError(r)) {
                if (ZSTD_getErrorCode(r) == ZSTD_error_frameParameter_windowTooLarge)
                    fail(ErrorCode::Corrupt, "zstd file asks for more memory than allowed");
                damaged("zstd");
            }
            mid_frame_ = r != 0;
            if (ob.pos) { pos_ += ob.pos; return ob.pos; }
        }
    }

private:
    SourceReader in_;
    ZSTD_DStream *d_;
    bool mid_frame_ = false;
};

// ---------------------------------------------------------------- core coders
class CoderStream final : public InStream {
public:
    CoderStream(const Source &s, std::uint64_t start, Codec c) : in_(s, start, s.size(), kInBuf), dec_(make_decoder(c)) {}
    std::size_t read(void *buf, std::size_t n) override
    {
        while (!end_) {
            auto view = in_.peek();
            const bool finish = view.size() == in_.left();
            auto st = dec_->step(view, {static_cast<std::uint8_t *>(buf), n}, finish);
            in_.consume(st.consumed);
            if (st.done) end_ = true;
            else if (!st.consumed && !st.produced && finish) ends_early();
            if (st.produced) { pos_ += st.produced; return st.produced; }
        }
        return 0;
    }

private:
    SourceReader in_;
    std::unique_ptr<Coder> dec_;
    bool end_ = false;
};

// ---------------------------------------------------------------- lzip
// Members of "LZIP" ver dict-code, an LZMA stream with end marker
// (lc=3 lp=0 pb=2), and a 20-byte trailer: CRC32, data size, member size.
std::uint32_t lzip_dict(std::uint8_t code)
{
    const std::uint32_t base = 1u << (code & 0x1f);
    return base - (base / 16) * ((code >> 5) & 7);
}

class LzipStream final : public InStream {
public:
    LzipStream(const Source &s, std::uint64_t start) : in_(s, start, s.size(), kInBuf) { member(); }
    std::size_t read(void *buf, std::size_t n) override
    {
        while (!end_) {
            auto view = in_.peek();
            if (view.empty()) ends_early();
            auto st = dec_->step(view, {static_cast<std::uint8_t *>(buf), n}, false);
            in_.consume(st.consumed);
            crc_ = crc32(crc_, buf, st.produced);
            size_ += st.produced;
            if (st.done) trailer();
            else if (!st.consumed && !st.produced) ends_early();
            if (st.produced) { pos_ += st.produced; return st.produced; }
        }
        return 0;
    }

private:
    void member()
    {
        member_start_ = in_.pos();
        std::uint8_t h[6];
        in_.read_exact(h, 6);
        if (std::memcmp(h, "LZIP", 4) != 0) damaged("lzip");
        if (h[4] != 1) fail(ErrorCode::UnsupportedMethod, "lzip version " + std::to_string(h[4]) + " is not supported");
        const std::uint32_t dict = lzip_dict(h[5]);
        if (dict < (1u << 12) || dict > (1u << 29)) damaged("lzip");
        CodecParams p;
        p.props = {0x5d, 0, 0, 0, 0};
        put_le32(&p.props[1], dict);
        dec_ = make_decoder(Codec::Lzma1Raw, p);
        crc_ = 0;
        size_ = 0;
    }
    void trailer()
    {
        std::uint8_t t[20];
        in_.read_exact(t, 20);
        if (le32(t) != crc_) fail(ErrorCode::Checksum, "lzip data does not match its CRC");
        if (le64(t + 4) != size_) fail(ErrorCode::Checksum, "lzip size does not match its trailer");
        if (le64(t + 12) != in_.pos() - member_start_) damaged("lzip");
        auto view = in_.peek();
        if (view.size() >= 4 && std::memcmp(view.data(), "LZIP", 4) == 0) member();
        else end_ = true;
    }
    SourceReader in_;
    std::unique_ptr<Coder> dec_;
    std::uint32_t crc_ = 0;
    std::uint64_t size_ = 0, member_start_ = 0;
    bool end_ = false;
};

// ---------------------------------------------------------------- .Z
class LzwStream final : public InStream {
public:
    LzwStream(const Source &s, std::uint64_t start) : in_(s, start, s.size(), kInBuf)
    {
        std::uint8_t h[3];
        in_.read_exact(h, 3);
        if (h[0] != 0x1f || h[1] != 0x9d) damaged(".Z");
        dec_ = std::make_unique<LzwDecoder>(h[2]);
    }
    std::size_t read(void *buf, std::size_t n) override
    {
        for (;;) {
            auto view = in_.peek();
            std::size_t used = 0;
            std::size_t got = dec_->decode(view, used, static_cast<std::uint8_t *>(buf), n, view.empty());
            in_.consume(used);
            if (got) { pos_ += got; return got; }
            if (view.empty()) return 0;
        }
    }

private:
    SourceReader in_;
    std::unique_ptr<LzwDecoder> dec_;
};

} // namespace

namespace {

// Decodes ahead on its own thread in 1 MiB chunks, so the reader (tar
// parsing, writing files) and the decoder run side by side, and small
// reads (tar headers) cost a memcpy instead of a decoder call.
class AheadStream final : public InStream {
public:
    explicit AheadStream(std::unique_ptr<InStream> base) : base_(std::move(base))
    {
        worker_ = std::thread([this] { run(); });
    }
    ~AheadStream() override
    {
        {
            std::lock_guard l(m_);
            stop_ = true;
        }
        cv_.notify_all();
        worker_.join();
    }
    std::size_t read(void *out, std::size_t n) override
    {
        while (at_ == cur_.size()) {
            std::unique_lock l(m_);
            if (!cur_.empty()) free_.push_back(std::move(cur_));
            cur_.clear();
            at_ = 0;
            cv_.notify_all();
            cv_.wait(l, [this] { return !full_.empty() || done_; });
            if (full_.empty()) {
                if (error_) std::rethrow_exception(error_);
                return 0;
            }
            cur_ = std::move(full_.front());
            full_.pop_front();
        }
        const std::size_t k = std::min(n, cur_.size() - at_);
        std::memcpy(out, cur_.data() + at_, k);
        at_ += k;
        pos_ += k;
        return k;
    }

private:
    void run()
    {
        try {
            for (;;) {
                std::vector<std::uint8_t> b;
                {
                    std::unique_lock l(m_);
                    cv_.wait(l, [this] { return stop_ || full_.size() < 4; });
                    if (stop_) break;
                    if (!free_.empty()) { b = std::move(free_.back()); free_.pop_back(); }
                }
                b.resize(1 << 20);
                std::size_t got = 0;
                while (got < b.size()) {
                    const std::size_t r = base_->read(b.data() + got, b.size() - got);
                    if (!r) break;
                    got += r;
                }
                b.resize(got);
                std::lock_guard l(m_);
                if (got) full_.push_back(std::move(b));
                if (got < (1u << 20)) break;
                cv_.notify_all();
            }
        } catch (...) {
            std::lock_guard l(m_);
            error_ = std::current_exception();
        }
        std::lock_guard l(m_);
        done_ = true;
        cv_.notify_all();
    }

    std::unique_ptr<InStream> base_;
    std::thread worker_;
    std::mutex m_;
    std::condition_variable cv_;
    std::deque<std::vector<std::uint8_t>> full_, free_;
    std::vector<std::uint8_t> cur_;
    std::size_t at_ = 0;
    bool stop_ = false, done_ = false;
    std::exception_ptr error_;
};

std::unique_ptr<InStream> open_raw(Format f, const Source &src, std::uint64_t start, int threads);

} // namespace

bool is_stream_format(Format f)
{
    switch (f) {
    case Format::Gzip: case Format::Bzip2: case Format::Xz: case Format::Lzma: case Format::Zstd:
    case Format::Lz4: case Format::Lzip: case Format::Brotli: case Format::Compress: return true;
    default: return false;
    }
}

std::unique_ptr<InStream> open_stream(Format f, const Source &src, std::uint64_t start, int threads, Context *)
{
    if (f == Format::Tar) return open_raw(f, src, start, threads);
    return std::make_unique<AheadStream>(open_raw(f, src, start, threads));
}

namespace {

std::unique_ptr<InStream> open_raw(Format f, const Source &src, std::uint64_t start, int threads)
{
    switch (f) {
    case Format::Tar: return std::make_unique<RangeStream>(src, start);
    case Format::Gzip: return std::make_unique<GzipStream>(src, start);
    case Format::Bzip2: return open_bzip2_parallel(src, start, threads);
    case Format::Xz: return std::make_unique<XzStream>(src, start, threads);
    case Format::Lzma: return std::make_unique<LzmaAloneStream>(src, start);
    case Format::Zstd: return std::make_unique<ZstdStream>(src, start);
    case Format::Lz4: return std::make_unique<CoderStream>(src, start, Codec::Lz4Frame);
    case Format::Brotli: return std::make_unique<CoderStream>(src, start, Codec::Brotli);
    case Format::Lzip: return std::make_unique<LzipStream>(src, start);
    case Format::Compress: return std::make_unique<LzwStream>(src, start);
    default: fail(ErrorCode::Internal, "not a stream format");
    }
}

} // namespace

std::unique_ptr<InStream> open_bzip2_serial(const Source &src, std::uint64_t start)
{
    return std::make_unique<Bz2Stream>(src, start);
}

// ---------------------------------------------------------------- metadata

namespace {

// Sum of the uncompressed sizes in the indexes of every stream, walking
// back from the end. Fails quietly (returns false) on anything odd.
bool xz_size(const Source &src, std::uint64_t start, std::uint64_t &out)
{
    std::uint64_t end = src.size(), total = 0;
    while (end > start) {
        if (end - start < 24) return false;
        std::uint8_t pad[4];
        src.read_exact(end - 4, pad, 4);
        if (!pad[0] && !pad[1] && !pad[2] && !pad[3]) { end -= 4; continue; }
        std::uint8_t foot[12];
        src.read_exact(end - 12, foot, 12);
        lzma_stream_flags flags;
        if (lzma_stream_footer_decode(&flags, foot) != LZMA_OK) return false;
        if (flags.backward_size > end - start - 24 || flags.backward_size > (64u << 20)) return false;
        std::vector<std::uint8_t> idx(flags.backward_size);
        src.read_exact(end - 12 - flags.backward_size, idx.data(), idx.size());
        lzma_index *i = nullptr;
        std::uint64_t memlimit = 256u << 20;
        std::size_t ipos = 0;
        if (lzma_index_buffer_decode(&i, &memlimit, nullptr, idx.data(), &ipos, idx.size()) != LZMA_OK) return false;
        total += lzma_index_uncompressed_size(i);
        const std::uint64_t ssize = lzma_index_stream_size(i);
        lzma_index_end(i, nullptr);
        if (ssize > end - start) return false;
        end -= ssize;
    }
    out = total;
    return true;
}

bool lzip_size(const Source &src, std::uint64_t start, std::uint64_t &out)
{
    std::uint64_t end = src.size(), total = 0;
    while (end > start) {
        if (end - start < 26) return false;
        std::uint8_t t[20];
        src.read_exact(end - 20, t, 20);
        const std::uint64_t msize = le64(t + 12);
        if (msize < 26 || msize > end - start) return false;
        std::uint8_t h[4];
        src.read_exact(end - msize, h, 4);
        if (std::memcmp(h, "LZIP", 4) != 0) return false;
        total += le64(t + 4);
        end -= msize;
    }
    out = total;
    return true;
}

} // namespace

StreamMeta stream_meta(Format f, const Source &src, std::uint64_t start)
{
    StreamMeta m;
    const std::uint64_t size = src.size();
    try {
        if (f == Format::Gzip && size >= start + 18) {
            std::uint8_t h[10];
            src.read_exact(start, h, 10);
            m.mtime = le32(h + 4);
            std::uint64_t p = start + 10;
            if (h[3] & 4) {
                std::uint8_t x[2];
                src.read_exact(p, x, 2);
                p += 2 + le16(x);
            }
            if (h[3] & 8) {
                std::string name;
                std::uint8_t c;
                while (name.size() < 4096 && src.read_at(p++, &c, 1) == 1 && c) name.push_back(char(c));
                m.name = name;
            }
            std::uint8_t t[4];
            src.read_exact(size - 4, t, 4);
            m.size = le32(t); // modulo 4 GiB, and only the last member: a hint
        } else if (f == Format::Zstd) {
            std::uint8_t h[32];
            const std::size_t n = src.read_at(start, h, sizeof h);
            const unsigned long long fcs = ZSTD_getFrameContentSize(h, n);
            if (fcs != ZSTD_CONTENTSIZE_UNKNOWN && fcs != ZSTD_CONTENTSIZE_ERROR) m.size = fcs;
        } else if (f == Format::Xz) {
            m.size_known = xz_size(src, start, m.size);
        } else if (f == Format::Lzip) {
            m.size_known = lzip_size(src, start, m.size);
        } else if (f == Format::Lzma && size >= start + 13) {
            std::uint8_t h[13];
            src.read_exact(start, h, 13);
            const std::uint64_t s = le64(h + 5);
            if (s != UINT64_MAX) { m.size = s; m.size_known = true; }
        }
    } catch (const Error &) {
        m.size_known = false;
    }
    return m;
}


// ================================================================ writing

namespace {

std::uint64_t pick_dict(const WriteOptions &o, std::uint64_t by_level)
{
    return o.dictionary ? o.dictionary : by_level;
}

// Compresses independent blocks on the pool and writes them in order, so
// reading the input and compressing overlap.
class BlockSink : public Sink {
public:
    BlockSink(Sink &out, Context &ctx, std::size_t block, std::size_t inflight)
        : out_(out), ctx_(ctx), block_(block), inflight_(std::max<std::size_t>(1, inflight))
    {
    }
    void write(const void *data, std::size_t n) override
    {
        auto *p = static_cast<const std::uint8_t *>(data);
        while (n) {
            if (cur_.capacity() < block_) cur_.reserve(block_);
            const std::size_t take = std::min(n, block_ - cur_.size());
            cur_.insert(cur_.end(), p, p + take);
            p += take;
            n -= take;
            if (cur_.size() == block_) push(false);
        }
    }
    void finish() override
    {
        push(true);
        while (!jobs_.empty()) drain_one();
        trailer();
    }

protected:
    struct Job {
        std::vector<std::uint8_t> data, dict;
        bool last = false;
    };
    struct Done {
        std::vector<std::uint8_t> bytes;
        std::uint32_t crc = 0;
        std::uint64_t size = 0;
    };
    virtual Done compress(const Job &job) = 0;
    virtual void header() {}
    virtual void trailer() {}
    virtual void after(const Done &) {}
    virtual std::size_t dict_size() const { return 0; } // look-back into the previous block
    Sink &out_;
    Context &ctx_;

private:
    // The newest block waits until we know whether more data follows.
    void push(bool last)
    {
        if (last && held_ && cur_.empty()) {
            held_->last = true;
            submit(std::move(*held_));
            held_.reset();
            return;
        }
        if (held_) { submit(std::move(*held_)); held_.reset(); }
        if (last && cur_.empty() && submitted_) return;
        Job j;
        j.data = std::move(cur_);
        cur_ = {};
        if (const std::size_t d = dict_size()) {
            j.dict = tail_;
            const auto keep = std::min(d, j.data.size());
            tail_.insert(tail_.end(), j.data.end() - std::ptrdiff_t(keep), j.data.end());
            if (tail_.size() > d) tail_.erase(tail_.begin(), tail_.end() - std::ptrdiff_t(d));
        }
        if (last) { j.last = true; submit(std::move(j)); }
        else held_ = std::move(j);
    }
    void submit(Job &&j)
    {
        if (!submitted_) header();
        submitted_ = true;
        ctx_.checkpoint();
        while (jobs_.size() >= inflight_) drain_one();
        auto job = std::make_shared<Job>(std::move(j));
        jobs_.push_back(ctx_.pool().submit([this, job] { return compress(*job); }));
    }
    void drain_one()
    {
        auto fut = std::move(jobs_.front());
        jobs_.pop_front();
        Done d = fut.get();
        out_.write(d.bytes.data(), d.bytes.size());
        after(d);
    }

    std::size_t block_, inflight_;
    std::vector<std::uint8_t> cur_, tail_;
    std::optional<Job> held_;
    std::deque<std::future<Done>> jobs_;
    bool submitted_ = false;
};

// pigz layout: one gzip member whose blocks are deflated on their own, with
// the previous 32 KiB as dictionary, and joined at byte boundaries.
class GzipSink final : public BlockSink {
public:
    GzipSink(Sink &out, Context &ctx, int level, std::string name, std::int64_t mtime)
        : BlockSink(out, ctx, 1 << 20, std::size_t(ctx.threads()) * 2), level_(std::clamp(level, 0, 9)),
          name_(std::move(name)), mtime_(mtime)
    {
    }

protected:
    std::size_t dict_size() const override { return 32768; }
    void header() override
    {
        std::vector<std::uint8_t> h = {0x1f, 0x8b, 8, std::uint8_t(name_.empty() ? 0 : 8), 0, 0, 0, 0,
                                       std::uint8_t(level_ >= 9 ? 2 : level_ <= 1 ? 4 : 0), 3};
        if (mtime_ > 0 && mtime_ < (std::int64_t(1) << 32)) put_le32(&h[4], std::uint32_t(mtime_));
        if (!name_.empty()) { h.insert(h.end(), name_.begin(), name_.end()); h.push_back(0); }
        out_.write(h.data(), h.size());
    }
    Done compress(const Job &j) override
    {
        z_stream z{};
        if (deflateInit2(&z, level_, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) != Z_OK) fail(ErrorCode::Internal, "zlib init failed");
        if (!j.dict.empty()) deflateSetDictionary(&z, j.dict.data(), uInt(j.dict.size()));
        Done d;
        d.bytes.resize(deflateBound(&z, uLong(j.data.size())) + 64);
        z.next_in = const_cast<Bytef *>(j.data.data());
        z.avail_in = uInt(j.data.size());
        z.next_out = d.bytes.data();
        z.avail_out = uInt(d.bytes.size());
        const int r = deflate(&z, j.last ? Z_FINISH : Z_SYNC_FLUSH);
        d.bytes.resize(d.bytes.size() - z.avail_out);
        deflateEnd(&z);
        if (r != (j.last ? Z_STREAM_END : Z_OK)) fail(ErrorCode::Internal, "deflate failed");
        d.crc = crc32(0, j.data.data(), j.data.size());
        d.size = j.data.size();
        return d;
    }
    void after(const Done &d) override
    {
        crc_ = total_ ? crc32_combine(crc_, d.crc, d.size) : d.crc;
        total_ += d.size;
    }
    void trailer() override
    {
        std::uint8_t t[8];
        put_le32(t, crc_);
        put_le32(t + 4, std::uint32_t(total_));
        out_.write(t, 8);
    }

private:
    int level_;
    std::string name_;
    std::int64_t mtime_;
    std::uint32_t crc_ = 0;
    std::uint64_t total_ = 0;
};

// Complete bzip2 streams back to back (what pbzip2/lbzip2 write).
class Bzip2Sink final : public BlockSink {
public:
    Bzip2Sink(Sink &out, Context &ctx, int level)
        : BlockSink(out, ctx, std::size_t(std::clamp(level, 1, 9)) * 100000 - 1000, std::size_t(ctx.threads()) * 2),
          level_(std::clamp(level, 1, 9))
    {
    }

protected:
    Done compress(const Job &j) override
    {
        Done d;
        unsigned n = unsigned(j.data.size() + j.data.size() / 100 + 1024);
        d.bytes.resize(n);
        const int r = BZ2_bzBuffToBuffCompress(reinterpret_cast<char *>(d.bytes.data()), &n,
                                               const_cast<char *>(reinterpret_cast<const char *>(j.data.data())),
                                               unsigned(j.data.size()), level_, 0, 0);
        if (r != BZ_OK) fail(ErrorCode::Internal, "bzip2 failed");
        d.bytes.resize(n);
        return d;
    }

private:
    int level_;
};

// lzip members compressed in parallel (what plzip does).
class LzipSink final : public BlockSink {
public:
    LzipSink(Sink &out, Context &ctx, const WriteOptions &o, std::uint32_t dict, std::size_t member, std::size_t inflight)
        : BlockSink(out, ctx, member, inflight), dict_(dict)
    {
        const int lvl = std::clamp(o.level, 0, 9);
        lzma_lzma_preset(&opt_, std::uint32_t(lvl) | (o.level > 9 ? LZMA_PRESET_EXTREME : 0));
        opt_.dict_size = dict_;
        opt_.lc = 3; opt_.lp = 0; opt_.pb = 2;
        if (o.word_size) opt_.nice_len = std::uint32_t(std::clamp(o.word_size, 8, 273));
    }
    static std::uint64_t memusage(const WriteOptions &o, std::uint32_t dict)
    {
        lzma_options_lzma opt{};
        lzma_lzma_preset(&opt, std::uint32_t(std::clamp(o.level, 0, 9)));
        opt.dict_size = dict;
        lzma_filter f[2] = {{LZMA_FILTER_LZMA1, &opt}, {LZMA_VLI_UNKNOWN, nullptr}};
        return lzma_raw_encoder_memusage(f);
    }

protected:
    Done compress(const Job &j) override
    {
        Done d;
        lzma_filter f[2] = {{LZMA_FILTER_LZMA1, const_cast<lzma_options_lzma *>(&opt_)}, {LZMA_VLI_UNKNOWN, nullptr}};
        std::uint8_t code = 0;
        while ((1u << code) < dict_) ++code;
        d.bytes.resize(6 + j.data.size() + j.data.size() / 16 + 4096);
        std::memcpy(d.bytes.data(), "LZIP\x01", 5);
        d.bytes[5] = code;
        std::size_t pos = 6;
        lzma_stream s = LZMA_STREAM_INIT;
        if (lzma_raw_encoder(&s, f) != LZMA_OK) fail(ErrorCode::Internal, "liblzma init failed");
        s.next_in = j.data.data();
        s.avail_in = j.data.size();
        lzma_ret r;
        do {
            if (pos + 4096 > d.bytes.size()) d.bytes.resize(d.bytes.size() * 2);
            s.next_out = d.bytes.data() + pos;
            s.avail_out = d.bytes.size() - pos;
            r = lzma_code(&s, LZMA_FINISH);
            pos = d.bytes.size() - s.avail_out;
        } while (r == LZMA_OK);
        lzma_end(&s);
        if (r != LZMA_STREAM_END) fail(ErrorCode::Internal, "lzip compression failed");
        d.bytes.resize(pos + 20);
        put_le32(&d.bytes[pos], crc32(0, j.data.data(), j.data.size()));
        put_le64(&d.bytes[pos + 4], j.data.size());
        put_le64(&d.bytes[pos + 12], pos + 20);
        return d;
    }

private:
    std::uint32_t dict_;
    lzma_options_lzma opt_{};
};

// .xz with liblzma's threaded encoder; threads are cut to fit in memory.
class XzSink final : public Sink {
public:
    XzSink(Sink &out, const WriteOptions &o, int threads) : out_(out)
    {
        lzma_lzma_preset(&opt_, std::uint32_t(std::clamp(o.level, 0, 9)) | (o.level > 9 ? LZMA_PRESET_EXTREME : 0));
        if (o.dictionary) opt_.dict_size = std::uint32_t(std::clamp<std::uint64_t>(o.dictionary, 4096, 1536u << 20));
        if (o.word_size) opt_.nice_len = std::uint32_t(std::clamp(o.word_size, 8, 273));
        filters_[0] = {LZMA_FILTER_LZMA2, &opt_};
        filters_[1] = {LZMA_VLI_UNKNOWN, nullptr};
        lzma_mt mt{};
        mt.filters = filters_;
        mt.check = LZMA_CHECK_CRC64;
        mt.threads = std::uint32_t(std::max(1, threads));
        while (mt.threads > 1 && lzma_stream_encoder_mt_memusage(&mt) > memory_budget()) --mt.threads;
        const lzma_ret r = mt.threads > 1 ? lzma_stream_encoder_mt(&s_, &mt) : lzma_stream_encoder(&s_, filters_, LZMA_CHECK_CRC64);
        if (r == LZMA_MEM_ERROR) fail(ErrorCode::Internal, "not enough memory for xz");
        if (r != LZMA_OK) fail(ErrorCode::InvalidOption, "xz does not accept these settings");
        buf_.resize(1 << 18);
    }
    ~XzSink() override { lzma_end(&s_); }
    void write(const void *data, std::size_t n) override { run(static_cast<const std::uint8_t *>(data), n, LZMA_RUN); }
    void finish() override { run(nullptr, 0, LZMA_FINISH); }

private:
    void run(const std::uint8_t *p, std::size_t n, lzma_action a)
    {
        s_.next_in = p;
        s_.avail_in = n;
        for (;;) {
            s_.next_out = buf_.data();
            s_.avail_out = buf_.size();
            const lzma_ret r = lzma_code(&s_, a);
            out_.write(buf_.data(), buf_.size() - s_.avail_out);
            if (r == LZMA_STREAM_END) return;
            if (r != LZMA_OK) fail(ErrorCode::Internal, "xz compression failed");
            if (a == LZMA_RUN && s_.avail_in == 0 && s_.avail_out != 0) return;
        }
    }
    Sink &out_;
    lzma_stream s_ = LZMA_STREAM_INIT;
    lzma_options_lzma opt_{};
    lzma_filter filters_[2]{};
    std::vector<std::uint8_t> buf_;
};

// zstd: levels 1-19 from 0-9, 20-22 (ultra) for higher values, a long
// window (--long) when a dictionary size is asked.
class ZstdSink final : public Sink {
public:
    ZstdSink(Sink &out, const WriteOptions &o, int threads) : out_(out), c_(ZSTD_createCCtx())
    {
        if (!c_) fail(ErrorCode::Internal, "zstd init failed");
        static const int map[] = {1, 1, 2, 3, 5, 8, 11, 14, 17, 19};
        const int level = o.level > 9 ? std::min(o.level, 22) : map[std::clamp(o.level, 0, 9)];
        ZSTD_CCtx_setParameter(c_, ZSTD_c_compressionLevel, level);
        ZSTD_CCtx_setParameter(c_, ZSTD_c_checksumFlag, 1);
        // Default window per level (libzstd's table for large inputs).
        int wlog = level <= 2 ? 19 : level <= 7 ? 21 : level <= 16 ? 22 : level <= 19 ? 23 : level == 20 ? 25 : level == 21 ? 26 : 27;
        if (o.dictionary) {
            wlog = 10;
            while (wlog < 31 && (1ull << wlog) < o.dictionary) ++wlog;
            ZSTD_CCtx_setParameter(c_, ZSTD_c_windowLog, wlog);
            ZSTD_CCtx_setParameter(c_, ZSTD_c_enableLongDistanceMatching, 1);
        }
        // A worker holds a few windows plus match tables; the strong levels need more.
        const std::uint64_t per = (level >= 16 ? 8ull : 4ull) << wlog;
        int workers = std::max(1, threads);
        while (workers > 1 && std::uint64_t(workers) * per > memory_budget()) --workers;
        if (workers > 1) ZSTD_CCtx_setParameter(c_, ZSTD_c_nbWorkers, workers);
        buf_.resize(ZSTD_CStreamOutSize());
    }
    ~ZstdSink() override { ZSTD_freeCCtx(c_); }
    void write(const void *data, std::size_t n) override { run(data, n, ZSTD_e_continue); }
    void finish() override { run(nullptr, 0, ZSTD_e_end); }

private:
    void run(const void *p, std::size_t n, ZSTD_EndDirective e)
    {
        ZSTD_inBuffer ib{p, n, 0};
        for (;;) {
            ZSTD_outBuffer ob{buf_.data(), buf_.size(), 0};
            const size_t r = ZSTD_compressStream2(c_, &ob, &ib, e);
            if (ZSTD_isError(r)) fail(ErrorCode::Internal, ZSTD_getErrorName(r));
            out_.write(buf_.data(), ob.pos);
            if (e == ZSTD_e_end ? r == 0 : ib.pos == ib.size) return;
        }
    }
    Sink &out_;
    ZSTD_CCtx *c_;
    std::vector<std::uint8_t> buf_;
};

class CoderSink final : public Sink {
public:
    CoderSink(Sink &out, Codec c, CodecParams p) : out_(out), enc_(make_encoder(c, p)), buf_(1 << 18) {}
    void write(const void *data, std::size_t n) override
    {
        std::span<const std::uint8_t> in{static_cast<const std::uint8_t *>(data), n};
        while (!in.empty()) {
            auto s = enc_->step(in, buf_, false);
            out_.write(buf_.data(), s.produced);
            in = in.subspan(s.consumed);
        }
    }
    void finish() override
    {
        for (;;) {
            auto s = enc_->step({}, buf_, true);
            out_.write(buf_.data(), s.produced);
            if (s.done) return;
        }
    }

private:
    Sink &out_;
    std::unique_ptr<Coder> enc_;
    std::vector<std::uint8_t> buf_;
};

} // namespace

std::unique_ptr<Sink> compress_sink(Format f, Sink &out, const WriteOptions &o, Context &ctx, const std::string &name,
                                    std::int64_t mtime)
{
    const int threads = ctx.threads();
    switch (f) {
    case Format::Gzip: return std::make_unique<GzipSink>(out, ctx, o.level, name, mtime);
    case Format::Bzip2: return std::make_unique<Bzip2Sink>(out, ctx, o.level);
    case Format::Xz: return std::make_unique<XzSink>(out, o, threads);
    case Format::Zstd: return std::make_unique<ZstdSink>(out, o, threads);
    case Format::Lzip: {
        static const std::uint32_t dicts[] = {1u << 18, 1u << 20, 1u << 21, 1u << 22, 1u << 22,
                                              1u << 23, 1u << 23, 1u << 24, 1u << 25, 1u << 26};
        std::uint64_t d = pick_dict(o, dicts[std::clamp(o.level, 0, 9)]);
        d = std::clamp<std::uint64_t>(d, 1u << 12, 1u << 29);
        std::uint32_t dict = 1u << 12;
        while (dict < d) dict <<= 1; // keep it a power of two: the header has no room for odd sizes
        const std::size_t member = std::max<std::size_t>(std::size_t(dict) * 2, 4u << 20);
        const std::uint64_t per = LzipSink::memusage(o, dict) + member * 2;
        const std::size_t inflight = std::size_t(std::clamp<std::uint64_t>(memory_budget() / per, 1, std::uint64_t(threads)));
        return std::make_unique<LzipSink>(out, ctx, o, dict, member, inflight);
    }
    case Format::Lzma: {
        CodecParams p;
        p.level = o.level;
        p.dictionary = o.dictionary;
        p.word_size = o.word_size;
        return std::make_unique<CoderSink>(out, Codec::LzmaAlone, p);
    }
    case Format::Lz4: { CodecParams p; p.level = o.level; return std::make_unique<CoderSink>(out, Codec::Lz4Frame, p); }
    case Format::Brotli: {
        CodecParams p;
        p.level = std::min(o.level, 9);
        p.dictionary = o.dictionary;
        return std::make_unique<CoderSink>(out, Codec::Brotli, p);
    }
    default: fail(ErrorCode::ReadOnlyFormat, std::string(format_name(f)) + " files can be read but not created");
    }
}

} // namespace raye::archive::detail
