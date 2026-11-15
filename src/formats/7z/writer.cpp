// SPDX-License-Identifier: GPL-3.0-or-later
// 7z writer. Folders are compressed on every core: LZMA2 cuts a big folder
// into blocks with a dictionary reset between them (one per thread, glued
// into one LZMA2 stream), and small folders are compressed side by side.
#include "writer.h"

#include "filters.h"
#include "ppmd.h"
#include "reader.h"

#include "../../core/checksum.h"
#include "../../core/codec.h"
#include "../../core/context.h"
#include "../../core/crypto.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <fstream>
#include <future>
#include <map>
#include <sys/stat.h>
#include <lzma.h>
#include <unistd.h>

namespace raye::archive::detail::sevenz {

namespace {

namespace fs = std::filesystem;

constexpr unsigned kAesCycles = 19; // what 7-Zip writes

// ---- output helpers

class CountingSink final : public Sink {
public:
    explicit CountingSink(Sink &s) : s_(s) {}
    void write(const void *d, std::size_t n) override { s_.write(d, n); count += n; }
    std::uint64_t count = 0;

private:
    Sink &s_;
};

// Compressed output of a folder done on a worker: memory first, a
// temporary file once it gets big.
class Spool final : public Sink {
public:
    ~Spool() override { if (f_) std::fclose(f_); }
    void write(const void *d, std::size_t n) override
    {
        size += n;
        if (!f_ && mem_.size() + n > (64u << 20)) {
            f_ = std::tmpfile();
            if (!f_) fail(ErrorCode::Io, "cannot create a temporary file");
            put(mem_.data(), mem_.size());
            mem_.clear();
            mem_.shrink_to_fit();
        }
        if (f_) put(d, n);
        else mem_.insert(mem_.end(), static_cast<const std::uint8_t *>(d), static_cast<const std::uint8_t *>(d) + n);
    }
    void copy_to(Sink &out)
    {
        if (!f_) {
            if (!mem_.empty()) out.write(mem_.data(), mem_.size());
            return;
        }
        std::rewind(f_);
        std::vector<std::uint8_t> buf(1 << 20);
        for (;;) {
            const std::size_t r = std::fread(buf.data(), 1, buf.size(), f_);
            if (!r) break;
            out.write(buf.data(), r);
        }
        if (std::ferror(f_)) fail(ErrorCode::Io, "cannot read a temporary file");
    }
    std::uint64_t size = 0;

private:
    void put(const void *d, std::size_t n)
    {
        if (n && std::fwrite(d, 1, n, f_) != n) fail(ErrorCode::NoSpace, "cannot write a temporary file");
    }
    std::vector<std::uint8_t> mem_;
    std::FILE *f_ = nullptr;
};

// ---- stream encoders: write() data in, compressed bytes go to a Sink

class Encoder {
public:
    virtual ~Encoder() = default;
    virtual void write(const std::uint8_t *d, std::size_t n) = 0;
    virtual void finish() = 0;
};

class CopyEncoder final : public Encoder {
public:
    explicit CopyEncoder(Sink &o) : o_(o) {}
    void write(const std::uint8_t *d, std::size_t n) override { o_.write(d, n); }
    void finish() override {}

private:
    Sink &o_;
};

class CoderEncoder final : public Encoder {
public:
    CoderEncoder(std::unique_ptr<detail::Coder> c, Sink &o) : c_(std::move(c)), o_(o), buf_(1 << 18) {}
    void write(const std::uint8_t *d, std::size_t n) override { run({d, n}, false); }
    void finish() override { run({}, true); }

private:
    void run(std::span<const std::uint8_t> in, bool fin)
    {
        for (;;) {
            auto s = c_->step(in, buf_, fin);
            in = in.subspan(s.consumed);
            if (s.produced) o_.write(buf_.data(), s.produced);
            if (s.done) return;
            if (!fin && in.empty() && s.produced < buf_.size()) return;
            if (s.consumed == 0 && s.produced == 0 && !fin) return;
        }
    }
    std::unique_ptr<detail::Coder> c_;
    Sink &o_;
    std::vector<std::uint8_t> buf_;
};

class PpmdEncoder final : public Encoder {
public:
    PpmdEncoder(unsigned order, std::uint32_t mem, Sink &o) : e_(order, mem), o_(o) {}
    void write(const std::uint8_t *d, std::size_t n) override
    {
        e_.encode(d, n);
        drain();
    }
    void finish() override
    {
        e_.finish();
        drain();
    }

private:
    void drain()
    {
        if (!e_.out.empty()) o_.write(e_.out.data(), e_.out.size());
        e_.out.clear();
    }
    ppmd7::Encoder e_;
    Sink &o_;
};

// One piece of an LZMA2 stream, compressed on its own. With a preset (the
// end of the data before it) the piece keeps the decoder's dictionary and
// may refer back into it, so cutting the stream costs almost nothing.
std::vector<std::uint8_t> lzma2_piece(std::span<const std::uint8_t> data, std::span<const std::uint8_t> preset,
                                      int level, std::uint32_t dict, int nice)
{
    lzma_options_lzma o{};
    lzma_lzma_preset(&o, std::uint32_t(std::clamp(level, 0, 9)));
    o.dict_size = dict;
    if (nice) o.nice_len = std::uint32_t(std::clamp(nice, 8, 273));
    if (!preset.empty()) {
        o.preset_dict = preset.data();
        o.preset_dict_size = std::uint32_t(preset.size());
    }
    lzma_filter f[2] = {{LZMA_FILTER_LZMA2, &o}, {LZMA_VLI_UNKNOWN, nullptr}};
    lzma_stream z = LZMA_STREAM_INIT;
    const lzma_ret init = lzma_raw_encoder(&z, f);
    if (init == LZMA_MEM_ERROR) fail(ErrorCode::Internal, "not enough memory for LZMA2");
    if (init != LZMA_OK) fail(ErrorCode::Internal, "liblzma init failed");
    std::vector<std::uint8_t> out(data.size() + data.size() / 64 + 4096);
    z.next_in = data.data();
    z.avail_in = data.size();
    z.next_out = out.data();
    z.avail_out = out.size();
    lzma_ret r;
    while ((r = lzma_code(&z, LZMA_FINISH)) == LZMA_OK) {
        const std::size_t used = out.size() - z.avail_out;
        out.resize(out.size() * 2);
        z.next_out = out.data() + used;
        z.avail_out = out.size() - used;
    }
    const std::size_t used = out.size() - z.avail_out;
    lzma_end(&z);
    if (r != LZMA_STREAM_END) fail(ErrorCode::Internal, "liblzma failed");
    out.resize(used);
    if (!out.empty()) out.pop_back(); // end marker: written once, after the last piece
    return out;
}

// LZMA2 compressed in pieces on every core and glued back into one stream.
class Lzma2MtEncoder final : public Encoder {
public:
    // dict: dictionary the decoder gets; overlap: how much earlier data each
    // piece may look back into.
    Lzma2MtEncoder(int level, int nice, std::uint32_t dict, std::size_t chunk, std::size_t overlap, unsigned threads,
                   ThreadPool *pool, Sink &o)
        : level_(level), nice_(nice), dict_(dict), chunk_(chunk), overlap_(overlap), threads_(threads), pool_(pool), o_(o)
    {
        cur_.reserve(chunk_);
    }
    void write(const std::uint8_t *d, std::size_t n) override
    {
        while (n) {
            const std::size_t k = std::min(n, chunk_ - cur_.size());
            cur_.insert(cur_.end(), d, d + k);
            d += k;
            n -= k;
            if (cur_.size() == chunk_) submit();
        }
    }
    void finish() override
    {
        if (!cur_.empty()) submit();
        while (!q_.empty()) pop();
        const std::uint8_t end = 0;
        o_.write(&end, 1);
    }

private:
    using Chunk = std::shared_ptr<const std::vector<std::uint8_t>>;
    void submit()
    {
        auto data = std::make_shared<const std::vector<std::uint8_t>>(std::move(cur_));
        cur_ = {};
        cur_.reserve(chunk_);
        std::vector<Chunk> before(hist_.begin(), hist_.end());
        auto job = [this, data, before]() {
            std::vector<std::uint8_t> preset;
            std::size_t want = overlap_;
            for (auto it = before.rbegin(); it != before.rend() && want; ++it) {
                const std::size_t k = std::min(want, (*it)->size());
                preset.insert(preset.begin(), (*it)->end() - std::ptrdiff_t(k), (*it)->end());
                want -= k;
            }
            return lzma2_piece(*data, preset, level_, dict_, nice_);
        };
        if (overlap_) {
            hist_.push_back(data);
            std::size_t kept = 0;
            for (auto &c : hist_) kept += c->size();
            while (!hist_.empty() && kept - hist_.front()->size() >= overlap_) {
                kept -= hist_.front()->size();
                hist_.pop_front();
            }
        }
        if (!pool_ || threads_ <= 1) {
            auto out = job();
            o_.write(out.data(), out.size());
            return;
        }
        q_.push_back(pool_->submit(std::move(job)));
        // Twice the threads in flight: one slow piece does not stall the rest.
        while (q_.size() > 2 * threads_) pop();
    }
    void pop()
    {
        auto out = q_.front().get();
        q_.pop_front();
        o_.write(out.data(), out.size());
    }
    int level_, nice_;
    std::uint32_t dict_;
    std::size_t chunk_, overlap_;
    unsigned threads_;
    ThreadPool *pool_;
    Sink &o_;
    std::vector<std::uint8_t> cur_;
    std::deque<Chunk> hist_;
    std::deque<std::future<std::vector<std::uint8_t>>> q_;
};

class FilterEncoder final : public Encoder {
public:
    FilterEncoder(std::unique_ptr<filters::Filter> f, std::unique_ptr<Encoder> next)
        : f_(std::move(f)), next_(std::move(next)) {}
    void write(const std::uint8_t *d, std::size_t n) override
    {
        pend_.insert(pend_.end(), d, d + n);
        if (pend_.size() < (1 << 16)) return;
        const std::size_t done = f_->run(pend_.data(), pend_.size());
        next_->write(pend_.data(), done);
        pend_.erase(pend_.begin(), pend_.begin() + std::ptrdiff_t(done));
    }
    void finish() override
    {
        const std::size_t done = f_->run(pend_.data(), pend_.size());
        (void)done; // the tail that run() leaves stays as it is
        next_->write(pend_.data(), pend_.size());
        next_->finish();
    }

private:
    std::unique_ptr<filters::Filter> f_;
    std::unique_ptr<Encoder> next_;
    std::vector<std::uint8_t> pend_;
};

class AesSink final : public Sink {
public:
    AesSink(std::span<const std::uint8_t> key, std::span<const std::uint8_t> iv, Sink &o)
        : aes_(key, Aes::Mode::Cbc, true, iv), o_(o) {}
    void write(const void *d, std::size_t n) override
    {
        const auto *p = static_cast<const std::uint8_t *>(d);
        buf_.insert(buf_.end(), p, p + n);
        const std::size_t whole = buf_.size() & ~std::size_t(15);
        if (whole < (1 << 16)) return;
        aes_.process(buf_.data(), buf_.data(), whole);
        o_.write(buf_.data(), whole);
        buf_.erase(buf_.begin(), buf_.begin() + std::ptrdiff_t(whole));
    }
    void finish() override
    {
        buf_.resize((buf_.size() + 15) & ~std::size_t(15), 0);
        if (!buf_.empty()) {
            aes_.process(buf_.data(), buf_.data(), buf_.size());
            o_.write(buf_.data(), buf_.size());
        }
        buf_.clear();
    }

private:
    Aes aes_;
    Sink &o_;
    std::vector<std::uint8_t> buf_;
};

// LZMA with explicit literal settings, for BCJ2's call and jump streams.
std::vector<std::uint8_t> lzma1_buffer(std::span<const std::uint8_t> in, std::uint32_t dict, unsigned lc, unsigned lp,
                                       std::vector<std::uint8_t> &props)
{
    lzma_options_lzma o{};
    lzma_lzma_preset(&o, 9);
    o.dict_size = dict;
    o.lc = lc;
    o.lp = lp;
    lzma_filter f[2] = {{LZMA_FILTER_LZMA1, &o}, {LZMA_VLI_UNKNOWN, nullptr}};
    std::uint32_t psize = 0;
    lzma_properties_size(&psize, &f[0]);
    props.resize(psize);
    lzma_properties_encode(&f[0], props.data());
    lzma_stream z = LZMA_STREAM_INIT;
    if (lzma_raw_encoder(&z, f) != LZMA_OK) fail(ErrorCode::Internal, "liblzma init failed");
    std::vector<std::uint8_t> out(in.size() + in.size() / 2 + 1024);
    z.next_in = in.data();
    z.avail_in = in.size();
    z.next_out = out.data();
    z.avail_out = out.size();
    lzma_ret r;
    while ((r = lzma_code(&z, LZMA_FINISH)) == LZMA_OK) {
        const std::size_t used = out.size() - z.avail_out;
        out.resize(out.size() * 2);
        z.next_out = out.data() + used;
        z.avail_out = out.size() - used;
    }
    const std::size_t used = out.size() - z.avail_out;
    lzma_end(&z);
    if (r != LZMA_STREAM_END) fail(ErrorCode::Internal, "liblzma failed");
    out.resize(used);
    return out;
}

// ---- settings

struct Settings {
    std::uint64_t main_id = method::Lzma2;
    CodecParams params;
    unsigned ppmd_order = 6;
    std::uint32_t ppmd_mem = 16 << 20;
    std::uint64_t solid_bytes = 0;     // 0 = not solid
    std::uint64_t solid_files = 0;
    bool filters = true;
    std::size_t lzma2_block = 0;
    int level = 5;
    std::optional<std::string> password;
    std::array<std::uint8_t, 32> key{};
};

std::uint64_t mem_available()
{
    std::ifstream f("/proc/meminfo");
    std::string k;
    std::uint64_t v = 0;
    while (f >> k >> v) {
        if (k == "MemAvailable:") return v << 10;
        std::string unit;
        f >> unit;
    }
    return 4ull << 30;
}

// How many encoders of this size fit in half the free memory.
unsigned fit_threads(unsigned want, std::uint64_t per_thread)
{
    static const std::uint64_t budget = mem_available() / 2;
    return unsigned(std::clamp<std::uint64_t>(budget / std::max<std::uint64_t>(per_thread, 1), 1, want));
}

std::uint8_t lzma2_dict_byte(std::uint64_t d)
{
    for (unsigned p = 0; p < 40; ++p)
        if ((std::uint64_t(2 | (p & 1)) << (p / 2 + 11)) >= d) return std::uint8_t(p);
    return 40;
}

Settings make_settings(const WriteOptions &o, unsigned threads)
{
    Settings s;
    const int level = std::clamp(o.level, 0, 9);
    s.filters = o.filters;
    Method m = o.method;
    if (m == Method::Default) m = level == 0 ? Method::Store : Method::Lzma2;
    switch (m) {
    case Method::Store: s.main_id = method::Copy; break;
    case Method::Lzma2: s.main_id = method::Lzma2; break;
    case Method::Lzma: s.main_id = method::Lzma; break;
    case Method::Ppmd: s.main_id = method::Ppmd; break;
    case Method::Bzip2: s.main_id = method::Bzip2; break;
    case Method::Deflate: s.main_id = method::Deflate; break;
    case Method::Zstd: s.main_id = method::Zstd; break;
    default: fail(ErrorCode::InvalidOption, std::string("7z cannot hold ") + method_name(m) + " data; use LZMA2, LZMA, PPMd, BZip2, Deflate, zstd or store");
    }
    if (o.encryption != Encryption::Default && o.encryption != Encryption::Aes256)
        fail(ErrorCode::InvalidOption, "7z only encrypts with AES-256");
    s.params.level = level;
    s.params.word_size = o.word_size;
    static constexpr std::uint64_t kDict[10] = {1 << 16, 1 << 20, 2 << 20, 4 << 20, 8 << 20,
                                                16 << 20, 32 << 20, 32 << 20, 64 << 20, 64 << 20};
    s.params.dictionary = o.dictionary ? o.dictionary : kDict[level];
    if (s.main_id == method::Ppmd) {
        s.ppmd_order = level >= 9 ? 32 : level >= 7 ? 16 : level >= 5 ? 6 : 4;
        s.ppmd_mem = std::uint32_t(o.dictionary ? std::min<std::uint64_t>(o.dictionary, 0xFFFFFFFFu - 36)
                                                : level >= 9 ? 192u << 20 : level >= 7 ? 64u << 20 : level >= 5 ? 16u << 20 : 4u << 20);
        s.ppmd_mem = std::max<std::uint32_t>(s.ppmd_mem, 1 << 11);
        if (o.word_size) s.ppmd_order = unsigned(std::clamp(o.word_size, 2, 32));
    }
    if (o.solid) {
        s.solid_bytes = o.solid_block_size ? o.solid_block_size
                                           : std::clamp<std::uint64_t>(s.params.dictionary * 64, 64u << 20, 4ull << 30);
        s.solid_files = o.solid_files_per_block;
    }
    // LZMA2 blocks: four dictionaries, as 7-Zip does.
    s.lzma2_block = std::size_t(std::clamp<std::uint64_t>(s.params.dictionary * 4, 1 << 20, 256 << 20));
    s.level = level;
    (void)threads;
    s.password = o.password;
    if (s.password) {
        if (s.password->empty()) fail(ErrorCode::InvalidOption, "the password is empty");
        s.key = derive_key(*s.password, {}, kAesCycles);
    }
    return s;
}

// ---- what goes in

enum class Exe { None, X86, Arm64, Arm, Armt, Ppc, Sparc, Ia64 };

Exe sniff_exe(const std::uint8_t *h, std::size_t n)
{
    if (n >= 20 && h[0] == 0x7F && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') {
        const bool be = h[5] == 2;
        const unsigned mach = be ? (h[18] << 8 | h[19]) : (h[18] | h[19] << 8);
        switch (mach) {
        case 0x03: case 0x3E: return Exe::X86;
        case 0xB7: return Exe::Arm64;
        case 0x28: return Exe::Arm;
        case 0x14: case 0x15: return be ? Exe::Ppc : Exe::None;
        case 0x02: case 0x2B: return Exe::Sparc;
        case 0x32: return Exe::Ia64;
        }
        return Exe::None;
    }
    if (n >= 64 && h[0] == 'M' && h[1] == 'Z') {
        const std::uint32_t pe = le32(h + 60);
        if (pe + 6 <= n && h[pe] == 'P' && h[pe + 1] == 'E' && h[pe + 2] == 0 && h[pe + 3] == 0) {
            switch (le16(h + pe + 4)) {
            case 0x14C: case 0x8664: return Exe::X86;
            case 0xAA64: return Exe::Arm64;
            case 0x1C0: return Exe::Arm;
            case 0x1C2: case 0x1C4: return Exe::Armt;
            case 0x200: return Exe::Ia64;
            }
        }
        return Exe::X86; // DOS programs
    }
    if (n >= 8 && le32(h) == 0xFEEDFACF) {
        const std::uint32_t cpu = le32(h + 4);
        if (cpu == 0x01000007) return Exe::X86;
        if (cpu == 0x0100000C) return Exe::Arm64;
    }
    return Exe::None;
}

std::optional<filters::Kind> exe_filter(Exe e)
{
    using K = filters::Kind;
    switch (e) {
    case Exe::X86: return K::X86;
    case Exe::Arm64: return K::Arm64;
    case Exe::Arm: return K::Arm;
    case Exe::Armt: return K::Armt;
    case Exe::Ppc: return K::Ppc;
    case Exe::Sparc: return K::Sparc;
    case Exe::Ia64: return K::Ia64;
    case Exe::None: break;
    }
    return std::nullopt;
}

std::uint64_t filter_id(filters::Kind k)
{
    using K = filters::Kind;
    switch (k) {
    case K::X86: return method::X86;
    case K::Arm64: return method::Arm64;
    case K::Arm: return method::Arm;
    case K::Armt: return method::Armt;
    case K::Ppc: return method::Ppc;
    case K::Sparc: return method::Sparc;
    case K::Ia64: return method::Ia64;
    default: break;
    }
    return method::Delta;
}

struct Item {
    FileItem meta;
    enum class Src { None, Disk, Bytes, Old } src = Src::None;
    fs::path disk;
    std::string bytes;
    std::size_t old_entry = 0;
    std::uint64_t size = 0;
    Exe exe = Exe::None;
    std::string sort_key;
};

std::string extension_of(const std::string &path)
{
    const std::size_t slash = path.rfind('/');
    const std::size_t dot = path.rfind('.');
    if (dot == std::string::npos || (slash != std::string::npos && dot < slash)) return {};
    std::string e = path.substr(dot + 1);
    for (auto &c : e) c = char(std::tolower(static_cast<unsigned char>(c)));
    return e;
}

FileItem meta_for(const PlanItem &p, const WriteOptions &o)
{
    FileItem f;
    f.name = p.archive_path;
    const Entry &e = p.stat;
    f.has_stream = false;
    f.is_dir = e.type == EntryType::Directory;
    std::uint32_t type = f.is_dir ? 0040000 : e.type == EntryType::Symlink ? 0120000 : 0100000;
    const std::uint32_t mode = e.mode.value_or(f.is_dir ? 0755 : 0644);
    std::uint32_t attr = kAttrUnixExtension | (type | mode) << 16 | (f.is_dir ? kAttrDirectory : kAttrArchive);
    if (!(mode & 0200)) attr |= kAttrReadOnly;
    f.attrib = attr;
    if (o.store_mtime && e.mtime) f.mtime = unix_to_filetime(*e.mtime);
    if (o.store_atime && e.atime) f.atime = unix_to_filetime(*e.atime);
    if (o.store_ctime && e.ctime) f.ctime = unix_to_filetime(*e.ctime);
    return f;
}

// Reads the data of kept entries from the old archive, folder by folder,
// decoding each old folder once and in order.
class OldData {
public:
    OldData(Reader &r, Context &ctx) : r_(r), ctx_(ctx) {}
    template <class F> void read(std::size_t entry, F &&f)
    {
        const auto &w = r_.where()[entry];
        if (w.folder == SIZE_MAX) return;
        auto &c = cur_[w.folder];
        if (!c.pull || c.pos > w.offset) {
            c.pull = r_.open_folder_checked(w.folder, ctx_, r_.db().files[w.file].name);
            c.pos = 0;
        }
        std::vector<std::uint8_t> buf(1 << 18);
        auto take = [&](std::uint64_t n, bool keep) {
            while (n) {
                const std::size_t want = std::size_t(std::min<std::uint64_t>(n, buf.size()));
                const std::size_t got = c.pull->read(buf.data(), want);
                if (!got) fail(ErrorCode::Truncated, "the old archive ends early");
                if (keep) f(buf.data(), got);
                n -= got;
                c.pos += got;
            }
        };
        take(w.offset - c.pos, false);
        take(r_.db().streams.sub_sizes[w.sub], true);
    }

private:
    struct Cur {
        std::unique_ptr<Pull> pull;
        std::uint64_t pos = 0;
    };
    Reader &r_;
    Context &ctx_;
    std::map<std::size_t, Cur> cur_;
};

// ---- one folder

struct Block {
    std::vector<Item *> items;
    std::optional<filters::Kind> filter;
    std::uint64_t bytes = 0;
};

struct Encoded {
    Folder folder;
    std::vector<std::uint64_t> pack_sizes;
    std::vector<std::uint32_t> crcs;
};

class FolderWriter {
public:
    FolderWriter(const Settings &s, Context &ctx, OldData *old) : s_(s), ctx_(ctx), old_(old) {}

    // Compresses the block into out. threads > 1 only for LZMA2 blocks.
    Encoded encode(const Block &b, Sink &out, unsigned threads)
    {
        if (b.filter == filters::Kind::X86 && s_.level >= 7 && b.bytes <= (512u << 20) &&
            (s_.main_id == method::Lzma2 || s_.main_id == method::Lzma))
            return encode_bcj2(b, out, threads);
        Encoded r;
        Folder &f = r.folder;
        // Coders in 7z order: the first one makes the folder's output.
        if (b.filter) {
            Coder c;
            c.id = filter_id(*b.filter);
            f.coders.push_back(c);
        }
        Coder main;
        main.id = s_.main_id;
        CountingSink counted(out);
        std::unique_ptr<AesSink> aes;
        std::array<std::uint8_t, 16> iv{};
        Sink *target = &counted;
        if (s_.password) {
            random_bytes(iv);
            aes = std::make_unique<AesSink>(s_.key, iv, counted);
            target = aes.get();
        }
        CountingSink compressed(*target);
        std::unique_ptr<Encoder> enc;
        CodecParams p = s_.params;
        switch (s_.main_id) {
        case method::Copy: enc = std::make_unique<CopyEncoder>(compressed); break;
        case method::Lzma2: {
            const Lzma2Plan lp = plan_lzma2(b.bytes, threads);
            main.props = {lzma2_dict_byte(lp.dict)};
            enc = std::make_unique<Lzma2MtEncoder>(p.level, p.word_size, lp.dict, lp.chunk, lp.overlap, lp.threads,
                                                   lp.threads > 1 ? &ctx_.pool() : nullptr, compressed);
            break;
        }
        case method::Lzma: {
            p.dictionary = std::min<std::uint64_t>(p.dictionary, std::max<std::uint64_t>(b.bytes, 4096));
            auto c = make_encoder(Codec::Lzma1Raw, p);
            main.props = p.props;
            enc = std::make_unique<CoderEncoder>(std::move(c), compressed);
            break;
        }
        case method::Ppmd: {
            main.props.resize(5);
            main.props[0] = std::uint8_t(s_.ppmd_order);
            put_le32(main.props.data() + 1, s_.ppmd_mem);
            enc = std::make_unique<PpmdEncoder>(s_.ppmd_order, s_.ppmd_mem, compressed);
            break;
        }
        case method::Bzip2: enc = std::make_unique<CoderEncoder>(make_encoder(Codec::Bzip2, p), compressed); break;
        case method::Deflate: enc = std::make_unique<CoderEncoder>(make_encoder(Codec::Deflate, p), compressed); break;
        case method::Zstd: {
            p.threads = int(threads);
            main.props = {1, 5, std::uint8_t(p.level), 0, 0};
            enc = std::make_unique<CoderEncoder>(make_encoder(Codec::Zstd, p), compressed);
            break;
        }
        default: fail(ErrorCode::Internal, "no encoder");
        }
        if (b.filter) enc = std::make_unique<FilterEncoder>(filters::make_filter(*b.filter, true), std::move(enc));
        f.coders.push_back(main);
        if (s_.password) {
            Coder a;
            a.id = method::Aes;
            a.props.push_back(std::uint8_t(kAesCycles | 0x40));
            a.props.push_back(0x0F); // no salt, 16-byte IV
            a.props.insert(a.props.end(), iv.begin(), iv.end());
            f.coders.push_back(a);
        }

        read_items(b, r, [&](const std::uint8_t *d, std::size_t n) { enc->write(d, n); });
        enc->finish();
        if (aes) aes->finish();

        const std::uint64_t data = b.bytes;
        for (std::size_t i = 0; i < f.coders.size(); ++i) {
            const bool is_aes = f.coders[i].id == method::Aes;
            f.unpack_sizes.push_back(is_aes ? compressed.count : data);
            if (i + 1 < f.coders.size()) f.binds.push_back({i, i + 1});
        }
        f.packed = {f.coders.size() - 1};
        f.num_substreams = b.items.size();
        r.pack_sizes = {counted.count};
        return r;
    }

    struct Lzma2Plan {
        std::uint32_t dict;
        std::size_t chunk, overlap;
        unsigned threads;
    };
    // Pieces small enough to keep every core busy; each one looks back into
    // the data before it, more at higher levels.
    Lzma2Plan plan_lzma2(std::uint64_t bytes, unsigned threads) const
    {
        // Measured on the bench corpus: past 4 MiB of look-back each piece
        // spends more time re-reading it than it saves.
        static constexpr std::uint64_t kOverlap[10] = {0, 0, 0, 1 << 20, 2 << 20, 2 << 20, 4 << 20, 4 << 20, 4 << 20, 4 << 20};
        static constexpr std::uint64_t kPiece[10] = {1 << 20, 1 << 20, 1 << 20, 1 << 20, 2 << 20, 2 << 20,
                                                     4 << 20, 4 << 20, 4 << 20, 4 << 20};
        const std::uint64_t dict = std::min<std::uint64_t>(s_.params.dictionary, std::max<std::uint64_t>(bytes, 4096));
        const std::uint64_t overlap = std::min<std::uint64_t>(kOverlap[s_.level], dict);
        const std::uint64_t floor = kPiece[s_.level];
        const std::uint64_t chunk = std::clamp<std::uint64_t>(bytes / std::max(1u, threads) + 1, floor, std::max<std::uint64_t>(floor, s_.lzma2_block));
        Lzma2Plan p;
        p.dict = std::uint32_t(std::max<std::uint64_t>(4096, std::min<std::uint64_t>(dict, overlap + chunk)));
        p.chunk = std::size_t(chunk);
        p.overlap = std::size_t(overlap);
        p.threads = fit_threads(threads, std::uint64_t(p.dict) * 12 + chunk * 2 + overlap);
        return p;
    }

    template <class F> void read_items(const Block &b, Encoded &r, F &&sink)
    {
        std::vector<std::uint8_t> buf(1 << 18);
        for (Item *it : b.items) {
            ctx_.checkpoint();
            ctx_.file_started(it->meta.name);
            std::uint32_t crc = 0;
            std::uint64_t got = 0;
            auto feed = [&](const std::uint8_t *d, std::size_t n) {
                crc = crc32(crc, d, n);
                got += n;
                sink(d, n);
                ctx_.add_bytes(n);
            };
            switch (it->src) {
            case Item::Src::Bytes: feed(reinterpret_cast<const std::uint8_t *>(it->bytes.data()), it->bytes.size()); break;
            case Item::Src::Old: old_->read(it->old_entry, feed); break;
            case Item::Src::Disk: {
                const int fd = ::open(it->disk.c_str(), O_RDONLY | O_CLOEXEC);
                if (fd < 0) fail(ErrorCode::Io, std::string("cannot open: ") + std::strerror(errno), it->disk.string());
                for (;;) {
                    // A file that grew while we read it is cut at its listed size.
                    const std::size_t want = std::size_t(std::min<std::uint64_t>(buf.size(), it->size - got));
                    if (!want) break;
                    const ssize_t n = ::read(fd, buf.data(), want);
                    if (n < 0 && errno == EINTR) continue;
                    if (n < 0) { const int e = errno; ::close(fd); fail(ErrorCode::Io, std::string("read failed: ") + std::strerror(e), it->disk.string()); }
                    if (n == 0) break;
                    feed(buf.data(), std::size_t(n));
                }
                ::close(fd);
                if (got != it->size) {
                    fail(ErrorCode::Io, "file got shorter while it was being added", it->disk.string());
                }
                break;
            }
            case Item::Src::None: break;
            }
            r.crcs.push_back(crc);
            ctx_.file_done();
        }
    }

    Encoded encode_bcj2(const Block &b, Sink &out, unsigned threads);

private:
    const Settings &s_;
    Context &ctx_;
    OldData *old_;
};

} // namespace

Encoded FolderWriter::encode_bcj2(const Block &b, Sink &out, unsigned threads)
{
    Encoded r;
    filters::Bcj2Encoder bcj(b.bytes);
    read_items(b, r, [&](const std::uint8_t *d, std::size_t n) { bcj.write(d, n); });
    bcj.finish();

    Folder &f = r.folder;
    Coder c0;
    c0.id = method::Bcj2;
    c0.num_in = 4;
    f.coders.push_back(c0);
    // Main stream: the usual compressor; calls and jumps: small LZMA.
    MemorySink main_packed;
    {
        const std::uint64_t dict = std::min<std::uint64_t>(s_.params.dictionary, std::max<std::uint64_t>(bcj.main.size(), 4096));
        Coder m;
        CodecParams p = s_.params;
        p.dictionary = dict;
        if (s_.main_id == method::Lzma2) {
            m.id = method::Lzma2;
            const Lzma2Plan lp = plan_lzma2(bcj.main.size(), threads);
            m.props = {lzma2_dict_byte(lp.dict)};
            Lzma2MtEncoder e(p.level, p.word_size, lp.dict, lp.chunk, lp.overlap, lp.threads,
                             lp.threads > 1 ? &ctx_.pool() : nullptr, main_packed);
            e.write(bcj.main.data(), bcj.main.size());
            e.finish();
        } else {
            m.id = method::Lzma;
            main_packed.bytes() = lzma1_buffer(bcj.main, std::uint32_t(dict), 3, 0, m.props);
        }
        f.coders.push_back(m);
    }
    std::vector<std::uint8_t> streams[4];
    streams[0] = std::move(main_packed.bytes());
    for (int k = 1; k <= 2; ++k) {
        auto &src = k == 1 ? bcj.call : bcj.jump;
        Coder c;
        c.id = method::Lzma;
        streams[k] = lzma1_buffer(src, std::uint32_t(std::max<std::size_t>(4096, std::min<std::size_t>(src.size(), 1 << 20))), 0, 2, c.props);
        f.coders.push_back(c);
    }
    streams[3] = std::move(bcj.rc);
    const std::uint64_t outs[4] = {b.bytes, bcj.main.size(), bcj.call.size(), bcj.jump.size()};
    f.unpack_sizes.assign(outs, outs + 4);
    f.binds = {{0, 1}, {1, 2}, {2, 3}};
    // In streams: BCJ2 0..3 (3 is the range coder, stored), LZMA2 4, LZMA 5, 6.
    const std::uint64_t ins[4] = {4, 5, 6, 3};
    for (int k = 0; k < 4; ++k) {
        CountingSink counted(out);
        if (s_.password) {
            std::array<std::uint8_t, 16> iv{};
            random_bytes(iv);
            AesSink a(s_.key, iv, counted);
            a.write(streams[k].data(), streams[k].size());
            a.finish();
            Coder ac;
            ac.id = method::Aes;
            ac.props = {std::uint8_t(kAesCycles | 0x40), 0x0F};
            ac.props.insert(ac.props.end(), iv.begin(), iv.end());
            const std::uint64_t in_index = 7 + std::uint64_t(k), out_index = 4 + std::uint64_t(k);
            f.coders.push_back(ac);
            f.unpack_sizes.push_back(streams[k].size());
            f.binds.push_back({ins[k], out_index});
            f.packed.push_back(in_index);
        } else {
            counted.write(streams[k].data(), streams[k].size());
            f.packed.push_back(ins[k]);
        }
        r.pack_sizes.push_back(counted.count);
    }
    f.num_substreams = b.items.size();
    return r;
}

class Writer final : public WriterImpl {
public:
    void write(const std::vector<PlanItem> &plan, ReaderImpl *existing, Sink &out, const WriteOptions &opts,
               Context &ctx) override;
};

std::unique_ptr<WriterImpl> make_writer() { return std::make_unique<Writer>(); }

void Writer::write(const std::vector<PlanItem> &plan, ReaderImpl *existing, Sink &out, const WriteOptions &opts,
                   Context &ctx)
{
    Reader *old = existing ? dynamic_cast<Reader *>(existing) : nullptr;
    if (existing && !old) fail(ErrorCode::Internal, "7z update without a 7z reader");
    const unsigned threads = unsigned(std::max(1, ctx.threads()));
    Settings s = make_settings(opts, threads);

    std::deque<Item> items;
    // Old folders whose every file stays: copied as they are.
    std::vector<bool> folder_whole;
    std::vector<std::size_t> kept_count;
    if (old) {
        const auto &si = old->db().streams;
        folder_whole.assign(si.folders.size(), false);
        kept_count.assign(si.folders.size(), 0);
        std::vector<std::size_t> total(si.folders.size(), 0);
        for (const auto &w : old->where())
            if (w.folder != SIZE_MAX) ++total[w.folder];
        for (const auto &p : plan)
            if (p.kind == PlanItem::Kind::Keep) {
                const auto &w = old->where().at(p.keep_index);
                if (w.folder != SIZE_MAX) ++kept_count[w.folder];
            }
        for (std::size_t f = 0; f < si.folders.size(); ++f)
            folder_whole[f] = total[f] > 0 && kept_count[f] == total[f] && unsupported_coder(si.folders[f]).empty();
    }

    std::vector<Item *> no_data, copied_order;
    std::vector<std::vector<Item *>> copied(folder_whole.size());
    std::vector<Item *> fresh;
    std::vector<std::uint8_t> head(4096);
    for (const auto &p : plan) {
        Item it;
        if (p.kind == PlanItem::Kind::Keep) {
            if (!old) fail(ErrorCode::Internal, "kept entry without an old archive");
            const auto &w = old->where().at(p.keep_index);
            it.meta = old->db().files.at(w.file);
            it.meta.name = p.archive_path;
            it.old_entry = p.keep_index;
            if (w.folder != SIZE_MAX) {
                it.src = Item::Src::Old;
                it.size = old->db().streams.sub_sizes[w.sub];
                it.meta.has_stream = true;
            } else {
                it.meta.has_stream = false;
            }
        } else {
            it.meta = meta_for(p, opts);
            if (p.stat.type == EntryType::Symlink) {
                it.src = Item::Src::Bytes;
                it.bytes = p.stat.link_target;
                it.size = it.bytes.size();
            } else if (p.stat.type == EntryType::File || p.stat.type == EntryType::Hardlink) {
                it.src = Item::Src::Disk;
                it.disk = p.disk;
                it.size = p.stat.size;
                if (s.filters && it.size >= 4096 &&
                    (s.main_id == method::Lzma2 || s.main_id == method::Lzma || s.main_id == method::Zstd)) {
                    const int fd = ::open(p.disk.c_str(), O_RDONLY | O_CLOEXEC);
                    if (fd >= 0) {
                        const ssize_t r = ::read(fd, head.data(), head.size());
                        ::close(fd);
                        if (r > 0) it.exe = sniff_exe(head.data(), std::size_t(r));
                    }
                }
            }
            if (it.src != Item::Src::None && it.size == 0) it.src = Item::Src::None; // empty file
            it.meta.has_stream = it.src != Item::Src::None;
        }
        it.sort_key = extension_of(it.meta.name) + '\0' + it.meta.name;
        items.push_back(std::move(it));
        Item *ip = &items.back();
        if (!ip->meta.has_stream) no_data.push_back(ip);
        else if (ip->src == Item::Src::Old && folder_whole[old->where()[ip->old_entry].folder])
            copied[old->where()[ip->old_entry].folder].push_back(ip);
        else fresh.push_back(ip);
    }

    // New blocks: executables of each kind on their own, the rest sorted by
    // type so that similar files sit next to each other.
    std::vector<Block> blocks;
    std::map<int, std::vector<Item *>> groups;
    // Methods that cannot split a folder themselves get one folder per core.
    if (s.solid_bytes && !opts.solid_block_size && s.main_id != method::Lzma2 && s.main_id != method::Zstd &&
        s.main_id != method::Copy && threads > 1) {
        std::uint64_t total = 0;
        for (Item *it : fresh) total += it->size;
        s.solid_bytes = std::clamp<std::uint64_t>(total / threads + 1, 1 << 20, s.solid_bytes);
    }
    for (Item *it : fresh) groups[int(s.filters ? it->exe : Exe::None)].push_back(it);
    for (auto &[kind, list] : groups) {
        if (s.solid_bytes)
            std::stable_sort(list.begin(), list.end(), [](Item *a, Item *b) { return a->sort_key < b->sort_key; });
        Block cur;
        cur.filter = exe_filter(Exe(kind));
        for (Item *it : list) {
            const bool full = !cur.items.empty() &&
                              (!s.solid_bytes || cur.bytes + it->size > s.solid_bytes ||
                               (s.solid_files && cur.items.size() >= s.solid_files));
            if (full) {
                blocks.push_back(std::move(cur));
                cur = Block{};
                cur.filter = exe_filter(Exe(kind));
            }
            cur.items.push_back(it);
            cur.bytes += it->size;
        }
        if (!cur.items.empty()) blocks.push_back(std::move(cur));
    }

    // Big blocks first: they use every core on their own, then the small
    // ones run side by side.
    std::stable_sort(blocks.begin(), blocks.end(), [](const Block &a, const Block &b) {
        return (a.bytes >= (8u << 20)) > (b.bytes >= (8u << 20));
    });

    // Start header comes back at the end, once the header is known.
    std::uint8_t start[kStartHeaderSize] = {};
    std::memcpy(start, kSignature, 6);
    start[7] = 4;
    out.write(start, sizeof start);
    std::uint64_t written = 0;

    Database db;
    auto &si = db.streams;
    std::vector<Item *> data_order;

    // 1. Old folders kept whole: raw copy.
    if (old) {
        const auto &osi = old->db().streams;
        std::size_t osub = 0;
        std::vector<std::uint8_t> buf(1 << 20);
        for (std::size_t f = 0; f < osi.folders.size(); ++f) {
            const Folder &of = osi.folders[f];
            const std::size_t nsub = std::size_t(of.num_substreams);
            if (folder_whole[f]) {
                Folder nf = of;
                nf.first_pack = si.pack_sizes.size();
                std::uint64_t at = old->folder_data_start(f);
                for (std::size_t k = 0; k < of.packed.size(); ++k) {
                    std::uint64_t n = osi.pack_sizes[of.first_pack + k];
                    si.pack_sizes.push_back(n);
                    written += n;
                    while (n) {
                        ctx.checkpoint();
                        const std::size_t c = std::size_t(std::min<std::uint64_t>(n, buf.size()));
                        old->source().read_exact(at, buf.data(), c);
                        out.write(buf.data(), c);
                        at += c;
                        n -= c;
                    }
                }
                for (std::size_t k = 0; k < nsub; ++k) {
                    si.sub_sizes.push_back(osi.sub_sizes[osub + k]);
                    si.sub_crcs.push_back(osi.sub_crcs[osub + k]);
                }
                si.folders.push_back(std::move(nf));
                // Entries of the folder, in the folder's order.
                std::vector<Item *> &list = copied[f];
                std::sort(list.begin(), list.end(), [&](Item *a, Item *b) {
                    return old->where()[a->old_entry].sub < old->where()[b->old_entry].sub;
                });
                data_order.insert(data_order.end(), list.begin(), list.end());
            }
            osub += nsub;
        }
    }

    // 2. New folders. Big LZMA2 or zstd blocks use every core themselves;
    // the others run side by side, each into its own spool.
    std::unique_ptr<OldData> old_data = old ? std::make_unique<OldData>(*old, ctx) : nullptr;
    auto add_result = [&](Encoded &e, const Block &b) {
        e.folder.first_pack = si.pack_sizes.size();
        si.pack_sizes.insert(si.pack_sizes.end(), e.pack_sizes.begin(), e.pack_sizes.end());
        for (std::size_t i = 0; i < b.items.size(); ++i) {
            si.sub_sizes.push_back(b.items[i]->size);
            si.sub_crcs.push_back(e.crcs[i]);
            data_order.push_back(b.items[i]);
        }
        si.folders.push_back(std::move(e.folder));
    };
    struct Pending {
        std::size_t block;
        std::unique_ptr<Spool> spool;
        std::future<Encoded> result;
    };
    std::deque<Pending> window;
    auto drain_one = [&]() {
        Pending p = std::move(window.front());
        window.pop_front();
        Encoded e = p.result.get();
        p.spool->copy_to(out);
        written += p.spool->size;
        add_result(e, blocks[p.block]);
    };
    const bool self_mt = s.main_id == method::Lzma2 || s.main_id == method::Zstd;
    // Kept-but-rewritten entries read one old folder in order: keep that sequential.
    const bool any_old = std::any_of(blocks.begin(), blocks.end(), [](const Block &b) {
        return std::any_of(b.items.begin(), b.items.end(), [](Item *i) { return i->src == Item::Src::Old; });
    });
    std::uint64_t biggest = 0;
    for (auto &b : blocks) biggest = std::max(biggest, b.bytes);
    const unsigned window_max = fit_threads(threads, std::min<std::uint64_t>(biggest, s.params.dictionary) * 12 + biggest * 2);
    try {
        for (std::size_t bi = 0; bi < blocks.size(); ++bi) {
            const Block &b = blocks[bi];
            const bool inline_mt = threads <= 1 || any_old || (self_mt && b.bytes >= (8u << 20));
            if (inline_mt) {
                while (!window.empty()) drain_one();
                FolderWriter fw(s, ctx, old_data.get());
                CountingSink c(out);
                Encoded e = fw.encode(b, c, self_mt ? threads : 1);
                written += c.count;
                add_result(e, b);
                continue;
            }
            auto spool = std::make_unique<Spool>();
            Spool *sp = spool.get();
            window.push_back({bi, std::move(spool), ctx.pool().submit([&s, &ctx, &b, sp]() {
                                  FolderWriter fw(s, ctx, nullptr);
                                  return fw.encode(b, *sp, 1);
                              })});
            if (window.size() > window_max) drain_one();
        }
        while (!window.empty()) drain_one();
    } catch (...) {
        for (auto &p : window) if (p.result.valid()) p.result.wait();
        throw;
    }

    // 3. Files list: folders first (no data), then files in stream order, then empty files.
    for (Item *it : no_data)
        if (it->meta.is_dir) db.files.push_back(it->meta);
    for (Item *it : data_order) {
        FileItem f = it->meta;
        f.has_stream = true;
        f.is_dir = false;
        db.files.push_back(std::move(f));
    }
    for (Item *it : no_data)
        if (!it->meta.is_dir) db.files.push_back(it->meta);

    std::vector<std::uint8_t> header = write_header(db);
    // Compressed (and encrypted) header, as 7-Zip writes it.
    if (header.size() > 64 || s.password) {
        CodecParams hp;
        hp.level = 9;
        hp.dictionary = std::max<std::uint64_t>(1 << 16, std::min<std::uint64_t>(header.size(), 1 << 26));
        std::vector<std::uint8_t> packed = encode_buffer(Codec::Lzma1Raw, header, hp);
        StreamsInfo hs;
        hs.pack_pos = written;
        Folder hf;
        Coder lz;
        lz.id = method::Lzma;
        lz.props = hp.props;
        hf.coders.push_back(lz);
        hf.unpack_sizes.push_back(header.size());
        if (s.password && opts.encrypt_names) {
            std::array<std::uint8_t, 16> iv{};
            random_bytes(iv);
            MemorySink enc;
            AesSink a(s.key, iv, enc);
            a.write(packed.data(), packed.size());
            a.finish();
            Coder ac;
            ac.id = method::Aes;
            ac.props = {std::uint8_t(kAesCycles | 0x40), 0x0F};
            ac.props.insert(ac.props.end(), iv.begin(), iv.end());
            hf.coders.push_back(ac);
            hf.unpack_sizes.push_back(packed.size());
            hf.binds.push_back({0, 1});
            hf.packed = {1};
            packed = std::move(enc.bytes());
        } else {
            hf.packed = {0};
        }
        hf.crc = crc32(0, header.data(), header.size());
        hs.folders.push_back(hf);
        hs.pack_sizes.push_back(packed.size());
        if (packed.size() < header.size() || (s.password && opts.encrypt_names)) {
            out.write(packed.data(), packed.size());
            written += packed.size();
            header = write_encoded_header(hs);
        }
    }
    out.write(header.data(), header.size());

    put_le64(start + 12, written);
    put_le64(start + 20, header.size());
    put_le32(start + 28, crc32(0, header.data(), header.size()));
    put_le32(start + 8, crc32(0, start + 12, 20));
    if (!out.rewrite(0, start, sizeof start))
        fail(ErrorCode::Internal, "7z needs an output it can go back into");
    secure_wipe(s.key.data(), s.key.size());
}

} // namespace raye::archive::detail::sevenz
