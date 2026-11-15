// SPDX-License-Identifier: GPL-3.0-or-later
// ZIP writer. Small files are compressed whole, several at a time; a big
// Deflate file is cut in blocks compressed in parallel (each block primed
// with the 32 KiB before it, like pigz), so one large file also uses every
// core. Entries kept from an existing archive are copied as stored.
#include "writer.h"

#include "reader.h"

#include "../../core/checksum.h"
#include "../../core/context.h"
#include "../../core/crypto.h"

#include <lzma.h>
#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <future>
#include <sys/stat.h>
#include <unistd.h>

namespace raye::archive::detail::zip {

namespace {

constexpr std::uint64_t kSmall = 8 << 20;       // compressed in memory, whole
constexpr std::uint64_t kInflight = 256 << 20;  // input held by queued small files
constexpr std::size_t kBlock = 1 << 20;         // parallel Deflate block
constexpr std::size_t kDict = 32 << 10;
constexpr std::uint64_t kZip64Guess = 0xf0000000; // streamed files above this get ZIP64 up front
constexpr std::uint32_t k32 = 0xffffffffu;

class Fd {
public:
    explicit Fd(const std::filesystem::path &p) : fd_(::open(p.c_str(), O_RDONLY | O_CLOEXEC)), path_(p.string())
    {
        if (fd_ < 0) fail(ErrorCode::Io, std::string("cannot read file: ") + std::strerror(errno), path_);
    }
    ~Fd() { if (fd_ >= 0) ::close(fd_); }
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
    std::size_t read(std::uint8_t *p, std::size_t n)
    {
        std::size_t got = 0;
        while (got < n) {
            const ssize_t r = ::read(fd_, p + got, n - got);
            if (r < 0) {
                if (errno == EINTR) continue;
                fail(ErrorCode::Io, std::string("cannot read file: ") + std::strerror(errno), path_);
            }
            if (r == 0) break;
            got += std::size_t(r);
        }
        return got;
    }
    std::size_t pread(std::uint8_t *p, std::size_t n, std::uint64_t at) const
    {
        const ssize_t r = ::pread(fd_, p, n, off_t(at));
        return r < 0 ? 0 : std::size_t(r);
    }

private:
    int fd_;
    std::string path_;
};

// Remembers the offset: the central directory needs it.
class Counter {
public:
    explicit Counter(Sink &s) : s_(s) {}
    void write(const void *p, std::size_t n) { s_.write(p, n); pos_ += n; }
    void write(const std::vector<std::uint8_t> &v) { write(v.data(), v.size()); }
    std::uint64_t pos() const { return pos_; }
    Sink &sink() { return s_; }

private:
    Sink &s_;
    std::uint64_t pos_ = 0;
};

struct Out {
    std::vector<std::uint8_t> b;
    void u8(std::uint8_t v) { b.push_back(v); }
    void u16(std::uint16_t v) { b.push_back(std::uint8_t(v)); b.push_back(std::uint8_t(v >> 8)); }
    void u32(std::uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back(std::uint8_t(v >> 8 * i)); }
    void u64(std::uint64_t v) { for (int i = 0; i < 8; ++i) b.push_back(std::uint8_t(v >> 8 * i)); }
    void bytes(std::string_view s) { b.insert(b.end(), s.begin(), s.end()); }
    void bytes(std::span<const std::uint8_t> s) { b.insert(b.end(), s.begin(), s.end()); }
};

struct Settings {
    std::uint16_t method = kDeflate;
    int level = 5;
    std::uint64_t dictionary = 0;
    int word_size = 0;
    enum class Crypt { None, ZipCrypto, Aes } crypt = Crypt::None;
    std::uint8_t strength = 3;
    std::string password;
    bool atime = false, ctime = false;
};

// Everything the central directory needs about one entry.
struct Central {
    std::uint16_t made_by = 0x033f, needed = 20, flags = 0, method = 0;
    std::uint16_t dos_time = 0, dos_date = 0;
    std::uint32_t crc = 0;
    std::uint64_t packed = 0, size = 0, offset = 0;
    std::uint32_t external = 0;
    std::uint16_t internal = 0;
    std::string name, comment;
    std::vector<std::uint8_t> extra; // without ZIP64, added when written
};

// A file squeezed in memory, waiting for its turn.
struct Prepared {
    std::vector<std::uint8_t> data; // encryption header + compressed data + MAC
    std::uint32_t crc = 0;
    std::uint64_t size = 0;
    std::uint16_t method = kStore;
};

bool ascii(std::string_view s)
{
    return std::all_of(s.begin(), s.end(), [](char c) { return std::uint8_t(c) < 0x80; });
}

std::uint16_t needed_for(std::uint16_t method, bool zip64, bool aes)
{
    std::uint16_t v = 20;
    if (zip64) v = 45;
    if (method == kBzip2) v = std::max<std::uint16_t>(v, 46);
    if (aes) v = std::max<std::uint16_t>(v, 51);
    if (method == kLzma || method == kZstd || method == kXz) v = std::max<std::uint16_t>(v, 63);
    return v;
}

Settings settings_from(const WriteOptions &o)
{
    Settings s;
    s.level = std::clamp(o.level, 0, 9);
    s.dictionary = o.dictionary;
    s.word_size = o.word_size;
    switch (o.method) {
    case Method::Default:
    case Method::Deflate: s.method = s.level == 0 ? kStore : kDeflate; break;
    case Method::Store: s.method = kStore; break;
    case Method::Bzip2: s.method = kBzip2; break;
    case Method::Lzma: s.method = kLzma; break;
    case Method::Zstd: s.method = kZstd; break;
    case Method::Xz: s.method = kXz; break;
    case Method::Deflate64:
        fail(ErrorCode::InvalidOption, "Deflate64 can be read but not written; use Deflate");
    default:
        fail(ErrorCode::InvalidOption, std::string(method_name(o.method)) +
                                           " cannot go in a ZIP archive; use Deflate, BZip2, LZMA, Zstandard, XZ or Store");
    }
    if (o.password && !o.password->empty()) {
        s.password = *o.password;
        switch (o.encryption) {
        case Encryption::ZipCrypto: s.crypt = Settings::Crypt::ZipCrypto; break;
        case Encryption::Aes128: s.crypt = Settings::Crypt::Aes; s.strength = 1; break;
        case Encryption::Aes192: s.crypt = Settings::Crypt::Aes; s.strength = 2; break;
        default: s.crypt = Settings::Crypt::Aes; s.strength = 3; break;
        }
    }
    if (o.encrypt_names) fail(ErrorCode::InvalidOption, "ZIP cannot hide file names; use 7z to encrypt them");
    s.atime = o.store_atime;
    s.ctime = o.store_ctime;
    return s;
}

Codec codec_of(std::uint16_t m)
{
    switch (m) {
    case kDeflate: return Codec::Deflate;
    case kBzip2: return Codec::Bzip2;
    case kLzma: return Codec::Lzma1Raw;
    case kZstd: return Codec::Zstd;
    default: return Codec::Xz;
    }
}

// Already-compressed content (photos, videos, archives) is stored instead:
// the try costs one 64 KiB Deflate at level 1.
bool looks_incompressible(const std::uint8_t *p, std::size_t n)
{
    if (n < 4096) return false;
    std::vector<std::uint8_t> out(compressBound(uLong(n)));
    uLongf len = uLongf(out.size());
    if (compress2(out.data(), &len, p, uLong(n), 1) != Z_OK) return false;
    return double(len) > 0.97 * double(n);
}

// XZ split in 1 MiB blocks: one big entry still uses every core. liblzma's
// own default (3x the dictionary) keeps files under 24 MiB on one thread.
class XzBlocks final : public Coder {
public:
    XzBlocks(const CodecParams &p)
    {
        lzma_mt mt{};
        mt.threads = std::uint32_t(p.threads);
        mt.preset = std::uint32_t(std::clamp(p.level, 0, 9));
        mt.check = LZMA_CHECK_CRC64;
        lzma_lzma_preset(&opt_, mt.preset);
        if (p.dictionary) opt_.dict_size = std::uint32_t(std::min<std::uint64_t>(p.dictionary, 1536u << 20));
        // Enough blocks for every thread, none under 1 MiB.
        const std::uint64_t per = p.expected_size ? (p.expected_size + mt.threads - 1) / mt.threads : opt_.dict_size;
        mt.block_size = std::clamp<std::uint64_t>(per, 1 << 20, std::max<std::uint64_t>(opt_.dict_size, 1 << 20));
        filters_[0] = {LZMA_FILTER_LZMA2, &opt_};
        filters_[1] = {LZMA_VLI_UNKNOWN, nullptr};
        mt.filters = filters_;
        if (lzma_stream_encoder_mt(&s_, &mt) != LZMA_OK) fail(ErrorCode::Internal, "liblzma init failed");
    }
    ~XzBlocks() override { lzma_end(&s_); }
    CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) override
    {
        s_.next_in = in.data();
        s_.avail_in = in.size();
        s_.next_out = out.data();
        s_.avail_out = out.size();
        const lzma_ret r = lzma_code(&s_, finish ? LZMA_FINISH : LZMA_RUN);
        if (r != LZMA_OK && r != LZMA_STREAM_END) fail(ErrorCode::Internal, "xz compression failed");
        return {in.size() - s_.avail_in, out.size() - s_.avail_out, r == LZMA_STREAM_END};
    }

private:
    lzma_stream s_ = LZMA_STREAM_INIT;
    lzma_options_lzma opt_{};
    lzma_filter filters_[2]{};
};

class Compressor {
public:
    Compressor(std::uint16_t method, const Settings &s, int threads, std::uint64_t size_hint)
    {
        CodecParams p;
        p.level = s.level;
        p.dictionary = s.dictionary;
        p.word_size = s.word_size;
        if (!p.dictionary && size_hint && (method == kLzma || method == kXz)) {
            // A dictionary bigger than the file only costs time and memory.
            static const std::uint32_t preset[10] = {256 << 10, 1 << 20, 2 << 20, 4 << 20, 4 << 20,
                                                     8 << 20, 8 << 20, 16 << 20, 32 << 20, 64 << 20};
            std::uint64_t d = 4096;
            while (d < size_hint && d < preset[s.level]) d <<= 1;
            p.dictionary = std::min<std::uint64_t>(d, preset[s.level]);
        }
        p.threads = threads;
        p.expected_size = size_hint;
        enc_ = method == kXz && threads > 1 ? std::make_unique<XzBlocks>(p) : make_encoder(codec_of(method), p);
        if (method == kLzma) {
            // 2-byte LZMA SDK version, 2-byte property size, properties.
            header_ = {0x09, 0x14, 0x05, 0x00};
            header_.insert(header_.end(), p.props.begin(), p.props.end());
        }
    }
    // Compresses in (finish: the last piece) and appends to out.
    void feed(std::span<const std::uint8_t> in, bool finish, std::vector<std::uint8_t> &out)
    {
        if (!header_.empty()) {
            out.insert(out.end(), header_.begin(), header_.end());
            header_.clear();
        }
        std::size_t pos = 0;
        for (;;) {
            const std::size_t at = out.size();
            out.resize(at + (256 << 10));
            auto st = enc_->step(in.subspan(pos), std::span(out).subspan(at), finish);
            out.resize(at + st.produced);
            pos += st.consumed;
            if (st.done) return;
            // Input used up and room left over: nothing is waiting (bzip2 refuses an empty BZ_RUN).
            if (pos == in.size() && !finish && st.produced < (256u << 10)) return;
        }
    }

private:
    std::unique_ptr<Coder> enc_;
    std::vector<std::uint8_t> header_;
};

// Encrypts the payload as it goes out.
class Encrypter {
public:
    Encrypter(const Settings &s, std::uint8_t check)
    {
        if (s.crypt == Settings::Crypt::ZipCrypto) {
            zc_.emplace(s.password);
            header_.resize(12);
            random_bytes(header_);
            header_[11] = check;
            zc_->encrypt(header_.data(), 12);
        } else if (s.crypt == Settings::Crypt::Aes) {
            const std::size_t salt = 4 * std::size_t(s.strength) + 4;
            header_.resize(salt);
            random_bytes(header_);
            AesKeys k = aes_keys(s.password, header_, s.strength);
            header_.push_back(k.verifier[0]);
            header_.push_back(k.verifier[1]);
            ctr_.emplace(k.key);
            mac_.emplace(k.mac_key);
        }
    }
    const std::vector<std::uint8_t> &header() const { return header_; }
    void process(std::uint8_t *p, std::size_t n)
    {
        if (zc_) zc_->encrypt(p, n);
        if (ctr_) {
            ctr_->process(p, n);
            mac_->update(p, n);
        }
    }
    std::vector<std::uint8_t> trailer()
    {
        if (!mac_) return {};
        auto m = mac_->final();
        return {m.begin(), m.begin() + 10};
    }
    std::size_t overhead() const { return header_.size() + (mac_ ? 10 : 0); }

private:
    std::optional<ZipCrypto> zc_;
    std::optional<AesCtrLE> ctr_;
    std::optional<HmacSha1> mac_;
    std::vector<std::uint8_t> header_;
};

std::vector<std::uint8_t> read_whole(const std::filesystem::path &p, std::uint64_t hint)
{
    Fd f(p);
    std::vector<std::uint8_t> v(std::size_t(hint) + 1);
    std::size_t n = f.read(v.data(), v.size());
    while (n == v.size()) { // grew since it was listed
        v.resize(v.size() * 2);
        n += f.read(v.data() + n, v.size() - n);
    }
    v.resize(n);
    return v;
}

class ZipWriter final : public WriterImpl {
public:
    void write(const std::vector<PlanItem> &plan, ReaderImpl *existing, Sink &sink, const WriteOptions &opts,
               Context &ctx) override
    {
        s_ = settings_from(opts);
        auto *old = dynamic_cast<ZipReader *>(existing);
        if (existing && !old) fail(ErrorCode::Internal, "existing archive is not a ZIP reader");
        Counter out(sink);
        can_rewrite_ = sink.rewrite(0, nullptr, 0);
        const unsigned threads = std::max(1, ctx.threads());

        auto small = [&](const PlanItem &p) {
            return p.kind != PlanItem::Kind::Add || p.stat.type != EntryType::File || p.stat.size <= kSmall;
        };
        std::deque<std::future<Prepared>> queue;
        std::size_t next = 0;
        std::uint64_t inflight = 0;
        try {
        for (std::size_t i = 0; i < plan.size(); ++i) {
            while (next < plan.size() && small(plan[next]) && queue.size() < 64 * threads && inflight < kInflight) {
                const PlanItem &p = plan[next];
                if (p.kind == PlanItem::Kind::Add && p.stat.type == EntryType::File) {
                    inflight += p.stat.size;
                    queue.push_back(ctx.pool().submit([this, &p, &ctx] { return prepare(p, ctx); }));
                } else {
                    std::promise<Prepared> ready;
                    ready.set_value({});
                    queue.push_back(ready.get_future());
                }
                ++next;
            }
            const PlanItem &p = plan[i];
            if (!small(p)) {
                stream_file(p, out, ctx);
                next = std::max(next, i + 1);
                continue;
            }
            Prepared pr = queue.front().get();
            queue.pop_front();
            if (p.kind == PlanItem::Kind::Keep) {
                keep(*old, p.keep_index, out, ctx);
            } else if (p.stat.type == EntryType::File) {
                inflight -= p.stat.size;
                write_prepared(p, std::move(pr), out);
                ctx.file_done();
            } else {
                write_special(p, out);
            }
        }
        } catch (...) {
            // Queued jobs point into this object: let them end first.
            for (auto &f : queue) f.wait();
            throw;
        }
        std::string comment = opts.comment;
        if (comment.empty() && old) comment = old->raw_comment();
        finish(out, comment);
    }

private:
    Central base(const PlanItem &p) const
    {
        Central c;
        c.name = p.archive_path;
        if (p.stat.type == EntryType::Directory) c.name += '/';
        if (!ascii(c.name)) c.flags |= kUtf8;
        const auto &t = p.stat.mtime;
        unix_to_dos(t ? t->seconds : 0, c.dos_time, c.dos_date);
        std::uint32_t mode = p.stat.mode.value_or(p.stat.type == EntryType::Directory ? 0755 : 0644) & 07777;
        switch (p.stat.type) {
        case EntryType::Directory: c.external = (S_IFDIR | mode) << 16 | 0x10; break;
        case EntryType::Symlink: c.external = std::uint32_t(S_IFLNK | 0777) << 16; break;
        default: c.external = (S_IFREG | mode) << 16; break;
        }
        // Unix time in both headers; NTFS times only when atime/ctime are kept.
        if (t) {
            Out e;
            e.u16(kExtraUnixTime);
            e.u16(5);
            e.u8(1);
            e.u32(std::uint32_t(std::clamp<std::int64_t>(t->seconds, INT32_MIN, INT32_MAX)));
            c.extra = e.b;
            if (s_.atime || s_.ctime) {
                Out n;
                n.u16(kExtraNtfs);
                n.u16(32);
                n.u32(0);
                n.u16(1);
                n.u16(24);
                n.u64(unix_to_filetime(*t));
                n.u64(p.stat.atime && s_.atime ? unix_to_filetime(*p.stat.atime) : unix_to_filetime(*t));
                n.u64(p.stat.ctime && s_.ctime ? unix_to_filetime(*p.stat.ctime) : unix_to_filetime(*t));
                c.extra.insert(c.extra.end(), n.b.begin(), n.b.end());
            }
        }
        return c;
    }

    void add_aes_extra(Central &c, std::uint16_t real_method) const
    {
        Out a;
        a.u16(kExtraAes);
        a.u16(7);
        a.u16(2); // AE-2: the MAC protects the data, the CRC field stays 0
        a.u8('A');
        a.u8('E');
        a.u8(s_.strength);
        a.u16(real_method);
        c.extra.insert(c.extra.end(), a.b.begin(), a.b.end());
    }

    // flags/method/needed for a file, before sizes are known.
    void file_header_fields(Central &c, std::uint16_t method, bool zip64) const
    {
        c.method = method;
        if (method == kLzma) c.flags |= kLzmaEos;
        if (s_.crypt != Settings::Crypt::None) c.flags |= kEncrypted;
        if (s_.crypt == Settings::Crypt::Aes) {
            add_aes_extra(c, method);
            c.method = kAes;
        }
        c.needed = needed_for(method, zip64, s_.crypt == Settings::Crypt::Aes);
    }

    static std::vector<std::uint8_t> local_header(const Central &c, bool zip64, std::uint64_t *z64_at = nullptr)
    {
        Out h;
        h.u32(kLocalSig);
        h.u16(c.needed);
        h.u16(c.flags);
        h.u16(c.method);
        h.u16(c.dos_time);
        h.u16(c.dos_date);
        h.u32(c.crc);
        h.u32(zip64 ? k32 : std::uint32_t(c.packed));
        h.u32(zip64 ? k32 : std::uint32_t(c.size));
        h.u16(std::uint16_t(c.name.size()));
        h.u16(std::uint16_t(c.extra.size() + (zip64 ? 20 : 0)));
        h.bytes(c.name);
        if (zip64) {
            if (z64_at) *z64_at = h.b.size() + 4;
            h.u16(kExtraZip64);
            h.u16(16);
            h.u64(c.size);
            h.u64(c.packed);
        }
        h.bytes(c.extra);
        return h.b;
    }

    Prepared prepare(const PlanItem &p, Context &ctx) const
    {
        ctx.checkpoint();
        ctx.file_started(p.archive_path);
        std::vector<std::uint8_t> raw = read_whole(p.disk, p.stat.size);
        Prepared pr;
        pr.size = raw.size();
        pr.crc = crc32(0, raw.data(), raw.size());
        std::vector<std::uint8_t> packed;
        pr.method = s_.method;
        if (pr.method != kStore && !raw.empty()) {
            const std::size_t probe = std::min<std::size_t>(raw.size(), 64 << 10);
            if (raw.size() > (256 << 10) && looks_incompressible(raw.data() + (raw.size() - probe) / 2, probe)) {
                pr.method = kStore;
            } else {
                // Only XZ can split one entry between threads.
                const int t = pr.method == kXz && raw.size() >= (2 << 20) ? ctx.threads() : 1;
                Compressor c(pr.method, s_, t, raw.size());
                c.feed(raw, true, packed);
                if (packed.size() >= raw.size()) pr.method = kStore;
            }
        }
        if (raw.empty()) pr.method = kStore;
        std::vector<std::uint8_t> &body = pr.method == kStore ? raw : packed;
        Encrypter enc(s_, std::uint8_t(pr.crc >> 24));
        enc.process(body.data(), body.size());
        pr.data.reserve(enc.overhead() + body.size());
        pr.data = enc.header();
        pr.data.insert(pr.data.end(), body.begin(), body.end());
        auto t = enc.trailer();
        pr.data.insert(pr.data.end(), t.begin(), t.end());
        ctx.add_bytes(pr.size);
        return pr;
    }

    void write_prepared(const PlanItem &p, Prepared pr, Counter &out)
    {
        Central c = base(p);
        c.size = pr.size;
        c.packed = pr.data.size();
        const bool zip64 = g_force_zip64 || c.size >= k32 || c.packed >= k32;
        file_header_fields(c, pr.method, zip64);
        c.crc = s_.crypt == Settings::Crypt::Aes ? 0 : pr.crc;
        c.offset = out.pos();
        out.write(local_header(c, zip64));
        out.write(pr.data);
        central_.push_back(std::move(c));
    }

    void write_special(const PlanItem &p, Counter &out)
    {
        Central c = base(p);
        c.offset = out.pos();
        if (p.stat.type == EntryType::Symlink) {
            const std::string &t = p.stat.link_target;
            c.crc = crc32(0, t.data(), t.size());
            c.size = c.packed = t.size();
            out.write(local_header(c, g_force_zip64));
            out.write(t.data(), t.size());
        } else {
            out.write(local_header(c, g_force_zip64));
        }
        central_.push_back(std::move(c));
    }

    void keep(ZipReader &old, std::size_t index, Counter &out, Context &ctx)
    {
        const Record &r = old.records().at(index);
        const auto span = old.raw_span(index);
        Central c;
        c.made_by = r.made_by;
        c.needed = r.needed;
        c.flags = r.flags;
        c.method = r.method;
        c.dos_time = r.dos_time;
        c.dos_date = r.dos_date;
        c.crc = r.crc;
        c.packed = r.packed;
        c.size = r.size;
        c.external = r.external_attr;
        c.internal = r.internal_attr;
        c.name = r.raw_name;
        c.comment = r.raw_comment;
        for_each_extra(std::span<const std::uint8_t>(r.extra), [&](std::uint16_t id, std::span<const std::uint8_t> d) {
            if (id == kExtraZip64) return;
            Out e;
            e.u16(id);
            e.u16(std::uint16_t(d.size()));
            e.bytes(d);
            c.extra.insert(c.extra.end(), e.b.begin(), e.b.end());
        });
        c.offset = out.pos();
        std::vector<std::uint8_t> buf(256 << 10);
        for (std::uint64_t done = 0; done < span.length;) {
            ctx.checkpoint();
            const std::size_t n = std::size_t(std::min<std::uint64_t>(buf.size(), span.length - done));
            old.source().read_exact(span.start + done, buf.data(), n);
            out.write(buf.data(), n);
            done += n;
        }
        central_.push_back(std::move(c));
    }

    // Big files: streamed, so memory stays flat whatever the size.
    void stream_file(const PlanItem &p, Counter &out, Context &ctx)
    {
        ctx.checkpoint();
        ctx.file_started(p.archive_path);
        Fd f(p.disk);
        std::uint16_t method = s_.method;
        if (method != kStore) {
            std::vector<std::uint8_t> sample(64 << 10);
            const std::size_t n = f.pread(sample.data(), sample.size(), p.stat.size / 2);
            if (looks_incompressible(sample.data(), n)) method = kStore;
        }
        const bool zip64 = g_force_zip64 || p.stat.size > kZip64Guess;
        Central c = base(p);
        file_header_fields(c, method, zip64);
        // ZipCrypto checks the time byte when the CRC comes after the data.
        const bool descriptor = !can_rewrite_ || s_.crypt == Settings::Crypt::ZipCrypto;
        if (descriptor) c.flags |= kDescriptor;
        c.offset = out.pos();
        std::uint64_t z64_at = 0;
        const auto header = local_header(c, zip64, &z64_at);
        out.write(header);
        const std::uint64_t data_at = out.pos();

        Encrypter enc(s_, std::uint8_t(c.dos_time >> 8));
        out.write(enc.header());
        std::uint32_t crc = 0;
        std::uint64_t size = 0;
        auto emit = [&](std::vector<std::uint8_t> &v) {
            enc.process(v.data(), v.size());
            out.write(v);
        };

        std::vector<std::uint8_t> chunk(kBlock);
        if (method == kDeflate) {
            parallel_deflate(f, out, ctx, crc, size, emit);
        } else {
            std::optional<Compressor> comp;
            if (method != kStore) comp.emplace(method, s_, ctx.threads(), p.stat.size);
            std::vector<std::uint8_t> packed;
            for (;;) {
                ctx.checkpoint();
                const std::size_t n = f.read(chunk.data(), chunk.size());
                crc = crc32(crc, chunk.data(), n);
                size += n;
                ctx.add_bytes(n);
                const bool last = n < chunk.size();
                if (comp) {
                    packed.clear();
                    comp->feed(std::span(chunk.data(), n), last, packed);
                    emit(packed);
                } else {
                    std::vector<std::uint8_t> v(chunk.begin(), chunk.begin() + std::ptrdiff_t(n));
                    emit(v);
                }
                if (last) break;
            }
        }
        out.write(enc.trailer());
        c.size = size;
        c.packed = out.pos() - data_at;
        c.crc = s_.crypt == Settings::Crypt::Aes ? 0 : crc;
        if (!zip64 && (c.size >= k32 || c.packed >= k32))
            fail(ErrorCode::Io, "the file grew past 4 GiB while it was being added", p.disk.string());
        if (descriptor) {
            Out d;
            d.u32(kDescriptorSig);
            d.u32(c.crc);
            if (zip64) { d.u64(c.packed); d.u64(c.size); }
            else { d.u32(std::uint32_t(c.packed)); d.u32(std::uint32_t(c.size)); }
            out.write(d.b);
        }
        if (can_rewrite_) {
            Out fix;
            fix.u32(c.crc);
            fix.u32(zip64 ? k32 : std::uint32_t(c.packed));
            fix.u32(zip64 ? k32 : std::uint32_t(c.size));
            out.sink().rewrite(c.offset + 14, fix.b.data(), fix.b.size());
            if (zip64) {
                Out z;
                z.u64(c.size);
                z.u64(c.packed);
                out.sink().rewrite(c.offset + z64_at, z.b.data(), z.b.size());
            }
        }
        central_.push_back(std::move(c));
        ctx.file_done();
    }

    template <class Emit>
    void parallel_deflate(Fd &f, Counter &, Context &ctx, std::uint32_t &crc, std::uint64_t &size, Emit &&emit)
    {
        struct Done {
            std::vector<std::uint8_t> out;
            std::uint32_t crc;
            std::size_t n;
        };
        const int level = std::clamp(s_.level, 1, 9);
        auto job = [level](std::vector<std::uint8_t> in, std::vector<std::uint8_t> dict, bool last) {
            Done d;
            d.n = in.size();
            d.crc = crc32(0, in.data(), in.size());
            z_stream z{};
            if (deflateInit2(&z, level, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) != Z_OK)
                fail(ErrorCode::Internal, "zlib init failed");
            if (!dict.empty()) deflateSetDictionary(&z, dict.data(), uInt(dict.size()));
            d.out.resize(deflateBound(&z, uLong(in.size())) + 64);
            z.next_in = in.data();
            z.avail_in = uInt(in.size());
            std::size_t at = 0;
            int r;
            do {
                if (at == d.out.size()) d.out.resize(d.out.size() * 2);
                z.next_out = d.out.data() + at;
                z.avail_out = uInt(d.out.size() - at);
                r = deflate(&z, last ? Z_FINISH : Z_SYNC_FLUSH);
                at = d.out.size() - z.avail_out;
            } while (last ? r == Z_OK : z.avail_out == 0);
            deflateEnd(&z);
            if (r != Z_STREAM_END && r != Z_OK && r != Z_BUF_ERROR) fail(ErrorCode::Internal, "deflate failed");
            d.out.resize(at);
            return d;
        };
        const std::size_t window = std::size_t(2 * std::max(1, ctx.threads()));
        std::deque<std::future<Done>> q;
        std::vector<std::uint8_t> prev_tail;
        bool eof = false;
        auto collect = [&] {
            Done d = q.front().get();
            q.pop_front();
            crc = crc32_combine(crc, d.crc, d.n);
            size += d.n;
            ctx.add_bytes(d.n);
            emit(d.out);
        };
        // Read one block ahead so the last one is known when it is sent.
        std::vector<std::uint8_t> cur(kBlock);
        cur.resize(f.read(cur.data(), kBlock));
        try {
        while (!eof) {
            ctx.checkpoint();
            std::vector<std::uint8_t> nxt(kBlock);
            nxt.resize(cur.size() < kBlock ? 0 : f.read(nxt.data(), kBlock));
            eof = nxt.empty();
            std::vector<std::uint8_t> dict = prev_tail;
            prev_tail.assign(cur.end() - std::ptrdiff_t(std::min(cur.size(), kDict)), cur.end());
            if (cur.size() < kDict && !dict.empty()) {
                // Very short block: carry the older bytes forward too.
                std::vector<std::uint8_t> joined(dict.end() - std::ptrdiff_t(std::min(dict.size(), kDict - cur.size())), dict.end());
                joined.insert(joined.end(), cur.begin(), cur.end());
                prev_tail = std::move(joined);
            }
            q.push_back(ctx.pool().submit([job, in = std::move(cur), d = std::move(dict), last = eof]() mutable {
                return job(std::move(in), std::move(d), last);
            }));
            cur = std::move(nxt);
            while (q.size() >= window || (eof && !q.empty())) collect();
        }
        } catch (...) {
            for (auto &f : q) f.wait();
            throw;
        }
    }

    void finish(Counter &out, const std::string &comment)
    {
        const std::uint64_t cd_start = out.pos();
        for (const Central &c : central_) {
            const bool big_size = g_force_zip64 || c.size >= k32;
            const bool big_packed = g_force_zip64 || c.packed >= k32;
            const bool big_offset = g_force_zip64 || c.offset >= k32;
            Out z;
            if (big_size || big_packed || big_offset) {
                Out v;
                if (big_size) v.u64(c.size);
                if (big_packed) v.u64(c.packed);
                if (big_offset) v.u64(c.offset);
                z.u16(kExtraZip64);
                z.u16(std::uint16_t(v.b.size()));
                z.bytes(v.b);
            }
            Out h;
            h.u32(kCentralSig);
            h.u16(c.made_by);
            h.u16(z.b.empty() ? c.needed : std::max<std::uint16_t>(c.needed, 45));
            h.u16(c.flags);
            h.u16(c.method);
            h.u16(c.dos_time);
            h.u16(c.dos_date);
            h.u32(c.crc);
            h.u32(big_packed ? k32 : std::uint32_t(c.packed));
            h.u32(big_size ? k32 : std::uint32_t(c.size));
            h.u16(std::uint16_t(c.name.size()));
            h.u16(std::uint16_t(z.b.size() + c.extra.size()));
            h.u16(std::uint16_t(c.comment.size()));
            h.u16(0);
            h.u16(c.internal);
            h.u32(c.external);
            h.u32(big_offset ? k32 : std::uint32_t(c.offset));
            h.bytes(c.name);
            h.bytes(z.b);
            h.bytes(c.extra);
            h.bytes(c.comment);
            out.write(h.b);
        }
        const std::uint64_t cd_size = out.pos() - cd_start;
        const std::uint64_t count = central_.size();
        const bool zip64 = g_force_zip64 || count >= 0xffff || cd_size >= k32 || cd_start >= k32;
        if (zip64) {
            const std::uint64_t z64 = out.pos();
            Out e;
            e.u32(kEnd64Sig);
            e.u64(kEnd64Size - 12);
            e.u16(0x033f);
            e.u16(45);
            e.u32(0);
            e.u32(0);
            e.u64(count);
            e.u64(count);
            e.u64(cd_size);
            e.u64(cd_start);
            e.u32(kLocator64Sig);
            e.u32(0);
            e.u64(z64);
            e.u32(1);
            out.write(e.b);
        }
        Out e;
        e.u32(kEndSig);
        e.u16(0);
        e.u16(0);
        e.u16(zip64 ? 0xffff : std::uint16_t(count));
        e.u16(zip64 ? 0xffff : std::uint16_t(count));
        e.u32(zip64 ? k32 : std::uint32_t(cd_size));
        e.u32(zip64 ? k32 : std::uint32_t(cd_start));
        const std::size_t clen = std::min<std::size_t>(comment.size(), 0xffff);
        e.u16(std::uint16_t(clen));
        e.bytes(std::string_view(comment).substr(0, clen));
        out.write(e.b);
    }

    Settings s_;
    bool can_rewrite_ = false;
    std::vector<Central> central_;
};

} // namespace

std::unique_ptr<WriterImpl> make_writer() { return std::make_unique<ZipWriter>(); }

} // namespace raye::archive::detail::zip
