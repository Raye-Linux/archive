// SPDX-License-Identifier: GPL-3.0-or-later
#include "reader.h"

#include "../../core/checksum.h"
#include "../../core/crypto.h"

#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <sys/stat.h>

namespace raye::archive::detail::zip {

namespace fs = std::filesystem;

namespace {

constexpr std::size_t kChunk = 256 << 10;

std::string decode_name(const std::string &raw, bool utf8_flag)
{
    if (utf8_flag && valid_utf8(raw)) return raw;
    if (valid_utf8(raw)) return raw;
    return cp437_to_utf8(raw);
}

struct EndRecord {
    std::uint64_t pos = 0; // where the PK\5\6 record sits
    std::uint32_t disk = 0, cd_disk = 0;
    std::uint64_t count = 0, cd_size = 0, cd_offset = 0;
    std::uint64_t cd_end = 0; // real position the central directory ends at
    bool zip64 = false;
};

std::optional<EndRecord> find_end(const Source &src, std::uint64_t size, std::string &comment)
{
    if (size < kEndSize) return std::nullopt;
    const std::uint64_t span = std::min<std::uint64_t>(size, kEndSize + 0xffff + 64);
    std::vector<std::uint8_t> tail(span);
    src.read_exact(size - span, tail.data(), span);
    std::optional<std::size_t> best;
    for (std::size_t i = span - kEndSize + 1; i-- > 0;) {
        if (le32(&tail[i]) != kEndSig) continue;
        const std::size_t clen = le16(&tail[i + 20]);
        if (i + kEndSize + clen == span) { best = i; break; }
        if (!best && i + kEndSize + clen <= span) best = i; // junk after the comment
    }
    if (!best) return std::nullopt;
    const std::uint8_t *p = &tail[*best];
    EndRecord e;
    e.pos = size - span + *best;
    e.disk = le16(p + 4);
    e.cd_disk = le16(p + 6);
    e.count = le16(p + 10);
    e.cd_size = le32(p + 12);
    e.cd_offset = le32(p + 16);
    e.cd_end = e.pos;
    const std::size_t clen = std::min<std::size_t>(le16(p + 20), span - *best - kEndSize);
    comment.assign(reinterpret_cast<const char *>(p + kEndSize), clen);

    // ZIP64 locator right before the end record.
    if (e.pos >= kLocator64Size) {
        std::uint8_t loc[kLocator64Size];
        src.read_exact(e.pos - kLocator64Size, loc, sizeof loc);
        if (le32(loc) == kLocator64Sig) {
            const std::uint64_t z64_off = le64(loc + 8);
            // Usually right before the locator; otherwise trust the stored offset.
            std::uint64_t at = e.pos - kLocator64Size >= kEnd64Size ? e.pos - kLocator64Size - kEnd64Size : 0;
            std::uint8_t z[kEnd64Size];
            bool ok = false;
            for (std::uint64_t cand : {at, z64_off}) {
                if (cand + kEnd64Size > size) continue;
                src.read_exact(cand, z, sizeof z);
                if (le32(z) == kEnd64Sig) { at = cand; ok = true; break; }
            }
            if (!ok) fail(ErrorCode::Corrupt, "ZIP64 end record is missing");
            e.zip64 = true;
            e.disk = le32(z + 16);
            e.cd_disk = le32(z + 20);
            e.count = le64(z + 32);
            e.cd_size = le64(z + 40);
            e.cd_offset = le64(z + 48);
            e.cd_end = at;
        }
    }
    return e;
}

void parse_extra(Record &r, std::span<const std::uint8_t> extra, bool central)
{
    for_each_extra(extra, [&](std::uint16_t id, std::span<const std::uint8_t> d) {
        ByteReader b(d);
        switch (id) {
        case kExtraZip64: {
            r.zip64 = true;
            auto take = [&](auto &field, std::uint64_t mark) {
                if (field == mark && b.left() >= 8) field = std::remove_reference_t<decltype(field)>(b.u64());
            };
            take(r.size, 0xffffffffu);
            take(r.packed, 0xffffffffu);
            if (central) {
                take(r.local_offset, 0xffffffffu);
                if (r.disk == 0xffff && b.left() >= 4) r.disk = b.u32();
            }
            break;
        }
        case kExtraNtfs: {
            if (d.size() < 4) break;
            b.skip(4);
            while (b.left() >= 4) {
                const auto tag = b.u16(), len = b.u16();
                if (len > b.left()) break;
                if (tag == 1 && len >= 24) {
                    const auto m = b.u64(), a = b.u64(), c = b.u64();
                    if (m) r.mtime = filetime_to_unix(m);
                    if (a) r.atime = filetime_to_unix(a);
                    if (c) r.ctime = filetime_to_unix(c);
                    b.skip(len - 24);
                } else {
                    b.skip(len);
                }
            }
            break;
        }
        case kExtraUnixTime: {
            if (d.empty()) break;
            const auto flags = b.u8();
            auto get = [&]() -> std::optional<Timestamp> {
                if (b.left() < 4) return std::nullopt;
                return Timestamp{std::int64_t(std::int32_t(b.u32())), 0};
            };
            std::optional<Timestamp> m, a, c;
            if (flags & 1) m = get();
            if (flags & 2) a = get();
            if (flags & 4) c = get();
            // NTFS times are finer: they win when both are there.
            if (m && !r.mtime) r.mtime = m;
            if (a && !r.atime) r.atime = a;
            if (c && !r.ctime) r.ctime = c;
            break;
        }
        case kExtraUnicodePath: {
            if (d.size() < 5 || d[0] != 1) break;
            const std::uint32_t want = le32(&d[1]);
            if (crc32(0, r.raw_name.data(), r.raw_name.size()) != want) break;
            std::string u(reinterpret_cast<const char *>(d.data() + 5), d.size() - 5);
            if (valid_utf8(u)) r.name = std::move(u);
            break;
        }
        case kExtraUnicodeComment: {
            if (d.size() < 5 || d[0] != 1) break;
            std::string u(reinterpret_cast<const char *>(d.data() + 5), d.size() - 5);
            if (crc32(0, r.raw_comment.data(), r.raw_comment.size()) == le32(&d[1]) && valid_utf8(u)) r.comment = std::move(u);
            break;
        }
        case kExtraAes: {
            if (d.size() < 7 || d[2] != 'A' || d[3] != 'E') break;
            AesInfo a;
            a.version = le16(&d[0]);
            a.strength = d[4];
            a.method = le16(&d[5]);
            r.aes = a;
            break;
        }
        default: break;
        }
    });
}

// ---- data pump: decrypt, decompress, check

class Decryptor {
public:
    virtual ~Decryptor() = default;
    virtual void process(std::uint8_t *p, std::size_t n) = 0;
    virtual void finish(const Source &, std::uint64_t, const std::string &) {}
};

class ZipCryptoDec final : public Decryptor {
public:
    explicit ZipCryptoDec(ZipCrypto c) : c_(c) {}
    void process(std::uint8_t *p, std::size_t n) override { c_.decrypt(p, n); }

private:
    ZipCrypto c_;
};

class AesDec final : public Decryptor {
public:
    AesDec(const AesKeys &k) : ctr_(k.key), mac_(k.mac_key) {}
    void process(std::uint8_t *p, std::size_t n) override
    {
        mac_.update(p, n);
        ctr_.process(p, n);
    }
    void finish(const Source &src, std::uint64_t at, const std::string &path) override
    {
        std::uint8_t code[10];
        src.read_exact(at, code, sizeof code);
        const auto want = mac_.final();
        if (std::memcmp(code, want.data(), 10) != 0)
            fail(ErrorCode::Checksum, "the data does not match its AES authentication code", path);
    }

private:
    AesCtrLE ctr_;
    HmacSha1 mac_;
};

std::unique_ptr<Coder> decoder_for(std::uint16_t method, const std::string &path)
{
    switch (method) {
    case kDeflate: return make_decoder(Codec::Deflate);
    case kDeflate64: return make_deflate64_decoder();
    case kBzip2: return make_decoder(Codec::Bzip2);
    case kZstd: case 20: return make_decoder(Codec::Zstd);
    case kXz: return make_decoder(Codec::Xz);
    default: break;
    }
    fail(ErrorCode::UnsupportedMethod,
         std::string("compression method ") + std::to_string(method) + " (" + method_label(method) + ") is not supported",
         path);
}

} // namespace

ZipReader::ZipReader(const OpenRequest &req, Context &)
    : src_(req.source), size_(req.source->size())
{
    std::string comment;
    if (auto end = find_end(*src_, size_, comment)) {
        raw_comment_ = comment;
        if (end->disk > 0) {
            // Spanned set (.z01 ... .zip): offsets are per disk.
            if (req.volumes.size() < std::size_t(end->disk) + 1)
                fail(ErrorCode::MissingVolume, "this is the last part of a split ZIP; the other parts (.z01, .z02 ...) are missing",
                     req.name);
            std::uint64_t at = 0;
            for (std::size_t i = 0; i <= end->disk; ++i) {
                disk_start_.push_back(at);
                std::error_code ec;
                at += fs::file_size(req.volumes[i], ec);
                if (ec) fail(ErrorCode::MissingVolume, "a part of this split ZIP cannot be read", req.volumes[i].string());
            }
            info_.volume_count = disk_start_.size();
        }
        std::uint64_t cd = 0;
        if (!disk_start_.empty()) {
            cd = resolve(end->cd_disk, end->cd_offset);
        } else {
            // A stub in front (self-extracting, or cat stub zip) shifts every offset.
            const std::int64_t want = std::int64_t(end->cd_end) - std::int64_t(end->cd_size);
            delta_ = want - std::int64_t(end->cd_offset);
            std::uint8_t sig[4] = {};
            auto sig_at = [&](std::int64_t at) {
                if (at < 0 || std::uint64_t(at) + 4 > size_) return false;
                src_->read_exact(std::uint64_t(at), sig, 4);
                return le32(sig) == kCentralSig;
            };
            if (end->count && !sig_at(std::int64_t(end->cd_offset) + delta_)) {
                if (sig_at(std::int64_t(end->cd_offset))) delta_ = 0;
                else fail(ErrorCode::Corrupt, "the ZIP central directory is not where the archive says", req.name);
            }
            if (delta_ < 0) delta_ = 0;
            cd = end->cd_offset + std::uint64_t(delta_);
        }
        if (cd > size_ || end->cd_size > size_ - cd) fail(ErrorCode::Truncated, "the ZIP central directory is cut short", req.name);
        check_alloc(end->cd_size, size_);
        std::vector<std::uint8_t> buf(end->cd_size);
        src_->read_exact(cd, buf.data(), buf.size());
        ByteReader b(buf);
        while (b.left() >= kCentralSize && le32(buf.data() + b.pos()) == kCentralSig) {
            b.skip(4);
            Record r;
            r.made_by = b.u16();
            r.needed = b.u16();
            r.flags = b.u16();
            r.method = b.u16();
            r.dos_time = b.u16();
            r.dos_date = b.u16();
            r.crc = b.u32();
            r.packed = b.u32();
            r.size = b.u32();
            const auto nlen = b.u16(), elen = b.u16(), clen = b.u16();
            r.disk = b.u16();
            r.internal_attr = b.u16();
            r.external_attr = b.u32();
            r.local_offset = b.u32();
            r.raw_name = b.str(nlen);
            auto ex = b.bytes(elen);
            r.extra.assign(ex.begin(), ex.end());
            r.raw_comment = b.str(clen);
            r.name = decode_name(r.raw_name, r.flags & kUtf8);
            r.comment = decode_name(r.raw_comment, r.flags & kUtf8);
            parse_extra(r, r.extra, true);
            if (r.disk == 0xffff && !r.zip64) r.disk = 0;
            r.local_offset = resolve(r.disk, r.local_offset);
            recs_.push_back(std::move(r));
        }
        if (recs_.empty() && end->count) fail(ErrorCode::Corrupt, "the ZIP central directory is damaged", req.name);
        info_.detail = end->zip64 ? "ZIP64" : "ZIP";
        if (!disk_start_.empty()) info_.detail += ", split in " + std::to_string(disk_start_.size()) + " parts";
    } else {
        scan_local_headers();
        if (recs_.empty())
            fail(ErrorCode::Truncated, "the end of this ZIP archive is missing and nothing in it can be read", req.name);
        info_.detail = "ZIP, damaged (central directory missing, read from the file headers)";
    }
    info_.comment = decode_name(raw_comment_, false);
    for (auto &r : recs_) info_.has_encrypted_entries = info_.has_encrypted_entries || (r.flags & kEncrypted);
    make_entries();
}

std::uint64_t ZipReader::resolve(std::uint32_t disk, std::uint64_t offset) const
{
    if (disk_start_.empty()) return offset + std::uint64_t(delta_);
    if (disk >= disk_start_.size()) fail(ErrorCode::Corrupt, "entry points to a part that does not exist");
    return disk_start_[disk] + offset;
}

// Truncated download, no central directory: walk the local headers.
void ZipReader::scan_local_headers()
{
    std::uint64_t pos = 0;
    while (pos + kLocalSize <= size_) {
        std::uint8_t h[kLocalSize];
        src_->read_exact(pos, h, sizeof h);
        if (le32(h) != kLocalSig) break;
        Record r;
        r.needed = le16(h + 4);
        r.flags = le16(h + 6);
        r.method = le16(h + 8);
        r.dos_time = le16(h + 10);
        r.dos_date = le16(h + 12);
        r.crc = le32(h + 14);
        r.packed = le32(h + 18);
        r.size = le32(h + 22);
        const std::uint16_t nlen = le16(h + 26), elen = le16(h + 28);
        if (pos + kLocalSize + nlen + elen > size_) break;
        std::vector<std::uint8_t> ne(nlen + elen);
        src_->read_exact(pos + kLocalSize, ne.data(), ne.size());
        r.raw_name.assign(reinterpret_cast<const char *>(ne.data()), nlen);
        r.name = decode_name(r.raw_name, r.flags & kUtf8);
        r.extra.assign(ne.begin() + nlen, ne.end());
        parse_extra(r, r.extra, false);
        r.local_offset = pos;
        r.made_by = 3 << 8; // unknown host: names stay as stored
        const std::uint64_t data = pos + kLocalSize + nlen + elen;
        std::uint64_t end;
        if (r.flags & kDescriptor) {
            // Sizes come after the data. Only deflate tells us where it ends.
            if (r.method != kDeflate || (r.flags & kEncrypted)) break;
            z_stream z{};
            if (inflateInit2(&z, -15) != Z_OK) break;
            std::vector<std::uint8_t> in(kChunk), out(kChunk);
            std::uint64_t at = data, produced = 0;
            std::uint32_t crc = 0;
            int ret = Z_OK;
            while (ret == Z_OK) {
                const std::size_t n = src_->read_at(at, in.data(), in.size());
                if (!n) break;
                z.next_in = in.data();
                z.avail_in = uInt(n);
                do {
                    z.next_out = out.data();
                    z.avail_out = uInt(out.size());
                    ret = inflate(&z, Z_NO_FLUSH);
                    const std::size_t got = out.size() - z.avail_out;
                    crc = std::uint32_t(::crc32(crc, out.data(), uInt(got)));
                    produced += got;
                } while (ret == Z_OK && z.avail_in && z.avail_out == 0);
                at += n - z.avail_in;
                if (ret == Z_OK && z.avail_in) ret = Z_DATA_ERROR;
            }
            inflateEnd(&z);
            if (ret != Z_STREAM_END) {
                // Cut in the middle of this file: list it, extraction will say why.
                r.packed = size_ - data;
                r.size = produced;
                r.crc = crc;
                recs_.push_back(std::move(r));
                break;
            }
            r.packed = at - data;
            r.size = produced;
            r.crc = crc;
            end = at;
            std::uint8_t d[4] = {};
            if (end + 4 <= size_) {
                src_->read_exact(end, d, 4);
                end += le32(d) == kDescriptorSig ? 4 : 0;
            }
            end += r.zip64 ? 20 : 12;
        } else {
            end = data + r.packed;
        }
        recs_.push_back(std::move(r));
        if (end > size_) break;
        pos = end;
    }
}

void ZipReader::make_entries()
{
    entries_.clear();
    entries_.reserve(recs_.size());
    for (std::size_t i = 0; i < recs_.size(); ++i) {
        const Record &r = recs_[i];
        Entry e;
        e.index = i;
        const std::uint8_t host = std::uint8_t(r.made_by >> 8);
        e.path = r.name;
        if (dos_like_host(host)) std::replace(e.path.begin(), e.path.end(), '\\', '/');
        const std::uint32_t unix_mode = unix_like_host(host) ? r.external_attr >> 16 : 0;
        const bool slash = !e.path.empty() && e.path.back() == '/';
        if (slash || (unix_mode & S_IFMT) == S_IFDIR || (dos_like_host(host) && (r.external_attr & 0x10)))
            e.type = EntryType::Directory;
        else if ((unix_mode & S_IFMT) == S_IFLNK)
            e.type = EntryType::Symlink;
        while (!e.path.empty() && e.path.back() == '/') e.path.pop_back();
        if (unix_mode & 07777) e.mode = unix_mode & 07777;
        if (dos_like_host(host)) e.windows_attributes = r.external_attr & 0xffff;
        e.size = r.size;
        e.packed_size = r.packed;
        e.mtime = r.mtime ? r.mtime : dos_to_unix(r.dos_time, r.dos_date);
        e.atime = r.atime;
        e.ctime = r.ctime;
        e.encrypted = r.flags & kEncrypted;
        if (!r.aes || r.aes->version != 2 || r.crc) e.crc32 = r.crc;
        e.method = method_label(r.real_method());
        if (r.aes) e.method += std::string(", AES-") + std::to_string(r.aes->key_size() * 8);
        else if (e.encrypted) e.method += ", ZipCrypto";
        e.comment = r.comment;
        e.volume = r.disk;
        entries_.push_back(std::move(e));
    }
}

std::vector<Entry> ZipReader::list(Context &ctx)
{
    if (!links_read_) {
        links_read_ = true;
        for (auto &e : entries_) {
            if (e.type != EntryType::Symlink || e.encrypted || e.size > 4096) continue;
            MemorySink m;
            try {
                decode(e.index, &m, ctx);
                e.link_target.assign(m.bytes().begin(), m.bytes().end());
            } catch (const Error &) {
                // Damaged link: extraction will report it.
            }
        }
    }
    return entries_;
}

std::uint64_t ZipReader::data_start(const Record &r) const
{
    std::uint8_t h[kLocalSize];
    if (r.local_offset > size_ || kLocalSize > size_ - r.local_offset)
        fail(ErrorCode::Truncated, "the archive ends before this file", r.name);
    src_->read_exact(r.local_offset, h, sizeof h);
    if (le32(h) != kLocalSig) fail(ErrorCode::Corrupt, "the file header is missing or damaged", r.name);
    const std::uint64_t start = r.local_offset + kLocalSize + le16(h + 26) + le16(h + 28);
    if (start > size_ || r.packed > size_ - start) fail(ErrorCode::Truncated, "the archive ends in the middle of this file", r.name);
    return start;
}

void ZipReader::decode(std::size_t i, Sink *sink, Context &ctx)
{
    const Record &r = recs_.at(i);
    const std::string &path = r.name;
    if (r.flags & kStrongEncryption) fail(ErrorCode::UnsupportedMethod, "PKWARE strong encryption is not supported", path);
    std::uint64_t at = data_start(r);
    std::uint64_t left = r.packed;
    std::unique_ptr<Decryptor> dec;
    std::uint64_t mac_at = 0;
    bool zipcrypto = false;

    if (r.flags & kEncrypted) {
        if (r.method == kAes) {
            if (!r.aes || r.aes->strength < 1 || r.aes->strength > 3)
                fail(ErrorCode::UnsupportedMethod, "unknown AES settings", path);
            const std::size_t salt_len = r.aes->salt_size();
            if (left < salt_len + 2 + 10) fail(ErrorCode::Corrupt, "encrypted file is too short", path);
            std::vector<std::uint8_t> head(salt_len + 2);
            src_->read_exact(at, head.data(), head.size());
            for (int attempt = 1;; ++attempt) {
                const std::string pw = ctx.password(path, attempt);
                AesKeys k = aes_keys(pw, std::span(head).first(salt_len), r.aes->strength);
                if (k.verifier[0] == head[salt_len] && k.verifier[1] == head[salt_len + 1]) {
                    ctx.password_ok(pw);
                    dec = std::make_unique<AesDec>(k);
                    break;
                }
            }
            at += head.size();
            left -= head.size() + 10;
            mac_at = at + left;
        } else {
            if (left < 12) fail(ErrorCode::Corrupt, "encrypted file is too short", path);
            std::uint8_t head[12];
            src_->read_exact(at, head, 12);
            for (int attempt = 1;; ++attempt) {
                const std::string pw = ctx.password(path, attempt);
                ZipCrypto c(pw);
                std::uint8_t h[12];
                std::memcpy(h, head, 12);
                c.decrypt(h, 12);
                const bool ok = h[11] == std::uint8_t(r.crc >> 24) ||
                                ((r.flags & kDescriptor) && h[11] == std::uint8_t(r.dos_time >> 8));
                if (ok) {
                    ctx.password_ok(pw);
                    dec = std::make_unique<ZipCryptoDec>(c);
                    break;
                }
            }
            at += 12;
            left -= 12;
            zipcrypto = true;
        }
    } else if (r.method == kAes) {
        fail(ErrorCode::Corrupt, "AES method on a file that is not encrypted", path);
    }

    const std::uint16_t method = r.real_method();
    SourceReader rd(*src_, at, at + left);
    std::vector<std::uint8_t> in(std::size_t(std::min<std::uint64_t>(left, kChunk))), out;
    std::size_t pend = 0, off = 0;
    std::uint64_t written = 0;
    std::uint32_t crc = 0;
    auto read_more = [&] {
        const std::size_t n = std::size_t(std::min<std::uint64_t>(left, in.size()));
        rd.read_exact(in.data(), n);
        if (dec) dec->process(in.data(), n);
        left -= n;
        pend = n;
        off = 0;
    };
    auto emit = [&](const std::uint8_t *p, std::size_t n) {
        written += n;
        if (written > r.size) fail(ErrorCode::Corrupt, "file is bigger than its header says", path);
        crc = crc32(crc, p, n);
        if (sink) sink->write(p, n);
        ctx.add_bytes(n);
    };

    try {
        if (method == kStore) {
            while (left) {
                ctx.checkpoint();
                read_more();
                emit(in.data(), pend);
            }
        } else {
            std::unique_ptr<Coder> coder;
            bool stop_at_size = false;
            if (left) read_more();
            if (method == kLzma) {
                // 2-byte version, 2-byte property size, then the 5 LZMA properties.
                if (pend < 9 || le16(&in[2]) != 5) fail(ErrorCode::Corrupt, "bad LZMA header", path);
                CodecParams p;
                p.props.assign(in.begin() + 4, in.begin() + 9);
                coder = make_decoder(Codec::Lzma1Raw, p);
                off = 9;
                pend -= 9;
                stop_at_size = !(r.flags & kLzmaEos);
            } else {
                coder = decoder_for(method, path);
            }
            out.resize(kChunk);
            for (;;) {
                ctx.checkpoint();
                if (stop_at_size && written == r.size) break;
                if (!pend && left) read_more();
                const bool finish = left == 0;
                auto s = coder->step(std::span(in.data() + off, pend), out, finish);
                off += s.consumed;
                pend -= s.consumed;
                if (s.produced) emit(out.data(), s.produced);
                if (s.done) break;
                if (!s.consumed && !s.produced && finish && !pend) {
                    if (stop_at_size && written == r.size) break;
                    fail(ErrorCode::Truncated, "compressed data ends early", path);
                }
            }
        }
        if (written != r.size) fail(ErrorCode::Corrupt, "file size does not match its header", path);
        if (dec) dec->finish(*src_, mac_at, path);
        const bool check_crc = !r.aes || r.aes->version != 2 || r.crc;
        if (check_crc && crc != r.crc) fail(ErrorCode::Checksum, "CRC does not match: the file is damaged", path);
    } catch (const Error &e) {
        // A wrong ZipCrypto password passes the 1-byte check once in 256.
        if (zipcrypto && (e.code() == ErrorCode::Checksum || e.code() == ErrorCode::Corrupt || e.code() == ErrorCode::Truncated))
            fail(ErrorCode::WrongPassword, "the password is wrong, or the file is damaged", path);
        throw;
    }
}

void ZipReader::extract_one(std::size_t i, EntryHandler &handler, Context &ctx)
{
    Entry e = entries_.at(i);
    Sink *sink = nullptr;
    try {
        if (e.type == EntryType::Symlink && e.link_target.empty()) {
            MemorySink m;
            decode(i, &m, ctx);
            e.link_target.assign(m.bytes().begin(), m.bytes().end());
            entries_[i].link_target = e.link_target;
        }
        sink = handler.begin(e);
        if (sink && e.type == EntryType::File) decode(i, sink, ctx);
        handler.end(e, sink);
    } catch (const Error &err) {
        if (err.code() == ErrorCode::Cancelled) throw;
        handler.failed(e, sink, err);
    }
}

void ZipReader::extract(const std::vector<std::size_t> &indexes, EntryHandler &handler, Context &ctx)
{
    std::vector<std::size_t> dirs, files, links;
    for (auto i : indexes) {
        if (i >= entries_.size()) fail(ErrorCode::NotFound, "no entry number " + std::to_string(i));
        switch (entries_[i].type) {
        case EntryType::Directory: dirs.push_back(i); break;
        case EntryType::Symlink: links.push_back(i); break;
        default: files.push_back(i); break;
        }
    }
    for (auto i : dirs) extract_one(i, handler, ctx);
    // The first encrypted file is done alone, so the password is asked once.
    auto first_enc = std::find_if(files.begin(), files.end(), [&](std::size_t i) { return entries_[i].encrypted; });
    if (first_enc != files.end()) {
        extract_one(*first_enc, handler, ctx);
        files.erase(first_enc);
    }
    // Biggest first keeps every core busy until the end.
    std::stable_sort(files.begin(), files.end(), [&](std::size_t a, std::size_t b) { return entries_[a].packed_size > entries_[b].packed_size; });
    std::uint64_t packed = 0;
    for (auto i : files) packed += entries_[i].packed_size;
    // Starting the workers costs more than a handful of small files.
    if (ctx.threads() > 1 && files.size() > 1 && (packed > (1 << 20) || files.size() > 32))
        ctx.pool().parallel_for(files.size(), [&](std::size_t k) { extract_one(files[k], handler, ctx); });
    else
        for (auto i : files) extract_one(i, handler, ctx);
    // Links last: nothing gets written through one.
    for (auto i : links) extract_one(i, handler, ctx);
}

ZipReader::RawSpan ZipReader::raw_span(std::size_t i) const
{
    const Record &r = recs_.at(i);
    RawSpan s;
    s.start = r.local_offset;
    std::uint8_t h[kLocalSize];
    src_->read_exact(r.local_offset, h, sizeof h);
    if (le32(h) != kLocalSig) fail(ErrorCode::Corrupt, "the file header is missing or damaged", r.name);
    const std::uint16_t nlen = le16(h + 26), elen = le16(h + 28);
    std::vector<std::uint8_t> ex(elen);
    src_->read_exact(r.local_offset + kLocalSize + nlen, ex.data(), ex.size());
    for_each_extra(std::span<const std::uint8_t>(ex), [&](std::uint16_t id, auto) { if (id == kExtraZip64) s.local_zip64 = true; });
    std::uint64_t end = data_start(r) + r.packed;
    if (le16(h + 6) & kDescriptor) {
        std::uint8_t d[4] = {};
        if (end + 4 <= size_) src_->read_exact(end, d, 4);
        if (le32(d) == kDescriptorSig) end += 4;
        end += s.local_zip64 ? 20 : 12;
        if (end > size_) fail(ErrorCode::Truncated, "the archive ends in the middle of this file", r.name);
    }
    s.length = end - s.start;
    return s;
}

bool ZipReader::copy_raw(std::size_t i, Sink &out, Context &ctx)
{
    const RawSpan s = raw_span(i);
    std::vector<std::uint8_t> buf(kChunk);
    for (std::uint64_t done = 0; done < s.length;) {
        ctx.checkpoint();
        const std::size_t n = std::size_t(std::min<std::uint64_t>(buf.size(), s.length - done));
        src_->read_exact(s.start + done, buf.data(), n);
        out.write(buf.data(), n);
        done += n;
    }
    return true;
}

} // namespace raye::archive::detail::zip
