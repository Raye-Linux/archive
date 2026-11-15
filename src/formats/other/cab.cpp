// SPDX-License-Identifier: GPL-3.0-or-later
// Microsoft cabinets: stored, MSZIP and LZX folders. Each folder is one
// solid stream; separate folders decode in parallel.
#include "items.h"
#include "lzx.h"
#include "readers.h"

#include "../../core/bytes.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <map>
#include <zlib.h>

namespace raye::archive::detail {

namespace {

[[noreturn]] void damaged(const char *what = "cabinet is damaged") { fail(ErrorCode::Corrupt, what); }

std::uint32_t cab_sum(const std::uint8_t *p, std::size_t n, std::uint32_t seed)
{
    std::uint32_t c = seed;
    std::size_t i = 0;
    for (; i + 4 <= n; i += 4) c ^= le32(p + i);
    std::uint32_t ul = 0;
    switch (n % 4) {
    case 3: ul |= std::uint32_t(p[i++]) << 16; [[fallthrough]];
    case 2: ul |= std::uint32_t(p[i++]) << 8; [[fallthrough]];
    case 1: ul |= p[i++]; break;
    default: break;
    }
    return c ^ ul;
}

struct Folder {
    std::uint32_t data_off = 0;
    std::uint16_t blocks = 0, type = 0;
};

struct CabFile {
    std::uint32_t size = 0, offset = 0;
    std::uint16_t folder = 0;
};

class CabReader final : public ReaderImpl {
public:
    CabReader(std::shared_ptr<Source> src, std::uint64_t start) : src_(std::move(src)), start_(start)
    {
        const std::uint64_t size = src_->size();
        std::uint8_t h[36];
        src_->read_exact(start_, h, 36);
        if (std::memcmp(h, "MSCF", 4) != 0) damaged();
        const std::uint32_t cab_size = le32(h + 8), files_off = le32(h + 16);
        const std::uint16_t nfolders = le16(h + 26), nfiles = le16(h + 28), flags = le16(h + 30);
        if (h[25] != 1) fail(ErrorCode::UnsupportedMethod, "cabinet version is not supported");
        if (flags & 3) fail(ErrorCode::UnsupportedMethod, "cabinets spread over several files are not supported yet");
        if (cab_size > size - start_ + 16) fail(ErrorCode::Truncated, "cabinet ends early");
        std::uint64_t p = start_ + 36;
        unsigned folder_res = 0;
        if (flags & 4) {
            std::uint8_t r[4];
            src_->read_exact(p, r, 4);
            folder_res = r[2];
            data_res_ = r[3];
            p += 4 + le16(r);
        }
        for (unsigned i = 0; i < nfolders; ++i) {
            std::uint8_t f[8];
            src_->read_exact(p, f, 8);
            folders_.push_back({le32(f), le16(f + 4), le16(f + 6)});
            p += 8 + folder_res;
        }
        p = start_ + files_off;
        for (unsigned i = 0; i < nfiles; ++i) {
            std::uint8_t f[16];
            src_->read_exact(p, f, 16);
            p += 16;
            std::string name;
            for (std::uint8_t c; name.size() < 4096;) {
                src_->read_exact(p++, &c, 1);
                if (!c) break;
                name.push_back(char(c));
            }
            const std::uint16_t attr = le16(f + 14);
            if (!(attr & 0x80)) name = legacy_name_to_utf8(name); // 0x80: name is UTF-8
            std::replace(name.begin(), name.end(), '\\', '/');
            CabFile cf{le32(f), le32(f + 4), le16(f + 8)};
            if (cf.folder >= nfolders) fail(ErrorCode::UnsupportedMethod, "file continues in another cabinet", name);
            Entry e;
            e.path = name;
            e.size = cf.size;
            e.windows_attributes = attr & 0x3f;
            e.mode = (attr & 1) ? 0444 : 0644;
            e.solid = true;
            const std::uint16_t date = le16(f + 10), time = le16(f + 12);
            struct tm tm{};
            tm.tm_year = (date >> 9) + 80;
            tm.tm_mon = ((date >> 5) & 15) - 1;
            tm.tm_mday = date & 31;
            tm.tm_hour = time >> 11;
            tm.tm_min = (time >> 5) & 63;
            tm.tm_sec = (time & 31) * 2;
            tm.tm_isdst = -1;
            if (tm.tm_mday) e.mtime = Timestamp{std::int64_t(mktime(&tm)), 0};
            const unsigned t = folders_[cf.folder].type & 15;
            e.method = t == 0 ? "Store" : t == 1 ? "MSZIP" : t == 2 ? "Quantum" : t == 3 ? "LZX:" + std::to_string((folders_[cf.folder].type >> 8) & 31) : "?";
            files_.push_back(cf);
            entries_.push_back(std::move(e));
        }
        info_.detail = "cabinet";
        info_.solid = true;
    }

    ArchiveInfo info() const override { return info_; }
    std::vector<Entry> list(Context &) override
    {
        for (std::size_t i = 0; i < entries_.size(); ++i) entries_[i].index = i;
        return entries_;
    }

    void extract(const std::vector<std::size_t> &indexes, EntryHandler &h, Context &ctx) override
    {
        std::map<unsigned, std::vector<std::size_t>> by_folder;
        for (auto i : indexes) {
            if (i >= files_.size()) fail(ErrorCode::NotFound, "no entry number " + std::to_string(i));
            by_folder[files_[i].folder].push_back(i);
        }
        std::vector<std::pair<unsigned, std::vector<std::size_t>>> work(by_folder.begin(), by_folder.end());
        ctx.pool().parallel_for(work.size(), [&](std::size_t k) { folder(work[k].first, work[k].second, h, ctx); });
    }

private:
    // Decodes a folder from its start and hands each wanted file its slice.
    void folder(unsigned fi, std::vector<std::size_t> want, EntryHandler &h, Context &ctx)
    {
        std::sort(want.begin(), want.end(), [&](auto a, auto b) {
            return files_[a].offset != files_[b].offset ? files_[a].offset < files_[b].offset : a < b;
        });
        const Folder &f = folders_[fi];
        const unsigned type = f.type & 15;
        if (type == 2) fail(ErrorCode::UnsupportedMethod, "Quantum compression is not supported", entries_[want[0]].path);
        if (type > 3) fail(ErrorCode::UnsupportedMethod, "unknown cabinet compression", entries_[want[0]].path);

        // Collect the data blocks.
        struct Block { std::uint64_t at; std::uint16_t packed, unpacked; std::uint32_t sum; };
        std::vector<Block> blocks;
        std::uint64_t p = start_ + f.data_off, total_out = 0;
        for (unsigned b = 0; b < f.blocks; ++b) {
            std::uint8_t d[8];
            src_->read_exact(p, d, 8);
            const Block blk{p + 8 + data_res_, le16(d + 4), le16(d + 6), le32(d)};
            if (blk.unpacked > 32768 + 6144 || (type != 0 && blk.unpacked > 32768)) damaged();
            blocks.push_back(blk);
            total_out += blk.unpacked;
            p = blk.at + blk.packed;
            if (p > src_->size()) fail(ErrorCode::Truncated, "cabinet ends early");
        }

        std::unique_ptr<LzxDecoder> lzx;
        std::vector<std::uint8_t> lzx_in;
        std::size_t lzx_pos = 0;
        if (type == 3) {
            lzx = std::make_unique<LzxDecoder>((f.type >> 8) & 31);
            check_alloc(p - start_, src_->size());
        }
        z_stream z{};
        if (type == 1 && inflateInit2(&z, -15) != Z_OK) fail(ErrorCode::Internal, "zlib init failed");
        struct ZEnd { z_stream *z; bool on; ~ZEnd() { if (on) inflateEnd(z); } } zend{&z, type == 1};
        std::vector<std::uint8_t> hist; // MSZIP: the last 32 KiB of output

        std::size_t wi = 0;
        std::uint64_t out_pos = 0;
        Sink *sink = nullptr;
        auto deliver = [&](const std::uint8_t *data, std::size_t n) {
            // Walk the slice [out_pos, out_pos + n) over the wanted files.
            while (n && wi < want.size()) {
                const CabFile &cf = files_[want[wi]];
                const Entry &e = entries_[want[wi]];
                const std::uint64_t fend = std::uint64_t(cf.offset) + cf.size;
                if (out_pos < cf.offset) {
                    const std::size_t skip = std::size_t(std::min<std::uint64_t>(n, cf.offset - out_pos));
                    data += skip; n -= skip; out_pos += skip;
                    continue;
                }
                if (!sink && out_pos == cf.offset) {
                    sink = h.begin(e);
                    if (!sink) { h.end(e, nullptr); ++wi; continue; }
                    ctx.file_started(e.path);
                }
                if (out_pos > cf.offset && !sink) fail(ErrorCode::Corrupt, "cabinet files overlap", e.path);
                const std::size_t k = std::size_t(std::min<std::uint64_t>(n, fend - out_pos));
                sink->write(data, k);
                ctx.add_bytes(k);
                data += k; n -= k; out_pos += k;
                if (out_pos == fend) { h.end(e, sink); ctx.file_done(); sink = nullptr; ++wi; }
            }
            out_pos += n;
        };
        auto flush_empty = [&] { // zero-length files at the current spot
            while (wi < want.size() && files_[want[wi]].size == 0 && files_[want[wi]].offset <= out_pos) {
                Sink *s = h.begin(entries_[want[wi]]);
                h.end(entries_[want[wi]], s);
                ++wi;
            }
        };

        try {
            std::vector<std::uint8_t> in, out(32768 + 6144);
            for (std::size_t b = 0; b < blocks.size() && wi < want.size(); ++b) {
                ctx.checkpoint();
                flush_empty();
                const Block &blk = blocks[b];
                in.resize(blk.packed);
                src_->read_exact(blk.at, in.data(), in.size());
                if (blk.sum) {
                    std::uint8_t sz[4];
                    put_le16(sz, blk.packed);
                    put_le16(sz + 2, blk.unpacked);
                    if (cab_sum(sz, 4, cab_sum(in.data(), in.size(), 0)) != blk.sum)
                        fail(ErrorCode::Checksum, "cabinet data block does not match its checksum");
                }
                std::span<std::uint8_t> o(out.data(), blk.unpacked);
                if (type == 0) {
                    if (blk.packed != blk.unpacked) damaged();
                    std::copy(in.begin(), in.end(), out.begin());
                } else if (type == 1) {
                    if (blk.packed < 2 || in[0] != 'C' || in[1] != 'K') damaged("MSZIP block is damaged");
                    inflateReset(&z);
                    if (!hist.empty()) inflateSetDictionary(&z, hist.data(), uInt(hist.size()));
                    z.next_in = in.data() + 2;
                    z.avail_in = uInt(in.size() - 2);
                    z.next_out = o.data();
                    z.avail_out = uInt(o.size());
                    const int r = inflate(&z, Z_FINISH);
                    if (r != Z_STREAM_END || z.avail_out != 0) damaged("MSZIP block is damaged");
                    hist.insert(hist.end(), o.begin(), o.end());
                    if (hist.size() > 32768) hist.erase(hist.begin(), hist.end() - 32768);
                } else {
                    // One stream over all the data blocks. The bit reader looks up to
                    // 16 bits ahead, so the next block must already be there.
                    lzx_in.erase(lzx_in.begin(), lzx_in.begin() + std::ptrdiff_t(std::min(lzx_pos, lzx_in.size())));
                    lzx_pos = 0;
                    if (b == 0) lzx_in.insert(lzx_in.end(), in.begin(), in.end());
                    if (b + 1 < blocks.size()) {
                        const Block &nx = blocks[b + 1];
                        const std::size_t old = lzx_in.size();
                        lzx_in.resize(old + nx.packed);
                        src_->read_exact(nx.at, lzx_in.data() + old, nx.packed);
                    }
                    lzx->frame(lzx_in, lzx_pos, o);
                }
                deliver(o.data(), o.size());
            }
            flush_empty();
            if (wi < want.size()) fail(ErrorCode::Truncated, "cabinet ends before its files do", entries_[want[wi]].path);
        } catch (const Error &err) {
            if (wi < want.size()) h.failed(entries_[want[wi]], sink, err);
            else throw;
        }
        (void)total_out;
    }

    std::shared_ptr<Source> src_;
    std::uint64_t start_;
    unsigned data_res_ = 0;
    std::vector<Folder> folders_;
    std::vector<CabFile> files_;
    std::vector<Entry> entries_;
    ArchiveInfo info_;
};

} // namespace

std::unique_ptr<ReaderImpl> open_cab(const OpenRequest &req)
{
    return std::make_unique<CabReader>(req.source, req.detection.offset);
}

} // namespace raye::archive::detail
