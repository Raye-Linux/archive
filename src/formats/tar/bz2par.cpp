// SPDX-License-Identifier: GPL-3.0-or-later
// Parallel bzip2 decoding. Blocks of a bzip2 stream are independent once
// found: each one starts with the 48-bit magic 0x314159265359 at any bit
// offset. We find them all, wrap each block in a tiny stream of its own
// ("BZh9", the block bits, an end marker carrying the block CRC) and let
// libbz2 decode those on the pool. Block CRCs are checked by libbz2, the
// stream CRC by us.
#include "stream.h"

#include "../../core/bytes.h"
#include "../../core/context.h"
#include "../../core/threadpool.h"

#include <bzlib.h>

#include <algorithm>
#include <atomic>
#include <deque>
#include <future>
#include <mutex>

namespace raye::archive::detail {

namespace {

constexpr std::uint64_t kBlockMagic = 0x314159265359ull;
constexpr std::uint64_t kEndMagic = 0x177245385090ull;
constexpr std::uint64_t kMask48 = (1ull << 48) - 1;

struct Mark {
    std::uint64_t bit;
    bool end; // end-of-stream marker
};

// Every magic whose first bit lies in [from, to) bytes of src.
std::vector<Mark> scan(const Source &src, std::uint64_t from, std::uint64_t to)
{
    std::vector<Mark> out;
    std::vector<std::uint8_t> buf(1 << 20);
    std::uint64_t w = 0;
    std::uint64_t off = from >= 6 ? from - 6 : 0; // prime the window with the bytes before
    while (off < to + 6) {
        const std::size_t n = src.read_at(off, buf.data(), std::size_t(std::min<std::uint64_t>(buf.size(), to + 6 - off)));
        if (!n) break;
        for (std::size_t i = 0; i < n; ++i) {
            w = (w << 8) | buf[i];
            const std::uint64_t byte = off + i;
            if (byte < 6) continue;
            // Window holds bytes byte-7..byte; a magic ending inside this byte
            // starts at one of 8 bit positions.
            for (int k = 0; k < 8; ++k) {
                const std::uint64_t v = (w >> k) & kMask48;
                if (v != kBlockMagic && v != kEndMagic) continue;
                const std::uint64_t start = (byte + 1) * 8 - std::uint64_t(k) - 48;
                if (start / 8 >= from && start / 8 < to) out.push_back({start, v == kEndMagic});
            }
        }
        off += n;
    }
    return out;
}

std::uint32_t bits_at(const Source &src, std::uint64_t bit, unsigned count)
{
    std::uint8_t b[6] = {};
    src.read_at(bit / 8, b, 6);
    std::uint64_t v = 0;
    for (auto x : b) v = (v << 8) | x;
    v <<= 16; // 48 bits now sit at the top of 64
    v <<= (bit % 8);
    return std::uint32_t(v >> (64 - count));
}

struct Block {
    std::uint64_t begin, end; // bits, end exclusive (start of the next magic)
    std::uint32_t crc;
    std::size_t stream;       // index of the stream it belongs to
};

struct Layout {
    std::vector<Block> blocks;
    std::vector<std::uint32_t> stream_crc;
    std::vector<std::uint64_t> stream_start; // byte offset of each "BZh"
};

// Checks the magics line up as streams of blocks. False = do it serially.
bool layout(const Source &src, std::uint64_t start, const std::vector<Mark> &marks, Layout &l)
{
    std::uint64_t pos = start;
    std::size_t m = 0;
    const std::uint64_t size = src.size();
    while (pos + 14 <= size) {
        std::uint8_t h[4];
        src.read_exact(pos, h, 4);
        if (h[0] != 'B' || h[1] != 'Z' || h[2] != 'h' || h[3] < '1' || h[3] > '9') break;
        std::uint64_t bit = pos * 8 + 32;
        while (m < marks.size() && marks[m].bit < bit) ++m;
        if (m == marks.size() || marks[m].bit != bit) return false;
        const std::size_t stream = l.stream_crc.size();
        l.stream_start.push_back(pos);
        for (;;) {
            if (m == marks.size()) return false;
            if (marks[m].end) {
                l.stream_crc.push_back(bits_at(src, marks[m].bit + 48, 32));
                const std::uint64_t after = marks[m].bit + 80;
                pos = (after + 7) / 8;
                ++m;
                break;
            }
            if (m + 1 == marks.size()) return false;
            l.blocks.push_back({marks[m].bit, marks[m + 1].bit, bits_at(src, marks[m].bit + 48, 32), stream});
            ++m;
        }
    }
    return !l.stream_crc.empty();
}

// Builds "BZh9" + bits [begin, end) + end marker + crc, and decodes it.
std::vector<std::uint8_t> decode_block(const Source &src, std::uint64_t begin, std::uint64_t end, std::uint32_t crc)
{
    const std::uint64_t first = begin / 8, last = (end + 7) / 8;
    std::vector<std::uint8_t> raw(std::size_t(last - first) + 1);
    raw.resize(src.read_at(first, raw.data(), raw.size()));
    std::vector<std::uint8_t> s;
    s.reserve(raw.size() + 16);
    s.insert(s.end(), {'B', 'Z', 'h', '9'});
    std::uint64_t acc = 0;
    unsigned nacc = 0;
    auto put = [&](std::uint64_t v, unsigned n) {
        for (int i = int(n) - 1; i >= 0; --i) {
            acc = (acc << 1) | ((v >> i) & 1);
            if (++nacc == 8) { s.push_back(std::uint8_t(acc)); acc = 0; nacc = 0; }
        }
    };
    const unsigned shift = unsigned(begin % 8);
    std::uint64_t nbits = end - begin;
    std::size_t i = 0;
    if (shift == 0) {
        while (nbits >= 8) { s.push_back(raw[i++]); nbits -= 8; }
    } else {
        while (nbits >= 8 && i + 1 < raw.size()) {
            s.push_back(std::uint8_t((raw[i] << shift) | (raw[i + 1] >> (8 - shift))));
            ++i;
            nbits -= 8;
        }
    }
    if (nbits) {
        std::uint32_t tail = std::uint32_t(i < raw.size() ? raw[i] : 0) << 8 | (i + 1 < raw.size() ? raw[i + 1] : 0);
        tail = (tail << shift) & 0xffff;
        put(tail >> (16 - nbits), unsigned(nbits));
    }
    put(kEndMagic, 48);
    put(crc, 32);
    if (nacc) put(0, 8 - nacc);

    bz_stream b{};
    if (BZ2_bzDecompressInit(&b, 0, 0) != BZ_OK) fail(ErrorCode::Internal, "bzip2 init failed");
    std::vector<std::uint8_t> out(1 << 20);
    std::size_t pos = 0;
    b.next_in = reinterpret_cast<char *>(s.data());
    b.avail_in = unsigned(s.size());
    int r;
    for (;;) {
        if (out.size() - pos < (1 << 18)) {
            if (out.size() > (64u << 20)) { BZ2_bzDecompressEnd(&b); fail(ErrorCode::Corrupt, "bzip2 data is damaged"); }
            out.resize(out.size() * 2);
        }
        b.next_out = reinterpret_cast<char *>(out.data() + pos);
        b.avail_out = unsigned(out.size() - pos);
        const unsigned before = b.avail_out;
        r = BZ2_bzDecompress(&b);
        pos += before - b.avail_out;
        if (r != BZ_OK) break;
        if (b.avail_in == 0 && before == b.avail_out) { r = BZ_UNEXPECTED_EOF; break; }
    }
    BZ2_bzDecompressEnd(&b);
    if (r != BZ_STREAM_END) fail(ErrorCode::Corrupt, "bzip2 data is damaged");
    out.resize(pos);
    return out;
}

class Bz2ParallelStream final : public InStream {
public:
    Bz2ParallelStream(const Source &src, Layout l, int threads)
        : src_(src), l_(std::move(l)), pool_(unsigned(threads)), inflight_(std::size_t(threads) * 2),
          combined_(l_.stream_crc.size(), 0), out_(l_.stream_crc.size(), 0)
    {
        fill();
    }
    ~Bz2ParallelStream() override { drop_jobs(); }
    std::size_t read(void *buf, std::size_t n) override
    {
        if (serial_) {
            const std::size_t k = serial_->read(buf, n);
            pos_ += k;
            return k;
        }
        while (cur_pos_ == cur_.size()) {
            if (jobs_.empty()) {
                if (!checked_) check_streams();
                return 0;
            }
            auto [stream, fut] = std::move(jobs_.front());
            jobs_.pop_front();
            try {
                cur_ = fut.get();
            } catch (const Error &) {
                // A magic can turn up inside compressed data by chance and cut
                // a block in two. Redo this stream on one thread from its start.
                drop_jobs();
                serial_ = open_bzip2_serial(src_, l_.stream_start[stream]);
                if (serial_->skip(out_[stream]) != out_[stream]) fail(ErrorCode::Corrupt, "bzip2 data is damaged");
                return read(buf, n);
            }
            cur_stream_ = stream;
            cur_pos_ = 0;
            fill();
        }
        const std::size_t k = std::min(n, cur_.size() - cur_pos_);
        std::copy_n(cur_.data() + cur_pos_, k, static_cast<std::uint8_t *>(buf));
        cur_pos_ += k;
        out_[cur_stream_] += k;
        pos_ += k;
        return k;
    }

private:
    void fill()
    {
        while (jobs_.size() < inflight_ && next_ < l_.blocks.size()) {
            const Block b = l_.blocks[next_++];
            auto &c = combined_[b.stream];
            c = ((c << 1) | (c >> 31)) ^ b.crc;
            const Source &src = src_;
            jobs_.emplace_back(b.stream, pool_.submit([&src, b] { return decode_block(src, b.begin, b.end, b.crc); }));
        }
    }
    void drop_jobs()
    {
        for (auto &j : jobs_)
            if (j.second.valid()) j.second.wait();
        jobs_.clear();
    }
    void check_streams()
    {
        checked_ = true;
        for (std::size_t i = 0; i < combined_.size(); ++i)
            if (combined_[i] != l_.stream_crc[i]) fail(ErrorCode::Checksum, "bzip2 data does not match its CRC");
    }

    const Source &src_;
    Layout l_;
    ThreadPool pool_;
    std::size_t inflight_, next_ = 0;
    std::deque<std::pair<std::size_t, std::future<std::vector<std::uint8_t>>>> jobs_;
    std::vector<std::uint8_t> cur_;
    std::size_t cur_pos_ = 0, cur_stream_ = 0;
    std::vector<std::uint32_t> combined_;
    std::vector<std::uint64_t> out_;
    std::unique_ptr<InStream> serial_;
    bool checked_ = false;
};

} // namespace

std::unique_ptr<InStream> open_bzip2_parallel(const Source &src, std::uint64_t start, int threads)
{
    const std::uint64_t size = src.size();
    if (threads <= 1 || size - start < (4u << 20)) return open_bzip2_serial(src, start);
    ThreadPool scanners{unsigned(threads)};
    const std::uint64_t parts = std::uint64_t(threads);
    const std::uint64_t step = (size - start + parts - 1) / parts;
    std::vector<std::vector<Mark>> found(parts);
    scanners.parallel_for(parts, [&](std::size_t i) {
        const std::uint64_t a = start + i * step, b = std::min(size, a + step);
        if (a < b) found[i] = scan(src, a, b);
    });
    std::vector<Mark> marks;
    for (auto &f : found) marks.insert(marks.end(), f.begin(), f.end());
    Layout l;
    if (!layout(src, start, marks, l) || l.blocks.size() < 2) return open_bzip2_serial(src, start);
    return std::make_unique<Bz2ParallelStream>(src, std::move(l), threads);
}

} // namespace raye::archive::detail
