// SPDX-License-Identifier: GPL-3.0-or-later
#include "lzma2mt.h"

#include "../../core/codec.h"

#include <raye/archive/error.h>

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <exception>
#include <mutex>
#include <thread>
#include <vector>

namespace raye::archive::detail::sevenz {

namespace {

// Pieces smaller than this are glued to the next one: a thread per 64 KB
// costs more than it saves.
constexpr std::uint64_t kMinPiece = 8 << 20;
constexpr std::uint64_t kMaxPiece = 64 << 20;
// Decoded pieces waiting to be read, in all.
constexpr std::uint64_t kBudget = 512ull << 20;

struct Piece {
    std::uint64_t at = 0, packed = 0, unpacked = 0;
};

// Splits the stream at chunks that reset the dictionary and bring their own
// properties (control byte 0xE0 and up). Empty when it can't be split.
std::vector<Piece> split(const Source &src, std::uint64_t offset, std::uint64_t packed, std::uint64_t unpacked)
{
    std::vector<Piece> pieces;
    Piece cur{offset, 0, 0};
    std::uint64_t pos = 0;
    std::uint8_t h[6];
    for (;;) {
        if (pos >= packed) return {};
        if (src.read_at(offset + pos, h, 1) != 1) return {};
        const std::uint8_t c = h[0];
        if (c == 0) {
            cur.packed = offset + pos + 1 - cur.at;
            pieces.push_back(cur);
            pos += 1;
            break;
        }
        std::uint64_t head = 0, data = 0, out = 0;
        if (c == 1 || c == 2) {
            if (src.read_at(offset + pos, h, 3) != 3) return {};
            head = 3;
            data = out = ((std::uint64_t(h[1]) << 8) | h[2]) + 1;
        } else if (c >= 0x80) {
            head = c >= 0xC0 ? 6 : 5;
            if (src.read_at(offset + pos, h, head) != head) return {};
            out = ((std::uint64_t(c & 0x1F) << 16) | (std::uint64_t(h[1]) << 8) | h[2]) + 1;
            data = ((std::uint64_t(h[3]) << 8) | h[4]) + 1;
        } else {
            return {};
        }
        if (c >= 0xE0 && cur.unpacked >= kMinPiece) {
            cur.packed = offset + pos - cur.at;
            pieces.push_back(cur);
            cur = Piece{offset + pos, 0, 0};
        }
        pos += head + data;
        cur.unpacked += out;
        if (cur.unpacked > kMaxPiece * 4) return {};
    }
    if (pos > packed) return {};
    std::uint64_t total = 0;
    for (auto &p : pieces) total += p.unpacked;
    if (total != unpacked || pieces.size() < 2) return {};
    return pieces;
}

class ParallelLzma2Pull final : public Pull {
public:
    ParallelLzma2Pull(const Source &src, std::vector<Piece> pieces, std::uint8_t props, unsigned threads)
        : src_(src), pieces_(std::move(pieces)), props_(props), out_(pieces_.size()), errors_(pieces_.size()),
          ready_(pieces_.size(), false)
    {
        std::uint64_t biggest = 0;
        for (auto &p : pieces_) biggest = std::max(biggest, p.unpacked);
        ahead_ = std::size_t(std::max<std::uint64_t>(1, kBudget / std::max<std::uint64_t>(biggest, 1)));
        threads = std::max(1u, std::min<unsigned>(threads, unsigned(std::min(pieces_.size(), ahead_))));
        for (unsigned i = 0; i < threads; ++i) workers_.emplace_back([this] { work(); });
    }

    ~ParallelLzma2Pull() override
    {
        {
            std::lock_guard l(m_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto &t : workers_) t.join();
    }

    std::size_t read(std::uint8_t *buf, std::size_t n) override
    {
        while (cur_ < pieces_.size()) {
            {
                std::unique_lock l(m_);
                cv_.wait(l, [&] { return bool(ready_[cur_]); });
                if (errors_[cur_]) std::rethrow_exception(errors_[cur_]);
            }
            // once ready, only this thread touches the piece
            const auto &o = out_[cur_];
            if (pos_ < o.size()) {
                const std::size_t k = std::size_t(std::min<std::uint64_t>(n, o.size() - pos_));
                std::memcpy(buf, o.data() + pos_, k);
                pos_ += k;
                return k;
            }
            {
                std::lock_guard l(m_);
                std::vector<std::uint8_t>().swap(out_[cur_]);
                ++cur_;
                pos_ = 0;
            }
            cv_.notify_all();
        }
        return 0;
    }

private:
    void work()
    {
        for (;;) {
            std::size_t i;
            {
                std::unique_lock l(m_);
                cv_.wait(l, [&] { return stop_ || (next_ < pieces_.size() && next_ < cur_ + ahead_); });
                if (stop_ || next_ >= pieces_.size()) return;
                i = next_++;
            }
            std::vector<std::uint8_t> out;
            std::exception_ptr err;
            try {
                out = decode(pieces_[i]);
            } catch (...) {
                err = std::current_exception();
            }
            {
                std::lock_guard l(m_);
                out_[i] = std::move(out);
                errors_[i] = err;
                ready_[i] = true;
            }
            cv_.notify_all();
        }
    }

    std::vector<std::uint8_t> decode(const Piece &p) const
    {
        std::vector<std::uint8_t> in(std::size_t(p.packed) + 1, 0);
        src_.read_exact(p.at, in.data(), std::size_t(p.packed));
        in.back() = 0; // end marker, so a piece cut before the real one still finishes
        CodecParams cp;
        cp.props = {props_};
        auto dec = make_decoder(Codec::Lzma2Raw, cp);
        std::vector<std::uint8_t> out(std::size_t(p.unpacked));
        std::size_t at = 0, made = 0;
        for (;;) {
            auto s = dec->step({in.data() + at, in.size() - at}, {out.data() + made, out.size() - made}, true);
            at += s.consumed;
            made += s.produced;
            if (s.done) break;
            if (s.consumed == 0 && s.produced == 0) fail(ErrorCode::Truncated, "LZMA2 data ends early");
        }
        if (made != out.size()) fail(ErrorCode::Corrupt, "LZMA2 piece has the wrong size");
        return out;
    }

    const Source &src_;
    std::vector<Piece> pieces_;
    std::uint8_t props_;
    std::vector<std::vector<std::uint8_t>> out_;
    std::vector<std::exception_ptr> errors_;
    std::vector<bool> ready_;
    std::vector<std::thread> workers_;
    std::mutex m_;
    std::condition_variable cv_;
    std::size_t next_ = 0, cur_ = 0, ahead_ = 1;
    std::uint64_t pos_ = 0;
    bool stop_ = false;
};

} // namespace

std::unique_ptr<Pull> open_lzma2_parallel(const Source &src, std::uint64_t offset, std::uint64_t packed,
                                          std::uint8_t props, std::uint64_t unpacked, unsigned threads)
{
    if (threads < 2 || unpacked < 2 * kMinPiece || offset + packed > src.size() || offset + packed < offset)
        return nullptr;
    auto pieces = split(src, offset, packed, unpacked);
    if (pieces.empty()) return nullptr;
    return std::make_unique<ParallelLzma2Pull>(src, std::move(pieces), props, threads);
}

} // namespace raye::archive::detail::sevenz
