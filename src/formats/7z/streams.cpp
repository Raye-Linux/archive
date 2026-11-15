// SPDX-License-Identifier: GPL-3.0-or-later
#include "streams.h"

#include "filters.h"
#include "lzma2mt.h"
#include "ppmd.h"

#include "../../core/codec.h"
#include "../zip/zip.h"
#include "../../core/crypto.h"

#include <raye/archive/error.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>
#include <tuple>


namespace raye::archive::detail::sevenz {

namespace {

constexpr std::size_t kChunk = 1 << 18;

class PackPull final : public Pull {
public:
    PackPull(const Source &src, std::uint64_t start, std::uint64_t size)
        : r_(src, start, start + size, kChunk), left_(size)
    {
        if (start + size > src.size() || start + size < start) fail(ErrorCode::Truncated, "7z packed data runs past the end of the file");
    }
    std::size_t read(std::uint8_t *buf, std::size_t n) override
    {
        n = std::size_t(std::min<std::uint64_t>(n, left_));
        const std::size_t got = r_.read(buf, n);
        if (got < n) fail(ErrorCode::Truncated, "unexpected end of archive");
        left_ -= got;
        return got;
    }

private:
    SourceReader r_;
    std::uint64_t left_;
};

// Output of a stream decoder from the system libraries, cut at its size.
class CoderPull final : public Pull {
public:
    CoderPull(std::unique_ptr<detail::Coder> c, std::unique_ptr<Pull> in, std::uint64_t size)
        : c_(std::move(c)), in_(std::move(in)), left_(size), buf_(kChunk) {}
    std::size_t read(std::uint8_t *out, std::size_t n) override
    {
        n = std::size_t(std::min<std::uint64_t>(n, left_));
        while (n) {
            if (at_ == have_ && !eof_) {
                have_ = in_->read(buf_.data(), buf_.size());
                at_ = 0;
                if (have_ == 0) eof_ = true;
            }
            if (ended_) fail(ErrorCode::Truncated, "compressed data ends before the size in the header");
            auto s = c_->step({buf_.data() + at_, have_ - at_}, {out, n}, eof_ && at_ == have_);
            at_ += s.consumed;
            if (s.done) ended_ = true;
            if (s.produced) {
                left_ -= s.produced;
                return s.produced;
            }
            if (s.consumed == 0 && eof_ && at_ == have_) fail(ErrorCode::Truncated, "compressed data ends early");
        }
        return 0;
    }

private:
    std::unique_ptr<detail::Coder> c_;
    std::unique_ptr<Pull> in_;
    std::uint64_t left_;
    std::vector<std::uint8_t> buf_;
    std::size_t at_ = 0, have_ = 0;
    bool eof_ = false, ended_ = false;
};

class CopyPull final : public Pull {
public:
    CopyPull(std::unique_ptr<Pull> in, std::uint64_t size) : in_(std::move(in)), left_(size) {}
    std::size_t read(std::uint8_t *out, std::size_t n) override
    {
        n = std::size_t(std::min<std::uint64_t>(n, left_));
        if (!n) return 0;
        const std::size_t got = in_->read(out, n);
        if (!got) fail(ErrorCode::Truncated, "stored data ends early");
        left_ -= got;
        return got;
    }

private:
    std::unique_ptr<Pull> in_;
    std::uint64_t left_;
};

class FilterPull final : public Pull {
public:
    FilterPull(std::unique_ptr<filters::Filter> f, std::unique_ptr<Pull> in, std::uint64_t size)
        : f_(std::move(f)), in_(std::move(in)), left_(size), buf_(kChunk) {}
    std::size_t read(std::uint8_t *out, std::size_t n) override
    {
        n = std::size_t(std::min<std::uint64_t>(n, left_));
        while (n) {
            if (pos_ < conv_) {
                const std::size_t k = std::min(n, conv_ - pos_);
                std::memcpy(out, buf_.data() + pos_, k);
                pos_ += k;
                left_ -= k;
                return k;
            }
            std::memmove(buf_.data(), buf_.data() + conv_, end_ - conv_);
            end_ -= conv_;
            pos_ = conv_ = 0;
            if (eof_) {
                if (end_ == 0) fail(ErrorCode::Truncated, "filtered data ends early");
                conv_ = end_;
                continue;
            }
            const std::size_t got = in_->read(buf_.data() + end_, buf_.size() - end_);
            if (got == 0) eof_ = true;
            end_ += got;
            conv_ = f_->run(buf_.data(), end_);
            if (eof_) conv_ = end_;
        }
        return 0;
    }

private:
    std::unique_ptr<filters::Filter> f_;
    std::unique_ptr<Pull> in_;
    std::uint64_t left_;
    std::vector<std::uint8_t> buf_;
    std::size_t pos_ = 0, conv_ = 0, end_ = 0;
    bool eof_ = false;
};

class Bcj2Pull final : public Pull {
public:
    Bcj2Pull(std::vector<std::unique_ptr<Pull>> in, std::uint64_t size)
        : in_(std::move(in)), dec_(&Bcj2Pull::pull, this, size) {}
    std::size_t read(std::uint8_t *out, std::size_t n) override { return dec_.read(out, n); }

private:
    static std::size_t pull(void *self, int s, std::uint8_t *buf, std::size_t n)
    {
        return static_cast<Bcj2Pull *>(self)->in_[std::size_t(s)]->read(buf, n);
    }
    std::vector<std::unique_ptr<Pull>> in_;
    filters::Bcj2Decoder dec_;
};

class AesPull final : public Pull {
public:
    AesPull(std::span<const std::uint8_t> key, std::span<const std::uint8_t> iv, std::unique_ptr<Pull> in,
            std::uint64_t size)
        : aes_(key, Aes::Mode::Cbc, false, iv), in_(std::move(in)), left_(size) {}
    std::size_t read(std::uint8_t *out, std::size_t n) override
    {
        n = std::size_t(std::min<std::uint64_t>(n, left_));
        if (!n) return 0;
        if (at_ == have_) {
            std::size_t got = 0;
            while (got < sizeof buf_) {
                const std::size_t r = in_->read(buf_ + got, sizeof buf_ - got);
                if (!r) break;
                got += r;
            }
            got &= ~std::size_t(15);
            if (!got) fail(ErrorCode::Truncated, "encrypted data ends early");
            aes_.process(buf_, buf_, got);
            have_ = got;
            at_ = 0;
        }
        const std::size_t k = std::min(n, have_ - at_);
        std::memcpy(out, buf_ + at_, k);
        at_ += k;
        left_ -= k;
        return k;
    }

private:
    Aes aes_;
    std::unique_ptr<Pull> in_;
    std::uint64_t left_;
    std::uint8_t buf_[1 << 16];
    std::size_t at_ = 0, have_ = 0;
};

class PpmdPull final : public Pull {
public:
    PpmdPull(unsigned order, std::uint32_t mem, std::unique_ptr<Pull> in, std::uint64_t size)
        : in_(std::move(in)), dec_(order, mem, &PpmdPull::byte, this), left_(size) {}
    std::size_t read(std::uint8_t *out, std::size_t n) override
    {
        n = std::size_t(std::min<std::uint64_t>(n, left_));
        for (std::size_t i = 0; i < n; ++i) {
            const int c = dec_.decode();
            if (c < 0) fail(ErrorCode::Corrupt, "PPMd data is damaged");
            out[i] = std::uint8_t(c);
        }
        left_ -= n;
        return n;
    }

private:
    static int byte(void *self)
    {
        auto *p = static_cast<PpmdPull *>(self);
        if (p->at_ == p->have_) {
            p->have_ = p->in_->read(p->buf_, sizeof p->buf_);
            p->at_ = 0;
            // The range decoder may look a few bytes past the end; much more
            // means the sizes in the header are lies.
            if (!p->have_) {
                if (++p->past_end_ > 64) throw Error(ErrorCode::Truncated, "PPMd data ends early");
                return 0;
            }
        }
        return p->buf_[p->at_++];
    }
    std::unique_ptr<Pull> in_;
    ppmd7::Decoder dec_;
    std::uint64_t left_;
    std::uint8_t buf_[1 << 16];
    std::size_t at_ = 0, have_ = 0;
    int past_end_ = 0;
};


std::optional<filters::Kind> branch_kind(std::uint64_t id)
{
    using filters::Kind;
    switch (id) {
    case method::X86: case method::X86Short: return Kind::X86;
    case method::Arm: case method::ArmShort: return Kind::Arm;
    case method::Armt: case method::ArmtShort: return Kind::Armt;
    case method::Ppc: case method::PpcShort: return Kind::Ppc;
    case method::Sparc: case method::SparcShort: return Kind::Sparc;
    case method::Ia64: case method::Ia64Short: return Kind::Ia64;
    case method::Arm64: return Kind::Arm64;
    case method::Delta: return Kind::Delta;
    }
    return std::nullopt;
}

struct AesProps {
    unsigned cycles = 0;
    std::vector<std::uint8_t> salt;
    std::uint8_t iv[16] = {};
};

AesProps parse_aes(const std::vector<std::uint8_t> &p)
{
    AesProps a;
    if (p.empty()) fail(ErrorCode::Corrupt, "7z AES properties are missing");
    const std::uint8_t b0 = p[0];
    a.cycles = b0 & 0x3F;
    if ((b0 & 0xC0) == 0) return a;
    if (p.size() < 2) fail(ErrorCode::Corrupt, "7z AES properties are too short");
    const std::uint8_t b1 = p[1];
    const std::size_t salt = ((b0 >> 7) & 1) + (b1 >> 4), iv = ((b0 >> 6) & 1) + (b1 & 0x0F);
    if (p.size() < 2 + salt + iv) fail(ErrorCode::Corrupt, "7z AES properties are too short");
    a.salt.assign(p.begin() + 2, p.begin() + 2 + std::ptrdiff_t(salt));
    std::memcpy(a.iv, p.data() + 2 + salt, iv);
    return a;
}

} // namespace

struct KeyCache {
    std::mutex m;
    std::map<std::tuple<std::string, std::vector<std::uint8_t>, unsigned>, std::array<std::uint8_t, 32>> keys;
    ~KeyCache()
    {
        for (auto &[k, v] : keys) secure_wipe(v.data(), v.size());
    }
};

std::shared_ptr<KeyCache> make_key_cache() { return std::make_shared<KeyCache>(); }

std::array<std::uint8_t, 32> derive_key(const std::string &password, std::span<const std::uint8_t> salt,
                                        unsigned cycles)
{
    auto pw = utf8_to_utf16le(password);
    std::array<std::uint8_t, 32> key{};
    if (cycles == 0x3F) {
        std::size_t k = 0;
        for (auto b : salt) if (k < 32) key[k++] = b;
        for (auto b : pw) if (k < 32) key[k++] = b;
    } else {
        if (cycles > 24) fail(ErrorCode::UnsupportedMethod, "7z key derivation asks for too many rounds");
        std::vector<std::uint8_t> buf(salt.begin(), salt.end());
        buf.insert(buf.end(), pw.begin(), pw.end());
        const std::size_t ctr = buf.size();
        buf.resize(ctr + 8, 0);
        Sha256 h;
        const std::uint64_t rounds = std::uint64_t(1) << cycles;
        for (std::uint64_t i = 0; i < rounds; ++i) {
            put_le64(buf.data() + ctr, i);
            h.update(buf.data(), buf.size());
        }
        key = h.final();
        secure_wipe(buf.data(), buf.size());
    }
    secure_wipe(pw.data(), pw.size());
    return key;
}

std::string unsupported_coder(const Folder &f)
{
    for (auto &c : f.coders) {
        switch (c.id) {
        case method::Copy: case method::Lzma: case method::Lzma2: case method::Ppmd: case method::Deflate:
        case method::Bzip2: case method::Aes: case method::Zstd: case method::Bcj2: case method::Deflate64:
            continue;
        default:
            if (branch_kind(c.id)) continue;
            return method_label(c.id);
        }
    }
    return {};
}

namespace {

class Builder {
public:
    explicit Builder(const FolderInput &in) : in_(in), f_(in.si.folders[in.folder]) {}

    std::unique_ptr<Pull> out_stream(std::uint64_t out, int depth)
    {
        if (depth > 32) fail(ErrorCode::Corrupt, "7z folder has a loop");
        std::uint32_t local = 0;
        const std::size_t ci = f_.coder_of_out(out, &local);
        const Coder &c = f_.coders[ci];
        if (c.num_out != 1) fail(ErrorCode::UnsupportedMethod, "7z coder with several outputs");
        const std::uint64_t size = f_.unpack_sizes[std::size_t(out)];
        std::vector<std::unique_ptr<Pull>> ins;
        for (std::uint32_t j = 0; j < c.num_in; ++j) ins.push_back(in_stream(f_.first_in(ci) + j, depth));
        auto one = [&]() -> std::unique_ptr<Pull> {
            if (ins.size() != 1) fail(ErrorCode::Corrupt, "7z coder has the wrong number of inputs");
            return std::move(ins[0]);
        };
        if (auto k = branch_kind(c.id)) {
            std::uint32_t start = 0;
            unsigned dist = 1;
            if (*k == filters::Kind::Delta) dist = c.props.empty() ? 1 : c.props[0] + 1u;
            else if (c.props.size() == 4) start = le32(c.props.data());
            return std::make_unique<FilterPull>(filters::make_filter(*k, false, start, dist), one(), size);
        }
        switch (c.id) {
        case method::Copy: return std::make_unique<CopyPull>(one(), size);
        case method::Lzma: case method::Lzma2: {
            CodecParams p;
            p.props = c.props;
            if (c.id == method::Lzma && p.props.size() != 5) fail(ErrorCode::Corrupt, "bad LZMA properties");
            if (c.id == method::Lzma2 && p.props.size() != 1) fail(ErrorCode::Corrupt, "bad LZMA2 properties");
            if (c.id == method::Lzma2 && in_.threads > 1 && c.num_in == 1) {
                std::uint64_t off = 0, len = 0;
                if (packed_input(f_.first_in(ci), &off, &len))
                    if (auto mt = open_lzma2_parallel(in_.source, off, len, p.props[0], size, in_.threads)) return mt;
            }
            return std::make_unique<CoderPull>(make_decoder(c.id == method::Lzma ? Codec::Lzma1Raw : Codec::Lzma2Raw, p),
                                               one(), size);
        }
        case method::Deflate: return std::make_unique<CoderPull>(make_decoder(Codec::Deflate), one(), size);
        case method::Deflate64: return std::make_unique<CoderPull>(zip::make_deflate64_decoder(), one(), size);
        case method::Bzip2: return std::make_unique<CoderPull>(make_decoder(Codec::Bzip2), one(), size);
        case method::Zstd: return std::make_unique<CoderPull>(make_decoder(Codec::Zstd), one(), size);
        case method::Ppmd: {
            if (c.props.size() != 5) fail(ErrorCode::Corrupt, "bad PPMd properties");
            const unsigned order = c.props[0];
            const std::uint32_t mem = le32(c.props.data() + 1);
            if (order < 2 || order > 64 || mem < (1u << 11) || mem > 0xFFFFFFFFu - 12 * 3)
                fail(ErrorCode::Corrupt, "bad PPMd properties");
            return std::make_unique<PpmdPull>(order, mem, one(), size);
        }
        case method::Bcj2:
            if (ins.size() != 4) fail(ErrorCode::Corrupt, "BCJ2 needs four inputs");
            return std::make_unique<Bcj2Pull>(std::move(ins), size);
        case method::Aes: {
            if (!in_.password) fail(ErrorCode::PasswordRequired, "this archive needs a password");
            auto a = parse_aes(c.props);
            std::array<std::uint8_t, 32> key;
            auto id = std::make_tuple(*in_.password, a.salt, a.cycles);
            {
                std::unique_lock l(in_.keys->m);
                auto it = in_.keys->keys.find(id);
                if (it != in_.keys->keys.end()) {
                    key = it->second;
                } else {
                    l.unlock();
                    key = derive_key(*in_.password, a.salt, a.cycles);
                    l.lock();
                    in_.keys->keys[id] = key;
                }
            }
            auto p = std::make_unique<AesPull>(key, a.iv, one(), size);
            secure_wipe(key.data(), key.size());
            return p;
        }
        }
        fail(ErrorCode::UnsupportedMethod, "7z method " + method_label(c.id) + " is not supported");
    }

    // Where a packed stream lies in the file, when the coder reads it directly.
    bool packed_input(std::uint64_t in, std::uint64_t *off, std::uint64_t *len) const
    {
        for (std::size_t k = 0; k < f_.packed.size(); ++k)
            if (f_.packed[k] == in) {
                *off = in_.data_start;
                for (std::size_t j = 0; j < k; ++j) *off += in_.si.pack_sizes[f_.first_pack + j];
                *len = in_.si.pack_sizes[f_.first_pack + k];
                return true;
            }
        return false;
    }

    std::unique_ptr<Pull> in_stream(std::uint64_t in, int depth)
    {
        for (std::size_t k = 0; k < f_.packed.size(); ++k)
            if (f_.packed[k] == in) {
                std::uint64_t off = in_.data_start;
                for (std::size_t j = 0; j < k; ++j) off += in_.si.pack_sizes[f_.first_pack + j];
                return std::make_unique<PackPull>(in_.source, off, in_.si.pack_sizes[f_.first_pack + k]);
            }
        for (auto &b : f_.binds)
            if (b.in == in) return out_stream(b.out, depth + 1);
        fail(ErrorCode::Corrupt, "7z folder stream is not connected");
    }

private:
    const FolderInput &in_;
    const Folder &f_;
};

} // namespace

std::unique_ptr<Pull> open_folder(const FolderInput &in)
{
    const Folder &f = in.si.folders.at(in.folder);
    if (f.first_pack + f.packed.size() > in.si.pack_sizes.size()) fail(ErrorCode::Corrupt, "7z folder has no data");
    Builder b(in);
    return b.out_stream(f.main_out(), 0);
}

} // namespace raye::archive::detail::sevenz
