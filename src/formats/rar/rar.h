// SPDX-License-Identifier: GPL-3.0-or-later
// Shared pieces of the RAR reader: archive items, packed data streams,
// the bit reader, Huffman tables and the LZ window every decoder uses.
#pragma once

#include "../../core/checksum.h"
#include "../../core/context.h"
#include "../../core/crypto.h"

#include <raye/archive/archive.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace raye::archive::detail::rar {

struct Part {
    std::uint32_t volume = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
};

enum class Crypt : std::uint8_t { None, Rar3, Rar5, Rar20, Rar15 };

struct CryptInfo {
    Crypt kind = Crypt::None;
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 16> iv{};
    std::uint8_t kdf_log2 = 0;
    bool has_check = false;
    std::array<std::uint8_t, 8> check{};
    bool hmac_sums = false; // RAR5: checksums are mixed with the key
    bool has_salt = false;  // RAR3: salt present
};

struct Item {
    Entry entry;
    std::vector<Part> parts;
    int version = 0;          // 15, 20, 29 (also 26/36), 50, 70
    bool stored = true;
    std::uint64_t dict = 0;   // dictionary size in bytes
    bool solid = false;       // continues the previous compressed file
    bool size_known = true;
    bool has_crc = false;
    std::uint32_t crc = 0;
    bool has_blake = false;
    std::array<std::uint8_t, 32> blake{};
    CryptInfo crypt;
    bool split_after = false;  // more parts in the next volume
    bool truncated = false;    // data cut by the end of the file
};

struct Parsed {
    std::vector<Item> items;
    std::string comment;
    bool solid = false;
    bool encrypted_headers = false;
    bool locked = false;
    bool recovery = false;
    int version = 5;          // 4 for RAR 1.5-4.x layout
    std::string damage;       // why parsing stopped early, if it did
    std::optional<Item> comment_item; // compressed or stored comment
    std::vector<std::uint8_t> comment_bytes; // packed comment kept in a header (RAR 1.5-2.x)
};

// Every volume of the archive, opened once. Volume 0 starts at base0.
struct Volumes {
    std::vector<std::shared_ptr<Source>> src;
    std::vector<std::string> names;
    std::uint64_t base0 = 0;
    const Source &get(std::uint32_t v, const std::string &entry) const;
};

// RAR4 headers and RAR5 headers.
Parsed parse_rar4(const Volumes &vols, Context &ctx);
Parsed parse_rar5(const Volumes &vols, Context &ctx);

// ---------------------------------------------------------------- crypto

// AES key material for one item, derived from the password.
struct Keys {
    std::vector<std::uint8_t> key;      // 16 (RAR3) or 32 (RAR5) bytes
    std::array<std::uint8_t, 16> iv{};
    std::array<std::uint8_t, 32> hash_key{}; // RAR5 checksum key
    std::array<std::uint8_t, 8> check{};     // RAR5 password check it gives
    ~Keys();
};

// RAR 3.x: SHA-1 based, 2^18 rounds, with the source-modifying quirk.
void rar3_keys(const std::string &password, const std::uint8_t salt[8], Keys &out);
// RAR 5.0: PBKDF2-HMAC-SHA256. Returns false when the check value says
// the password is wrong.
bool rar5_keys(const std::string &password, const CryptInfo &ci, Keys &out);
// RAR5 password check of headers or files without having to decode.
std::array<std::uint8_t, 8> rar5_check_value(const std::array<std::uint8_t, 32> &v);
// RAR5 with hmac_sums: CRC32 and BLAKE2sp are passed through HMAC.
std::uint32_t rar5_mix_crc(std::uint32_t crc, const std::array<std::uint8_t, 32> &hk);
std::array<std::uint8_t, 32> rar5_mix_hash(const std::array<std::uint8_t, 32> &h, const std::array<std::uint8_t, 32> &hk);

// SHA-1 with the in-place quirk of RAR 2.9 (exposed for tests).
std::array<std::uint8_t, 20> sha1_rar29(std::vector<std::uint8_t> data);

// ---------------------------------------------------------------- input

// Byte input of a decoder.
class ByteIn {
public:
    virtual ~ByteIn() = default;
    // Up to n bytes, 0 only at the end.
    virtual std::size_t read(std::uint8_t *out, std::size_t n) = 0;
};

// Packed data of one item: its parts across volumes, decrypted if needed.
class PackedStream final : public ByteIn {
public:
    PackedStream(const Volumes &vols, const Item &item, const Keys *keys);
    std::size_t read(std::uint8_t *out, std::size_t n) override;
    std::uint64_t total() const { return total_; }

private:
    std::size_t read_raw(std::uint8_t *out, std::size_t n);
    const Volumes &vols_;
    const Item &item_;
    std::size_t part_ = 0;
    std::uint64_t in_part_ = 0, total_ = 0;
    std::unique_ptr<Aes> aes_;
    std::vector<std::uint8_t> pend_; // decrypted bytes not handed out yet
    std::size_t pend_pos_ = 0;
};

// MSB-first bit reader. fill() before each symbol keeps 32+ bytes ahead.
class BitIn {
public:
    static constexpr std::size_t kChunk = 1 << 16;
    void reset(ByteIn *src)
    {
        src_ = src;
        buf_.assign(kChunk + kPad, 0);
        len_ = 0;
        pos_ = 0;
        dropped_ = 0;
        eof_ = false;
        refill();
    }
    void fill()
    {
        if (len_ - std::min(len_, pos_ >> 3) < 64 && !eof_) refill();
        if (pos_ > (len_ + 16) * 8) fail(ErrorCode::Truncated, "compressed data ends early");
    }
    std::uint32_t peek32() const
    {
        std::uint64_t v;
        std::memcpy(&v, &buf_[pos_ >> 3], 8);
        v = __builtin_bswap64(v) << (pos_ & 7);
        return std::uint32_t(v >> 32);
    }
    std::uint32_t peek16() const { return peek32() >> 16; }
    void skip(unsigned n) { pos_ += n; }
    std::uint32_t get(unsigned n)
    {
        if (n == 0) return 0;
        const std::uint32_t v = peek32() >> (32 - n);
        pos_ += n;
        return v;
    }
    void align() { pos_ = (pos_ + 7) & ~std::size_t(7); }
    std::uint8_t byte()
    {
        const std::uint8_t v = std::uint8_t(peek32() >> 24);
        pos_ += 8;
        return v;
    }
    // Bits read since reset().
    std::uint64_t bit_pos() const { return dropped_ * 8 + pos_; }
    // At least `bytes` more input bytes are there.
    bool more(std::size_t bytes)
    {
        fill();
        return len_ * 8 >= pos_ + bytes * 8;
    }
    // True once everything read lies past the end of the input.
    bool exhausted() const { return eof_ && pos_ >= len_ * 8; }
    bool overrun() const { return eof_ && pos_ > len_ * 8; }

private:
    static constexpr std::size_t kPad = 128;
    void refill();
    ByteIn *src_ = nullptr;
    std::vector<std::uint8_t> buf_;
    std::size_t len_ = 0, pos_ = 0;
    std::uint64_t dropped_ = 0;
    bool eof_ = true;
};

// Canonical Huffman table as RAR builds it: symbols ordered by length,
// codes left-aligned in 16 bits, lengths up to 15.
class Huff {
public:
    void build(const std::uint8_t *lens, unsigned n);
    unsigned decode(BitIn &in) const
    {
        const std::uint32_t bits = in.peek16() & 0xfffe;
        if (bits < limit_[kQuick]) {
            const unsigned code = bits >> (16 - kQuick);
            in.skip(qlen_[code]);
            return qsym_[code];
        }
        unsigned len = kQuick + 1;
        while (len < 15 && bits >= limit_[len]) ++len;
        in.skip(len);
        const std::uint32_t pos = pos_[len] + ((bits - limit_[len - 1]) >> (16 - len));
        return pos < n_ ? sym_[pos] : sym_[0];
    }

private:
    static constexpr unsigned kQuick = 10;
    std::uint32_t limit_[16]{};
    std::uint32_t pos_[16]{};
    std::uint16_t sym_[512]{};
    unsigned n_ = 0;
    std::uint16_t qsym_[1 << kQuick]{};
    std::uint8_t qlen_[1 << kQuick]{};
};

// ---------------------------------------------------------------- output

// Where a decoder's bytes go for one item: the sink, the checksum, and
// the clip at the unpacked size.
class Output {
public:
    Output(Sink *sink, const Item &item, Context &ctx);
    void put(const std::uint8_t *p, std::size_t n);
    std::uint64_t written() const { return written_; }
    bool full() const { return known_ && written_ >= limit_; }
    std::uint32_t crc() const { return crc_; }
    std::array<std::uint8_t, 32> blake();

private:
    Sink *sink_;
    Context &ctx_;
    std::uint64_t limit_, written_ = 0, since_check_ = 0;
    bool known_;
    std::uint32_t crc_ = 0;
    std::unique_ptr<Blake2sp> b2_;
};

// Sliding window with absolute positions. Its size is a power of two at
// least as large as the dictionary (or the whole data when smaller).
class Window {
public:
    void ensure(std::uint64_t size);
    std::uint8_t *data() { return w_.get(); }
    std::uint64_t size() const { return size_; }
    std::uint64_t mask() const { return size_ - 1; }
    std::uint8_t &at(std::uint64_t pos) { return w_[pos & (size_ - 1)]; }
    // Copies len bytes from dist back. Positions before the start read as zero.
    void copy(std::uint64_t &pos, std::uint64_t dist, std::uint32_t len)
    {
        const std::uint64_t m = size_ - 1;
        std::uint64_t src = pos - dist;
        std::uint8_t *w = w_.get();
        const std::uint64_t d = pos & m, s = src & m;
        if (d + len <= size_ && s + len <= size_) {
            // Source ahead of the target (wrapped) or far enough behind: no overlap issue.
            if (s > d || dist >= len) std::memmove(w + d, w + s, len);
            else if (dist >= 8) for (std::uint32_t i = 0; i < len; i += 8) std::memcpy(w + d + i, w + s + i, std::min<std::uint32_t>(8, len - i));
            else for (std::uint32_t i = 0; i < len; ++i) w[d + i] = w[s + i];
        } else {
            for (std::uint32_t i = 0; i < len; ++i) w[(pos + i) & m] = w[(src + i) & m];
        }
        pos += len;
    }
    // Writes [from, to) of the window to out (to - from <= size()).
    void emit(std::uint64_t from, std::uint64_t to, Output &out);
    // Copies [from, from+n) into dst.
    void read(std::uint64_t from, std::size_t n, std::uint8_t *dst) const;

private:
    std::unique_ptr<std::uint8_t[]> w_;
    std::uint64_t size_ = 0;
};

// Window size for a dictionary when at most `total` bytes will be decoded.
std::uint64_t window_size(std::uint64_t dict, std::uint64_t total, bool total_known);

// ---------------------------------------------------------------- decoders

class Decoder {
public:
    virtual ~Decoder() = default;
    // Decodes one item. solid: continue from the state of the previous one.
    virtual void decode(ByteIn &in, Output &out, const Item &item, bool solid) = 0;
};

// window: bytes to reserve (see window_size).
std::unique_ptr<Decoder> make_rar5_decoder(std::uint64_t window, bool v7);
std::unique_ptr<Decoder> make_rar3_decoder(std::uint64_t window);
std::unique_ptr<Decoder> make_rar2_decoder(std::uint64_t window);
std::unique_ptr<Decoder> make_rar1_decoder(std::uint64_t window);

// DOS date/time (local) to Unix time.
Timestamp dos_time(std::uint32_t dos);
// Windows FILETIME to Unix time.
Timestamp file_time(std::uint64_t ft);
// UTF-16 code units to UTF-8.
std::string utf16_to_utf8(const std::vector<std::uint16_t> &w);
// Legacy 8-bit names: UTF-8 if valid, else code page 437.
std::string legacy_name(std::string_view s);

} // namespace raye::archive::detail::rar
