// SPDX-License-Identifier: GPL-3.0-or-later
// Bounds-checked byte parsing. Every header reader goes through these:
// a short or lying header throws Corrupt/Truncated, never reads past the end.
#pragma once

#include <raye/archive/error.h>
#include <raye/archive/io.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace raye::archive::detail {

inline std::uint16_t le16(const std::uint8_t *p) { return std::uint16_t(p[0] | p[1] << 8); }
inline std::uint32_t le32(const std::uint8_t *p) {
    return std::uint32_t(p[0]) | std::uint32_t(p[1]) << 8 | std::uint32_t(p[2]) << 16 | std::uint32_t(p[3]) << 24;
}
inline std::uint64_t le64(const std::uint8_t *p) { return le32(p) | std::uint64_t(le32(p + 4)) << 32; }
inline std::uint32_t be32(const std::uint8_t *p) {
    return std::uint32_t(p[0]) << 24 | std::uint32_t(p[1]) << 16 | std::uint32_t(p[2]) << 8 | p[3];
}
inline void put_le16(std::uint8_t *p, std::uint16_t v) { p[0] = std::uint8_t(v); p[1] = std::uint8_t(v >> 8); }
inline void put_le32(std::uint8_t *p, std::uint32_t v) { for (int i = 0; i < 4; ++i) p[i] = std::uint8_t(v >> (8 * i)); }
inline void put_le64(std::uint8_t *p, std::uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = std::uint8_t(v >> (8 * i)); }

// Cursor over a buffer already in memory.
class ByteReader {
public:
    explicit ByteReader(std::span<const std::uint8_t> data) : d_(data) {}
    std::size_t pos() const { return pos_; }
    std::size_t left() const { return d_.size() - pos_; }
    bool eof() const { return pos_ >= d_.size(); }
    void need(std::size_t n) const {
        if (n > left()) fail(ErrorCode::Corrupt, "header is shorter than it says");
    }
    void skip(std::size_t n) { need(n); pos_ += n; }
    void seek(std::size_t p) { if (p > d_.size()) fail(ErrorCode::Corrupt, "bad offset in header"); pos_ = p; }
    std::uint8_t u8() { need(1); return d_[pos_++]; }
    std::uint16_t u16() { need(2); auto v = le16(&d_[pos_]); pos_ += 2; return v; }
    std::uint32_t u32() { need(4); auto v = le32(&d_[pos_]); pos_ += 4; return v; }
    std::uint64_t u64() { need(8); auto v = le64(&d_[pos_]); pos_ += 8; return v; }
    std::uint32_t u32be() { need(4); auto v = be32(&d_[pos_]); pos_ += 4; return v; }
    // RAR5 vint: 7 bits per byte, low first, at most 10 bytes.
    std::uint64_t vint();
    std::span<const std::uint8_t> bytes(std::size_t n) { need(n); auto s = d_.subspan(pos_, n); pos_ += n; return s; }
    std::string str(std::size_t n) { auto s = bytes(n); return {reinterpret_cast<const char *>(s.data()), s.size()}; }

private:
    std::span<const std::uint8_t> d_;
    std::size_t pos_ = 0;
};

// Sequential reads from a Source with a buffer (headers, compressed data).
class SourceReader {
public:
    SourceReader(const Source &src, std::uint64_t start, std::uint64_t end, std::size_t buffer = 1 << 16);
    std::uint64_t pos() const { return pos_; }
    std::uint64_t left() const { return end_ - pos_; }
    void seek(std::uint64_t p);
    // Up to n bytes; 0 only at end.
    std::size_t read(void *out, std::size_t n);
    void read_exact(void *out, std::size_t n);
    std::vector<std::uint8_t> read_vec(std::size_t n);
    // Direct view of what is buffered (at least 1 byte unless at end).
    std::span<const std::uint8_t> peek();
    void consume(std::size_t n);

private:
    void fill();
    const Source &src_;
    std::uint64_t pos_, end_;
    std::vector<std::uint8_t> buf_;
    std::uint64_t buf_pos_ = 0; // file offset of buf_[0]
    std::size_t buf_len_ = 0;
};

// Refuses absurd header sizes before allocating (a 4 GiB "header" in a
// 10 KiB file is an attack, not an archive).
void check_alloc(std::uint64_t wanted, std::uint64_t archive_size, std::uint64_t slack = 64 << 20);

} // namespace raye::archive::detail
