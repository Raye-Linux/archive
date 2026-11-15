// SPDX-License-Identifier: GPL-3.0-or-later
// PPMd variant H (Dmitry Shkarin's model) with the range coder 7z uses.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace raye::archive::detail::ppmd7 {

class Model;

class Decoder {
public:
    // read_byte returns the next compressed byte (0 past the end).
    Decoder(unsigned order, std::uint32_t memory, int (*read_byte)(void *), void *ctx);
    ~Decoder();
    // Next symbol, -1 at an end marker, -2 on damaged data.
    int decode();

private:
    void normalize();
    std::unique_ptr<Model> m_;
    int (*read_)(void *);
    void *ctx_;
    std::uint32_t range_ = 0xFFFFFFFF, code_ = 0;
    bool started_ = false;
};

class Encoder {
public:
    Encoder(unsigned order, std::uint32_t memory);
    ~Encoder();
    void encode(const std::uint8_t *data, std::size_t n);
    // Flushes the range coder; out then holds the whole stream.
    void finish();
    std::vector<std::uint8_t> out;

private:
    void shift_low();
    void put(std::uint32_t start, std::uint32_t size, std::uint32_t total);
    void put_bit(std::uint32_t size0, int bit);
    void symbol(int c);
    std::unique_ptr<Model> m_;
    std::uint64_t low_ = 0;
    std::uint32_t range_ = 0xFFFFFFFF;
    std::uint8_t cache_ = 0;
    std::uint64_t cache_size_ = 1;
};

} // namespace raye::archive::detail::ppmd7
