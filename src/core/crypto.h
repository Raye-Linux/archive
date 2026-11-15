// SPDX-License-Identifier: GPL-3.0-or-later
// Thin wrappers over libcrypto. Keys and passwords are wiped on destruction.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace raye::archive::detail {

enum class Hash { Sha1, Sha256 };

void sha256(const void *data, std::size_t n, std::uint8_t out[32]);
void sha1(const void *data, std::size_t n, std::uint8_t out[20]);

class Sha256 {
public:
    Sha256();
    ~Sha256();
    void update(const void *data, std::size_t n);
    std::array<std::uint8_t, 32> final();

private:
    std::unique_ptr<struct HashState> s_;
};

std::vector<std::uint8_t> hmac(Hash h, std::span<const std::uint8_t> key, std::span<const std::uint8_t> data);
// PBKDF2-HMAC; out.size() bytes of key material.
void pbkdf2(Hash h, std::string_view password, std::span<const std::uint8_t> salt, std::uint32_t iterations,
            std::span<std::uint8_t> out);

// AES in CBC (7z, RAR) or as a raw block cipher (build WinZip's
// little-endian CTR on top). key: 16, 24 or 32 bytes.
class Aes {
public:
    enum class Mode { Ecb, Cbc };
    Aes(std::span<const std::uint8_t> key, Mode mode, bool encrypt, std::span<const std::uint8_t> iv = {});
    ~Aes();
    Aes(const Aes &) = delete;
    Aes &operator=(const Aes &) = delete;
    // n must be a multiple of 16; in and out may be the same buffer.
    void process(const std::uint8_t *in, std::uint8_t *out, std::size_t n);

private:
    void *ctx_ = nullptr;
};

// WinZip AE-1/AE-2 CTR: counter starts at 1, little-endian, 16-byte block.
class AesCtrLE {
public:
    explicit AesCtrLE(std::span<const std::uint8_t> key);
    void process(std::uint8_t *data, std::size_t n);

private:
    Aes aes_;
    std::array<std::uint8_t, 16> counter_{}, stream_{};
    std::size_t used_ = 16;
};

void random_bytes(std::span<std::uint8_t> out);
void secure_wipe(void *p, std::size_t n);

} // namespace raye::archive::detail
