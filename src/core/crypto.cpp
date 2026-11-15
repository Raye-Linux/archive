// SPDX-License-Identifier: GPL-3.0-or-later
#include "crypto.h"

#include <raye/archive/error.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <string>

namespace raye::archive::detail {

namespace {
const EVP_MD *md(Hash h) { return h == Hash::Sha1 ? EVP_sha1() : EVP_sha256(); }
[[noreturn]] void crypto_fail(const char *what) { fail(ErrorCode::Internal, std::string("crypto: ") + what); }
} // namespace

void sha256(const void *data, std::size_t n, std::uint8_t out[32])
{
    if (!EVP_Digest(data, n, out, nullptr, EVP_sha256(), nullptr)) crypto_fail("sha256");
}

void sha1(const void *data, std::size_t n, std::uint8_t out[20])
{
    if (!EVP_Digest(data, n, out, nullptr, EVP_sha1(), nullptr)) crypto_fail("sha1");
}

struct HashState {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    ~HashState() { EVP_MD_CTX_free(ctx); }
};

Sha256::Sha256() : s_(std::make_unique<HashState>())
{
    if (!s_->ctx || !EVP_DigestInit_ex(s_->ctx, EVP_sha256(), nullptr)) crypto_fail("sha256 init");
}
Sha256::~Sha256() = default;

void Sha256::update(const void *data, std::size_t n)
{
    if (!EVP_DigestUpdate(s_->ctx, data, n)) crypto_fail("sha256 update");
}

std::array<std::uint8_t, 32> Sha256::final()
{
    std::array<std::uint8_t, 32> out{};
    unsigned len = 0;
    if (!EVP_DigestFinal_ex(s_->ctx, out.data(), &len)) crypto_fail("sha256 final");
    return out;
}

std::vector<std::uint8_t> hmac(Hash h, std::span<const std::uint8_t> key, std::span<const std::uint8_t> data)
{
    std::vector<std::uint8_t> out(EVP_MAX_MD_SIZE);
    unsigned len = 0;
    if (!HMAC(md(h), key.data(), int(key.size()), data.data(), data.size(), out.data(), &len)) crypto_fail("hmac");
    out.resize(len);
    return out;
}

void pbkdf2(Hash h, std::string_view pw, std::span<const std::uint8_t> salt, std::uint32_t iterations,
            std::span<std::uint8_t> out)
{
    if (!PKCS5_PBKDF2_HMAC(pw.data(), int(pw.size()), salt.data(), int(salt.size()), int(iterations), md(h),
                           int(out.size()), out.data()))
        crypto_fail("pbkdf2");
}

Aes::Aes(std::span<const std::uint8_t> key, Mode mode, bool encrypt, std::span<const std::uint8_t> iv)
{
    const EVP_CIPHER *c = nullptr;
    const bool cbc = mode == Mode::Cbc;
    switch (key.size()) {
    case 16: c = cbc ? EVP_aes_128_cbc() : EVP_aes_128_ecb(); break;
    case 24: c = cbc ? EVP_aes_192_cbc() : EVP_aes_192_ecb(); break;
    case 32: c = cbc ? EVP_aes_256_cbc() : EVP_aes_256_ecb(); break;
    default: fail(ErrorCode::Internal, "AES key must be 16, 24 or 32 bytes");
    }
    if (cbc && iv.size() != 16) fail(ErrorCode::Internal, "AES-CBC needs a 16-byte IV");
    auto *ctx = EVP_CIPHER_CTX_new();
    if (!ctx || !EVP_CipherInit_ex(ctx, c, nullptr, key.data(), cbc ? iv.data() : nullptr, encrypt ? 1 : 0)) {
        EVP_CIPHER_CTX_free(ctx);
        crypto_fail("aes init");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    ctx_ = ctx;
}

Aes::~Aes() { EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX *>(ctx_)); }

void Aes::process(const std::uint8_t *in, std::uint8_t *out, std::size_t n)
{
    if (n % 16) fail(ErrorCode::Internal, "AES input is not a multiple of 16 bytes");
    while (n) {
        const int chunk = n > (1u << 30) ? (1 << 30) : int(n);
        int len = 0;
        if (!EVP_CipherUpdate(static_cast<EVP_CIPHER_CTX *>(ctx_), out, &len, in, chunk)) crypto_fail("aes");
        in += chunk;
        out += chunk;
        n -= std::size_t(chunk);
    }
}

AesCtrLE::AesCtrLE(std::span<const std::uint8_t> key) : aes_(key, Aes::Mode::Ecb, true) {}

void AesCtrLE::process(std::uint8_t *data, std::size_t n)
{
    for (std::size_t i = 0; i < n; ++i) {
        if (used_ == 16) {
            for (auto &b : counter_)
                if (++b != 0) break;
            aes_.process(counter_.data(), stream_.data(), 16);
            used_ = 0;
        }
        data[i] ^= stream_[used_++];
    }
}

void random_bytes(std::span<std::uint8_t> out)
{
    if (RAND_bytes(out.data(), int(out.size())) != 1) crypto_fail("random");
}

void secure_wipe(void *p, std::size_t n) { OPENSSL_cleanse(p, n); }

} // namespace raye::archive::detail
