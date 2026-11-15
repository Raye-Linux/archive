// SPDX-License-Identifier: GPL-3.0-or-later
// Password to key for RAR 3.x (SHA-1 rounds) and RAR 5.0 (PBKDF2).
#include "rar.h"

#include "../../core/bytes.h"

#include <openssl/evp.h>

namespace raye::archive::detail::rar {

Keys::~Keys()
{
    if (!key.empty()) secure_wipe(key.data(), key.size());
    secure_wipe(iv.data(), iv.size());
    secure_wipe(hash_key.data(), hash_key.size());
}

namespace {

inline std::uint32_t rol(std::uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

// SHA-1 as the RAR 2.9 code had it: whole blocks hashed straight from the
// caller's buffer get the last 16 words of the message schedule written
// back into that buffer. Keys of long passwords depend on it.
struct Sha1Rar {
    std::uint32_t h[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    std::uint64_t count = 0;
    std::uint8_t buf[64] = {};

    void transform(const std::uint8_t *block, std::uint32_t *tail)
    {
        std::uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = std::uint32_t(block[4 * i]) << 24 | std::uint32_t(block[4 * i + 1]) << 16 |
                   std::uint32_t(block[4 * i + 2]) << 8 | block[4 * i + 3];
        for (int i = 16; i < 80; ++i) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            std::uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
            else { f = b ^ c ^ d; k = 0xca62c1d6; }
            const std::uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
        if (tail)
            for (int i = 0; i < 16; ++i) tail[i] = w[64 + i];
    }

    void update(std::uint8_t *data, std::size_t len, bool modify)
    {
        std::size_t j = std::size_t(count & 63), i = 0;
        count += len;
        if (j + len > 63) {
            i = 64 - j;
            std::memcpy(buf + j, data, i);
            transform(buf, nullptr);
            for (; i + 63 < len; i += 64) {
                std::uint32_t tail[16];
                transform(data + i, modify ? tail : nullptr);
                if (modify)
                    for (int k = 0; k < 16; ++k) put_le32(data + i + 4 * k, tail[k]);
            }
            j = 0;
        }
        std::memcpy(buf + j, data + i, len - i);
    }

    std::array<std::uint8_t, 20> final() const
    {
        Sha1Rar c = *this;
        const std::uint64_t bits = count * 8;
        std::uint8_t pad[72] = {0x80};
        const std::size_t padlen = ((count & 63) < 56 ? 56 : 120) - std::size_t(count & 63);
        for (int i = 0; i < 8; ++i) pad[padlen + std::size_t(i)] = std::uint8_t(bits >> (56 - 8 * i));
        c.update(pad, padlen + 8, false);
        std::array<std::uint8_t, 20> out{};
        for (int i = 0; i < 5; ++i)
            for (int k = 0; k < 4; ++k) out[std::size_t(4 * i + k)] = std::uint8_t(c.h[i] >> (24 - 8 * k));
        return out;
    }
};

// UTF-8 to UTF-16LE bytes (RAR passwords are UTF-16 in 2.9-4.x).
std::vector<std::uint8_t> utf16le(const std::string &s)
{
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i < s.size();) {
        std::uint32_t c = std::uint8_t(s[i]);
        int extra = c < 0x80 ? 0 : c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : c >= 0xc0 ? 1 : 0;
        if (extra) c &= 0x3f >> extra;
        ++i;
        for (int k = 0; k < extra && i < s.size(); ++k, ++i) c = (c << 6) | (std::uint8_t(s[i]) & 0x3f);
        auto put = [&](std::uint32_t u) { out.push_back(std::uint8_t(u)); out.push_back(std::uint8_t(u >> 8)); };
        if (c >= 0x10000) {
            c -= 0x10000;
            put(0xd800 + (c >> 10));
            put(0xdc00 + (c & 0x3ff));
        } else {
            put(c);
        }
    }
    return out;
}

// HMAC-SHA256 with the key pads hashed once.
class Hmac256 {
public:
    explicit Hmac256(std::string_view key)
    {
        std::uint8_t k[64] = {};
        if (key.size() > 64) sha256(key.data(), key.size(), k);
        else std::memcpy(k, key.data(), key.size());
        std::uint8_t pad[64];
        inner_ = EVP_MD_CTX_new();
        outer_ = EVP_MD_CTX_new();
        tmp_ = EVP_MD_CTX_new();
        for (int i = 0; i < 64; ++i) pad[i] = k[i] ^ 0x36;
        EVP_DigestInit_ex(inner_, EVP_sha256(), nullptr);
        EVP_DigestUpdate(inner_, pad, 64);
        for (int i = 0; i < 64; ++i) pad[i] = k[i] ^ 0x5c;
        EVP_DigestInit_ex(outer_, EVP_sha256(), nullptr);
        EVP_DigestUpdate(outer_, pad, 64);
        secure_wipe(k, sizeof k);
        secure_wipe(pad, sizeof pad);
    }
    ~Hmac256()
    {
        EVP_MD_CTX_free(inner_);
        EVP_MD_CTX_free(outer_);
        EVP_MD_CTX_free(tmp_);
    }
    void mac(const std::uint8_t *msg, std::size_t n, std::uint8_t out[32])
    {
        unsigned len = 0;
        EVP_MD_CTX_copy_ex(tmp_, inner_);
        EVP_DigestUpdate(tmp_, msg, n);
        EVP_DigestFinal_ex(tmp_, out, &len);
        EVP_MD_CTX_copy_ex(tmp_, outer_);
        EVP_DigestUpdate(tmp_, out, 32);
        EVP_DigestFinal_ex(tmp_, out, &len);
    }

private:
    EVP_MD_CTX *inner_, *outer_, *tmp_;
};

} // namespace

std::array<std::uint8_t, 20> sha1_rar29(std::vector<std::uint8_t> data)
{
    Sha1Rar s;
    s.update(data.data(), data.size(), true);
    return s.final();
}

void rar3_keys(const std::string &password, const std::uint8_t salt[8], Keys &out)
{
    std::vector<std::uint8_t> raw = utf16le(password);
    if (raw.size() > 254) raw.resize(254); // RAR keeps 127 characters
    if (salt) raw.insert(raw.end(), salt, salt + 8);
    Sha1Rar s;
    constexpr std::uint32_t kRounds = 0x40000;
    for (std::uint32_t i = 0; i < kRounds; ++i) {
        s.update(raw.data(), raw.size(), true);
        std::uint8_t num[3] = {std::uint8_t(i), std::uint8_t(i >> 8), std::uint8_t(i >> 16)};
        s.update(num, 3, true);
        if (i % (kRounds / 16) == 0) out.iv[i / (kRounds / 16)] = s.final()[19];
    }
    const auto d = s.final();
    out.key.resize(16);
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j) out.key[std::size_t(i * 4 + j)] = d[std::size_t(i * 4 + 3 - j)];
    secure_wipe(raw.data(), raw.size());
}

std::array<std::uint8_t, 8> rar5_check_value(const std::array<std::uint8_t, 32> &v)
{
    std::array<std::uint8_t, 8> c{};
    for (std::size_t i = 0; i < 32; ++i) c[i % 8] ^= v[i];
    return c;
}

bool rar5_keys(const std::string &password, const CryptInfo &ci, Keys &out)
{
    if (ci.kdf_log2 > 24) fail(ErrorCode::UnsupportedMethod, "RAR5 key derivation count is too large");
    Hmac256 h(password);
    std::uint8_t u[32], t[32];
    std::uint8_t first[20];
    std::memcpy(first, ci.salt.data(), 16);
    first[16] = 0; first[17] = 0; first[18] = 0; first[19] = 1;
    h.mac(first, 20, u);
    std::memcpy(t, u, 32);
    const std::uint32_t count = 1u << ci.kdf_log2;
    std::array<std::uint8_t, 32> check{};
    if (count == 1) out.key.assign(t, t + 32);
    for (std::uint32_t i = 1; i < count + 32; ++i) {
        h.mac(u, 32, u);
        for (int k = 0; k < 32; ++k) t[k] ^= u[k];
        if (i == count - 1) out.key.assign(t, t + 32);
        else if (i == count + 15) std::memcpy(out.hash_key.data(), t, 32);
        else if (i == count + 31) std::memcpy(check.data(), t, 32);
    }
    std::memcpy(out.iv.data(), ci.iv.data(), 16);
    secure_wipe(u, sizeof u);
    secure_wipe(t, sizeof t);
    out.check = rar5_check_value(check);
    if (!ci.has_check) return true;
    return out.check == ci.check;
}

std::uint32_t rar5_mix_crc(std::uint32_t crc, const std::array<std::uint8_t, 32> &hk)
{
    Hmac256 h(std::string_view(reinterpret_cast<const char *>(hk.data()), hk.size()));
    std::uint8_t raw[4], d[32];
    put_le32(raw, crc);
    h.mac(raw, 4, d);
    std::uint32_t v = 0;
    for (int i = 0; i < 32; ++i) v ^= std::uint32_t(d[i]) << ((i & 3) * 8);
    return v;
}

std::array<std::uint8_t, 32> rar5_mix_hash(const std::array<std::uint8_t, 32> &v, const std::array<std::uint8_t, 32> &hk)
{
    Hmac256 h(std::string_view(reinterpret_cast<const char *>(hk.data()), hk.size()));
    std::array<std::uint8_t, 32> out{};
    h.mac(v.data(), 32, out.data());
    return out;
}

} // namespace raye::archive::detail::rar
