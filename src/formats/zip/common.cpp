// SPDX-License-Identifier: GPL-3.0-or-later
#include "zip.h"

#include "../../core/crypto.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>

#include <ctime>

namespace raye::archive::detail::zip {

bool g_force_zip64 = false;

namespace {

const std::array<std::uint32_t, 256> &crc_table()
{
    static const auto t = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }();
    return t;
}

} // namespace

std::uint32_t crc_byte(std::uint32_t crc, std::uint8_t b) { return crc_table()[(crc ^ b) & 0xff] ^ (crc >> 8); }

ZipCrypto::ZipCrypto(std::string_view password) : k_{0x12345678, 0x23456789, 0x34567890}
{
    for (char c : password) update(std::uint8_t(c));
}

void ZipCrypto::update(std::uint8_t c)
{
    k_[0] = crc_byte(k_[0], c);
    k_[1] = (k_[1] + (k_[0] & 0xff)) * 134775813u + 1;
    k_[2] = crc_byte(k_[2], std::uint8_t(k_[1] >> 24));
}

void ZipCrypto::decrypt(std::uint8_t *p, std::size_t n)
{
    for (std::size_t i = 0; i < n; ++i) {
        p[i] ^= stream();
        update(p[i]);
    }
}

void ZipCrypto::encrypt(std::uint8_t *p, std::size_t n)
{
    for (std::size_t i = 0; i < n; ++i) {
        const std::uint8_t c = p[i];
        p[i] ^= stream();
        update(c);
    }
}

HmacSha1::HmacSha1(std::span<const std::uint8_t> key)
{
    auto *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    auto *ctx = mac ? EVP_MAC_CTX_new(mac) : nullptr;
    mac_ = mac;
    ctx_ = ctx;
    char digest[] = "SHA1";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0), OSSL_PARAM_construct_end()};
    if (!ctx || !EVP_MAC_init(ctx, key.data(), key.size(), params)) fail(ErrorCode::Internal, "HMAC-SHA1 is not available");
}

HmacSha1::~HmacSha1()
{
    EVP_MAC_CTX_free(static_cast<EVP_MAC_CTX *>(ctx_));
    EVP_MAC_free(static_cast<EVP_MAC *>(mac_));
}

void HmacSha1::update(const std::uint8_t *p, std::size_t n)
{
    if (n && !EVP_MAC_update(static_cast<EVP_MAC_CTX *>(ctx_), p, n)) fail(ErrorCode::Internal, "HMAC update failed");
}

std::array<std::uint8_t, 20> HmacSha1::final()
{
    std::array<std::uint8_t, 20> out{};
    std::size_t len = 0;
    if (!EVP_MAC_final(static_cast<EVP_MAC_CTX *>(ctx_), out.data(), &len, out.size()) || len != 20)
        fail(ErrorCode::Internal, "HMAC final failed");
    return out;
}

AesKeys::~AesKeys()
{
    secure_wipe(key.data(), key.size());
    secure_wipe(mac_key.data(), mac_key.size());
}

AesKeys aes_keys(std::string_view password, std::span<const std::uint8_t> salt, std::uint8_t strength)
{
    const std::size_t ks = 8 * std::size_t(strength) + 8;
    std::vector<std::uint8_t> km(2 * ks + 2);
    pbkdf2(Hash::Sha1, password, salt, 1000, km);
    AesKeys k;
    k.key.assign(km.begin(), km.begin() + std::ptrdiff_t(ks));
    k.mac_key.assign(km.begin() + std::ptrdiff_t(ks), km.begin() + std::ptrdiff_t(2 * ks));
    k.verifier[0] = km[2 * ks];
    k.verifier[1] = km[2 * ks + 1];
    secure_wipe(km.data(), km.size());
    return k;
}

// DOS times are local wall-clock times, like Info-ZIP and 7-Zip read them.
std::optional<Timestamp> dos_to_unix(std::uint16_t time, std::uint16_t date)
{
    if (date == 0) return std::nullopt;
    std::tm tm{};
    tm.tm_year = ((date >> 9) & 0x7f) + 80;
    tm.tm_mon = ((date >> 5) & 0x0f) - 1;
    tm.tm_mday = date & 0x1f;
    tm.tm_hour = (time >> 11) & 0x1f;
    tm.tm_min = (time >> 5) & 0x3f;
    tm.tm_sec = (time & 0x1f) * 2;
    tm.tm_isdst = -1;
    if (tm.tm_mon < 0 || tm.tm_mon > 11 || tm.tm_mday == 0) return std::nullopt;
    const std::time_t t = std::mktime(&tm);
    if (t == std::time_t(-1)) return std::nullopt;
    return Timestamp{std::int64_t(t), 0};
}

void unix_to_dos(std::int64_t seconds, std::uint16_t &time, std::uint16_t &date)
{
    std::time_t t = std::time_t(seconds);
    std::tm tm{};
    if (!localtime_r(&t, &tm) || tm.tm_year < 80) {
        time = 0;
        date = (1 << 5) | 1; // 1980-01-01
        return;
    }
    if (tm.tm_year > 207) tm = std::tm{0, 58, 23, 31, 11, 207, 0, 0, 0, 0, nullptr};
    time = std::uint16_t(tm.tm_hour << 11 | tm.tm_min << 5 | tm.tm_sec / 2);
    date = std::uint16_t((tm.tm_year - 80) << 9 | (tm.tm_mon + 1) << 5 | tm.tm_mday);
}

static constexpr std::int64_t kFiletimeEpoch = 11644473600; // seconds from 1601 to 1970

Timestamp filetime_to_unix(std::uint64_t ft)
{
    const std::int64_t secs = std::int64_t(ft / 10000000) - kFiletimeEpoch;
    return {secs, std::uint32_t(ft % 10000000) * 100};
}

std::uint64_t unix_to_filetime(const Timestamp &t)
{
    const std::int64_t s = t.seconds + kFiletimeEpoch;
    if (s < 0) return 0;
    return std::uint64_t(s) * 10000000 + t.nanoseconds / 100;
}

std::string cp437_to_utf8(std::string_view s)
{
    static const char *const high[128] = {
        "Ç", "ü", "é", "â", "ä", "à", "å", "ç", "ê", "ë", "è", "ï", "î", "ì", "Ä", "Å",
        "É", "æ", "Æ", "ô", "ö", "ò", "û", "ù", "ÿ", "Ö", "Ü", "¢", "£", "¥", "₧", "ƒ",
        "á", "í", "ó", "ú", "ñ", "Ñ", "ª", "º", "¿", "⌐", "¬", "½", "¼", "¡", "«", "»",
        "░", "▒", "▓", "│", "┤", "╡", "╢", "╖", "╕", "╣", "║", "╗", "╝", "╜", "╛", "┐",
        "└", "┴", "┬", "├", "─", "┼", "╞", "╟", "╚", "╔", "╩", "╦", "╠", "═", "╬", "╧",
        "╨", "╤", "╥", "╙", "╘", "╒", "╓", "╫", "╪", "┘", "┌", "█", "▄", "▌", "▐", "▀",
        "α", "ß", "Γ", "π", "Σ", "σ", "µ", "τ", "Φ", "Θ", "Ω", "δ", "∞", "φ", "ε", "∩",
        "≡", "±", "≥", "≤", "⌠", "⌡", "÷", "≈", "°", "∙", "·", "√", "ⁿ", "²", "■", " ",
    };
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
        const auto c = std::uint8_t(ch);
        if (c < 0x80) out += ch;
        else out += high[c - 0x80];
    }
    return out;
}

bool valid_utf8(std::string_view s)
{
    std::size_t i = 0;
    while (i < s.size()) {
        const auto c = std::uint8_t(s[i]);
        std::size_t n;
        std::uint32_t cp;
        if (c < 0x80) { ++i; continue; }
        if ((c & 0xe0) == 0xc0) { n = 1; cp = c & 0x1f; }
        else if ((c & 0xf0) == 0xe0) { n = 2; cp = c & 0x0f; }
        else if ((c & 0xf8) == 0xf0) { n = 3; cp = c & 0x07; }
        else return false;
        for (std::size_t k = 1; k <= n; ++k) {
            if (i + k >= s.size()) return false;
            const auto d = std::uint8_t(s[i + k]);
            if ((d & 0xc0) != 0x80) return false;
            cp = cp << 6 | (d & 0x3f);
        }
        // Overlong forms and surrogates are not UTF-8.
        if ((n == 1 && cp < 0x80) || (n == 2 && cp < 0x800) || (n == 3 && (cp < 0x10000 || cp > 0x10ffff)) ||
            (cp >= 0xd800 && cp <= 0xdfff))
            return false;
        i += n + 1;
    }
    return true;
}

const char *method_label(std::uint16_t m)
{
    switch (m) {
    case kStore: return "Store";
    case kDeflate: return "Deflate";
    case kDeflate64: return "Deflate64";
    case kBzip2: return "BZip2";
    case kLzma: return "LZMA";
    case kZstd: return "Zstandard";
    case 20: return "Zstandard (old id)";
    case kXz: return "XZ";
    case kPpmd: return "PPMd";
    case 1: return "Shrink";
    case 2: case 3: case 4: case 5: return "Reduce";
    case 6: return "Implode";
    case 10: return "PKWARE Implode";
    case 18: return "IBM TERSE";
    case 19: return "IBM LZ77";
    case 96: return "JPEG";
    case 97: return "WavPack";
    default: return "unknown";
    }
}

} // namespace raye::archive::detail::zip
