// SPDX-License-Identifier: GPL-3.0-or-later
// ZIP layout shared by the reader and the writer (APPNOTE 6.3.10, WinZip AE-x).
#pragma once

#include "../../core/bytes.h"
#include "../../core/codec.h"
#include "../../core/driver.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace raye::archive::detail::zip {

inline constexpr std::uint32_t kLocalSig = 0x04034b50;
inline constexpr std::uint32_t kCentralSig = 0x02014b50;
inline constexpr std::uint32_t kEndSig = 0x06054b50;
inline constexpr std::uint32_t kEnd64Sig = 0x06064b50;
inline constexpr std::uint32_t kLocator64Sig = 0x07064b50;
inline constexpr std::uint32_t kDescriptorSig = 0x08074b50;

inline constexpr std::size_t kLocalSize = 30;
inline constexpr std::size_t kCentralSize = 46;
inline constexpr std::size_t kEndSize = 22;
inline constexpr std::size_t kEnd64Size = 56;
inline constexpr std::size_t kLocator64Size = 20;

enum Flag : std::uint16_t {
    kEncrypted = 1 << 0,
    kLzmaEos = 1 << 1,
    kDescriptor = 1 << 3,
    kStrongEncryption = 1 << 6,
    kUtf8 = 1 << 11,
    kMaskedHeaders = 1 << 13,
};

enum MethodId : std::uint16_t {
    kStore = 0,
    kDeflate = 8,
    kDeflate64 = 9,
    kBzip2 = 12,
    kLzma = 14,
    kZstd = 93,
    kXz = 95,
    kPpmd = 98,
    kAes = 99,
};

enum ExtraId : std::uint16_t {
    kExtraZip64 = 0x0001,
    kExtraNtfs = 0x000a,
    kExtraUnixTime = 0x5455,
    kExtraUnicodePath = 0x7075,
    kExtraUnicodeComment = 0x6375,
    kExtraAes = 0x9901,
};

// Hosts in the high byte of "version made by".
inline bool dos_like_host(std::uint8_t host) { return host == 0 || host == 6 || host == 10 || host == 11 || host == 14; }
inline bool unix_like_host(std::uint8_t host) { return host == 3 || host == 19; }

struct AesInfo {
    std::uint16_t version = 0;  // 1 = AE-1 (CRC checked), 2 = AE-2
    std::uint8_t strength = 0;  // 1, 2, 3 = 128, 192, 256 bits
    std::uint16_t method = 0;   // real compression method
    std::size_t key_size() const { return 8 * strength + 8; }
    std::size_t salt_size() const { return 4 * strength + 4; }
};

// One file as the central directory describes it.
struct Record {
    std::uint16_t made_by = 0, needed = 0, flags = 0, method = 0;
    std::uint16_t dos_time = 0, dos_date = 0;
    std::uint32_t crc = 0;
    std::uint64_t packed = 0, size = 0;
    std::uint32_t disk = 0;
    std::uint16_t internal_attr = 0;
    std::uint32_t external_attr = 0;
    std::uint64_t local_offset = 0;   // absolute in the source once resolved
    std::string raw_name, raw_comment;
    std::vector<std::uint8_t> extra;  // central extra, as stored
    std::optional<AesInfo> aes;
    std::string name;                 // UTF-8
    std::string comment;
    std::optional<Timestamp> mtime, atime, ctime;
    bool zip64 = false;

    std::uint16_t real_method() const { return aes ? aes->method : method; }
};

// Walks the extra fields of a header; callback gets (id, payload). Stops
// quietly on a truncated last field (some writers pad with junk).
template <class F> void for_each_extra(std::span<const std::uint8_t> extra, F &&f)
{
    std::size_t p = 0;
    while (p + 4 <= extra.size()) {
        const std::uint16_t id = le16(&extra[p]);
        const std::uint16_t len = le16(&extra[p + 2]);
        if (p + 4 + len > extra.size()) return;
        f(id, extra.subspan(p + 4, len));
        p += 4 + std::size_t(len);
    }
}

// Raw CRC step used by the traditional PKWARE cipher (no pre/post inversion).
std::uint32_t crc_byte(std::uint32_t crc, std::uint8_t b);

class ZipCrypto {
public:
    explicit ZipCrypto(std::string_view password);
    void decrypt(std::uint8_t *p, std::size_t n);
    void encrypt(std::uint8_t *p, std::size_t n);

private:
    std::uint8_t stream() const
    {
        const std::uint32_t t = (k_[2] | 2) & 0xffff;
        return std::uint8_t((t * (t ^ 1)) >> 8);
    }
    void update(std::uint8_t c);
    std::uint32_t k_[3];
};

// HMAC-SHA1 fed piece by piece (WinZip authentication code).
class HmacSha1 {
public:
    explicit HmacSha1(std::span<const std::uint8_t> key);
    ~HmacSha1();
    HmacSha1(const HmacSha1 &) = delete;
    HmacSha1 &operator=(const HmacSha1 &) = delete;
    void update(const std::uint8_t *p, std::size_t n);
    std::array<std::uint8_t, 20> final();

private:
    void *mac_ = nullptr, *ctx_ = nullptr;
};

// Key material for WinZip AES: encryption key, HMAC key, 2-byte verifier.
struct AesKeys {
    std::vector<std::uint8_t> key, mac_key;
    std::uint8_t verifier[2] = {};
    ~AesKeys();
};
AesKeys aes_keys(std::string_view password, std::span<const std::uint8_t> salt, std::uint8_t strength);

std::optional<Timestamp> dos_to_unix(std::uint16_t time, std::uint16_t date);
void unix_to_dos(std::int64_t seconds, std::uint16_t &time, std::uint16_t &date);
// 100 ns ticks since 1601 <-> Unix.
Timestamp filetime_to_unix(std::uint64_t ft);
std::uint64_t unix_to_filetime(const Timestamp &t);

std::string cp437_to_utf8(std::string_view s);
bool valid_utf8(std::string_view s);

const char *method_label(std::uint16_t method);

// Deflate64 (PKWARE method 9) decoder, also usable by the 7z reader.
std::unique_ptr<Coder> make_deflate64_decoder();

// Set by tests: every new entry gets ZIP64 fields even when small.
extern bool g_force_zip64;

} // namespace raye::archive::detail::zip
