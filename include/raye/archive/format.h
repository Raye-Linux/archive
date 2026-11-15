// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace raye::archive {

class Source;

enum class Format : std::uint16_t {
    Unknown = 0,
    Zip,
    SevenZip,
    Rar,      // RAR 1.5 to 4.x
    Rar5,
    Tar,
    Gzip,     // single stream compressors; tar.* is detected as the stream first
    Bzip2,
    Xz,
    Lzma,     // legacy .lzma (LZMA alone)
    Zstd,
    Lz4,
    Lzip,
    Brotli,   // no magic, extension only
    Compress, // .Z
    Iso9660,
    Udf,
    Cab,
    Cpio,
    Ar,       // includes .deb
    Rpm,
    Arj,
    Lzh,
};

// "zip", "7z", "rar", ... (lower case, stable, used by the CLI).
const char *format_name(Format f) noexcept;
// Parse a name from format_name() or a common alias ("7zip", "tgz"); nullopt if unknown.
std::optional<Format> format_from_name(std::string_view name) noexcept;
// True if Raye can create archives of this format (never for RAR).
bool format_can_write(Format f) noexcept;

struct Detection {
    Format format = Format::Unknown;
    int score = 0;               // 0..100; 100 = signature at offset 0
    std::uint64_t offset = 0;    // where the archive starts (non-zero for self-extracting)
    bool self_extracting = false;
    std::string detail;          // e.g. "RAR 5.0", "ZIP64", "tar.xz"
};

// Detect by content (signatures, end records), never trusting the extension
// except to break ties and for formats with no magic.
Detection detect(const std::filesystem::path &path);
Detection detect(Source &source, std::string_view name_hint = {});

// Every candidate the drivers proposed, best first (for diagnostics).
std::vector<Detection> detect_all(Source &source, std::string_view name_hint = {});

// Multi-volume sets. From any member, return every volume in order, first
// one first. Single-volume archives return {path}. Missing later volumes are
// not an error here; missing_after tells where the set breaks.
struct VolumeSet {
    std::vector<std::filesystem::path> volumes;
    bool complete = true;
    enum class Kind { Single, Split, RarNew, RarOld, ZipSplit } kind = Kind::Single;
};
VolumeSet find_volumes(const std::filesystem::path &any_volume);

} // namespace raye::archive
