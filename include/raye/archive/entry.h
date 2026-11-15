// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace raye::archive {

enum class EntryType : std::uint8_t { File, Directory, Symlink, Hardlink, Other };

struct Timestamp {
    std::int64_t seconds = 0; // Unix time
    std::uint32_t nanoseconds = 0;
};

struct Entry {
    std::size_t index = 0;          // position in Archive::entries()
    std::string path;               // UTF-8, '/' separated, as stored (not yet sanitized)
    EntryType type = EntryType::File;
    std::uint64_t size = 0;         // unpacked size, if known
    std::uint64_t packed_size = 0;  // 0 if not known per entry (solid blocks)
    bool size_known = true;
    std::optional<Timestamp> mtime, atime, ctime;
    std::optional<std::uint32_t> mode;      // Unix permission bits, without file type
    std::optional<std::uint32_t> windows_attributes;
    std::string link_target;        // Symlink / Hardlink
    bool encrypted = false;
    bool solid = false;             // depends on earlier entries
    std::optional<std::uint32_t> crc32;
    std::string method;             // "Deflate", "LZMA2:24", "RAR5", "Store" ...
    std::string comment;
    std::uint32_t volume = 0;       // volume the entry starts in
};

} // namespace raye::archive
