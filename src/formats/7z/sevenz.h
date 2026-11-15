// SPDX-License-Identifier: GPL-3.0-or-later
// 7z archive layout, as described in 7zFormat.txt.
#pragma once

#include "../../core/bytes.h"

#include <raye/archive/entry.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace raye::archive::detail::sevenz {

inline constexpr std::uint8_t kSignature[6] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
inline constexpr std::size_t kStartHeaderSize = 32;

enum Prop : std::uint8_t {
    kEnd = 0x00, kHeader, kArchiveProperties, kAdditionalStreamsInfo, kMainStreamsInfo, kFilesInfo,
    kPackInfo, kUnpackInfo, kSubStreamsInfo, kSize, kCRC, kFolder, kCodersUnpackSize, kNumUnpackStream,
    kEmptyStream, kEmptyFile, kAnti, kName, kCTime, kATime, kMTime, kWinAttributes, kComment,
    kEncodedHeader, kStartPos, kDummy,
};

// Method ids, as stored (big-endian bytes packed into an integer).
namespace method {
inline constexpr std::uint64_t Copy = 0x00, Delta = 0x03, X86 = 0x03030103, Bcj2 = 0x0303011B,
    Ppc = 0x03030205, Ia64 = 0x03030401, Arm = 0x03030501, Armt = 0x03030701, Sparc = 0x03030805,
    Arm64 = 0x0A, RiscV = 0x0B, Lzma = 0x030101, Lzma2 = 0x21, Ppmd = 0x030401, Deflate = 0x040108,
    Deflate64 = 0x040109, Bzip2 = 0x040202, Aes = 0x06F10701, Zstd = 0x04F71101, Brotli = 0x04F71102,
    Lz4 = 0x04F71104,
    // newer short ids for the branch filters (7-Zip 9.30 and later write the long ones)
    X86Short = 0x04, PpcShort = 0x05, Ia64Short = 0x06, ArmShort = 0x07, ArmtShort = 0x08, SparcShort = 0x09;
}
std::string method_label(std::uint64_t id);

struct Coder {
    std::uint64_t id = 0;
    std::uint32_t num_in = 1, num_out = 1;
    std::vector<std::uint8_t> props;
};

struct BindPair {
    std::uint64_t in = 0, out = 0;
};

struct Folder {
    std::vector<Coder> coders;
    std::vector<BindPair> binds;
    std::vector<std::uint64_t> packed;       // coder in-stream index of each packed stream
    std::vector<std::uint64_t> unpack_sizes; // one per coder out stream
    std::optional<std::uint32_t> crc;
    std::size_t first_pack = 0;              // index into pack_sizes
    std::uint64_t num_substreams = 1;

    std::size_t total_in() const;
    std::size_t total_out() const;
    // Out stream that is not bound to anything: the folder's output.
    std::size_t main_out() const;
    std::uint64_t unpack_size() const { return unpack_sizes.empty() ? 0 : unpack_sizes[main_out()]; }
    // Coder and its first in/out stream index for a global stream index.
    std::size_t coder_of_in(std::uint64_t in, std::uint32_t *local = nullptr) const;
    std::size_t coder_of_out(std::uint64_t out, std::uint32_t *local = nullptr) const;
    std::size_t first_in(std::size_t coder) const;
    std::size_t first_out(std::size_t coder) const;
    bool encrypted() const;
};

struct StreamsInfo {
    std::uint64_t pack_pos = 0;                         // from the end of the start header
    std::vector<std::uint64_t> pack_sizes;
    std::vector<Folder> folders;
    std::vector<std::uint64_t> sub_sizes;               // every substream, folder by folder
    std::vector<std::optional<std::uint32_t>> sub_crcs;
};

struct FileItem {
    std::string name;                                   // UTF-8
    bool has_stream = true;
    bool is_dir = false;
    bool is_anti = false;
    std::optional<std::uint64_t> mtime, atime, ctime;   // FILETIME
    std::optional<std::uint32_t> attrib;
    std::optional<std::uint64_t> start_pos;
};

struct Database {
    StreamsInfo streams;
    std::vector<FileItem> files;
};

// 7z variable-length number.
std::uint64_t read_number(ByteReader &r);
void write_number(std::vector<std::uint8_t> &out, std::uint64_t v);

void parse_streams_info(ByteReader &r, StreamsInfo &si, std::uint64_t archive_size);
// Header that starts with kHeader (after decoding any kEncodedHeader).
void parse_header(ByteReader &r, Database &db, std::uint64_t archive_size);
std::vector<std::uint8_t> write_header(const Database &db);
std::vector<std::uint8_t> write_encoded_header(const StreamsInfo &si);

std::string utf16le_to_utf8(const std::uint8_t *p, std::size_t units);
std::vector<std::uint8_t> utf8_to_utf16le(const std::string &s);

// Windows FILETIME (100 ns since 1601) and Unix time.
std::optional<Timestamp> filetime_to_unix(std::uint64_t ft);
std::uint64_t unix_to_filetime(const Timestamp &t);

inline constexpr std::uint32_t kAttrDirectory = 0x10, kAttrReadOnly = 0x01, kAttrArchive = 0x20,
                               kAttrUnixExtension = 0x8000;

} // namespace raye::archive::detail::sevenz
