// SPDX-License-Identifier: GPL-3.0-or-later
// tar headers: ustar, pax (POSIX 2001), GNU (long names, old sparse,
// base-256 numbers) and v7. Reading and writing.
#pragma once

#include "stream.h"

#include <raye/archive/entry.h>

#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace raye::archive::detail {

struct TarItem {
    Entry entry;
    std::uint64_t data_pos = 0;  // offset of the data in the (decoded) tar stream
    std::uint64_t stored = 0;    // bytes of data stored (without padding)
    bool sparse = false;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> segments; // sparse: (offset, length) in the real file
    std::uint64_t uid = 0, gid = 0;
    std::string uname, gname;
    std::vector<std::pair<std::string, std::string>> xattrs; // SCHILY.xattr.* and LIBARCHIVE.xattr.*
};

class TarParser {
public:
    explicit TarParser(InStream &in) : in_(in) {}
    // Next entry, or false at the end. The data is left in the stream:
    // read it with read_data() or leave it, next() skips what is left.
    bool next(TarItem &item);
    std::size_t read_data(void *buf, std::size_t n);
    std::uint64_t entries() const { return count_; }

private:
    bool block(std::uint8_t *b); // false at a clean end of stream
    std::string read_text(std::uint64_t size);
    void skip_rest();

    InStream &in_;
    std::uint64_t left_ = 0, pad_ = 0, count_ = 0;
    std::vector<std::pair<std::string, std::string>> global_;
};

// Writes sparse data out as a full file: holes become zeros.
// read(buf, n) gives the stored bytes in order.
template <class Read, class Write>
void expand_sparse(const TarItem &item, Read &&read, Write &&write);

bool tar_header_ok(const std::uint8_t *h); // checksum of a 512-byte block

struct TarHeaderIn {
    std::string path;            // '/'-separated; directories get a trailing '/'
    EntryType type = EntryType::File;
    std::uint64_t size = 0;
    Timestamp mtime;
    std::optional<Timestamp> atime, ctime;
    std::uint32_t mode = 0644;
    std::uint64_t uid = 0, gid = 0;
    std::string uname, gname, link;
};
// The header blocks for one entry (a pax header first when ustar is not enough).
std::vector<std::uint8_t> tar_header(const TarHeaderIn &h);

// ------------------------------------------------------------------ inline

template <class Read, class Write>
void expand_sparse(const TarItem &item, Read &&read, Write &&write)
{
    static const std::vector<std::uint8_t> zeros(1 << 16);
    std::vector<std::uint8_t> buf(1 << 20);
    std::uint64_t at = 0;
    auto hole = [&](std::uint64_t n) {
        while (n) {
            const std::size_t k = std::size_t(std::min<std::uint64_t>(n, zeros.size()));
            write(zeros.data(), k);
            n -= k;
        }
    };
    for (auto [off, len] : item.segments) {
        hole(off - at);
        std::uint64_t left = len;
        while (left) {
            const std::size_t k = std::size_t(std::min<std::uint64_t>(left, buf.size()));
            read(buf.data(), k);
            write(buf.data(), k);
            left -= k;
        }
        at = off + len;
    }
    hole(item.entry.size - at);
}

} // namespace raye::archive::detail
