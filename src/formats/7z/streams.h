// SPDX-License-Identifier: GPL-3.0-or-later
// Decoding one 7z folder: a small graph of coders pulling from each other.
#pragma once

#include "sevenz.h"

#include <raye/archive/io.h>

#include <array>
#include <memory>
#include <span>
#include <string>

namespace raye::archive::detail {
class Context;
}

namespace raye::archive::detail::sevenz {

class Pull {
public:
    virtual ~Pull() = default;
    // Up to n bytes; 0 only at the end.
    virtual std::size_t read(std::uint8_t *buf, std::size_t n) = 0;
};

// Key cache shared by every folder of one archive: deriving a 7z key costs
// half a million SHA-256 rounds.
struct KeyCache;
std::shared_ptr<KeyCache> make_key_cache();

// Derives the AES-256 key the way 7z does (SHA-256 rounds over salt,
// UTF-16LE password and a counter). cycles_power 0x3F means no hashing.
std::array<std::uint8_t, 32> derive_key(const std::string &password, std::span<const std::uint8_t> salt,
                                        unsigned cycles_power);

struct FolderInput {
    const Source &source;
    std::uint64_t data_start;          // file offset of the first packed stream of this folder
    const StreamsInfo &si;
    std::size_t folder;
    const std::string *password;       // nullptr: none known
    KeyCache *keys;
    unsigned threads = 1;              // for an LZMA2 stream 7-Zip cut into pieces
};

// Returns the folder's main output, at most unpack_size() bytes.
std::unique_ptr<Pull> open_folder(const FolderInput &in);

// True if every coder of the folder is something we can decode.
std::string unsupported_coder(const Folder &f);

} // namespace raye::archive::detail::sevenz
