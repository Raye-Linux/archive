// SPDX-License-Identifier: GPL-3.0-or-later
// Streaming coders over the system libraries (zlib, libbz2, liblzma, libzstd,
// liblz4, libbrotli). Format code drives them through one interface.
#pragma once

#include <raye/archive/io.h>

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace raye::archive::detail {

class Context;
class SourceReader;

enum class Codec {
    Deflate,   // raw (ZIP, 7z)
    Zlib,
    Gzip,      // one member; Gzip decoder also follows concatenated members
    Bzip2,
    Xz,        // .xz container, multithreaded when params.threads > 1
    LzmaAlone, // legacy .lzma
    Lzma1Raw,  // 7z/ZIP LZMA: props = 5 bytes (lc/lp/pb + dict)
    Lzma2Raw,  // 7z LZMA2: props = 1 byte dict code
    Zstd,      // frames, multithreaded encoder
    Lz4Frame,
    Brotli,
};

struct CodecParams {
    int level = 6;                         // codec's own scale is mapped from 0..9
    std::uint64_t dictionary = 0;          // 0 = from level
    int word_size = 0;                     // nice_len / fast bytes
    int threads = 1;
    std::vector<std::uint8_t> props;       // raw LZMA properties (decoder input, encoder output)
    std::uint64_t expected_size = 0;       // hint, 0 = unknown
};

struct CodeStep {
    std::size_t consumed = 0;
    std::size_t produced = 0;
    bool done = false;                     // end of stream reached
};

class Coder {
public:
    virtual ~Coder() = default;
    // finish: no more input after this call (encoders flush, decoders know
    // that a missing end marker is truncation).
    virtual CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) = 0;
};

std::unique_ptr<Coder> make_decoder(Codec c, const CodecParams &p = {});
// After construction, params.props holds what the decoder will need (LZMA raw).
std::unique_ptr<Coder> make_encoder(Codec c, CodecParams &p);

// Pumps exactly packed_size bytes from in through dec into out.
// Calls ctx.checkpoint() and ctx.add_bytes() per block when ctx is given.
// Throws Corrupt/Truncated; returns bytes written.
std::uint64_t decode_all(Coder &dec, SourceReader &in, std::uint64_t packed_size, Sink &out,
                         Context *ctx = nullptr, std::uint64_t max_out = UINT64_MAX);
std::vector<std::uint8_t> decode_buffer(Codec c, std::span<const std::uint8_t> in, std::size_t max_out,
                                        const CodecParams &p = {});
std::vector<std::uint8_t> encode_buffer(Codec c, std::span<const std::uint8_t> in, CodecParams &p);

} // namespace raye::archive::detail
