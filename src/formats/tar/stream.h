// SPDX-License-Identifier: GPL-3.0-or-later
// Pull streams over a compressed source, and compressing sinks for writing.
// The tar reader and the single-file readers (.gz, .xz ...) both use them.
#pragma once

#include <raye/archive/format.h>
#include <raye/archive/io.h>
#include <raye/archive/options.h>

#include <cstdint>
#include <memory>
#include <string>

namespace raye::archive::detail {

class Context;

class InStream {
public:
    virtual ~InStream() = default;
    // Up to n bytes; 0 only at the end of the data.
    virtual std::size_t read(void *buf, std::size_t n) = 0;
    void read_exact(void *buf, std::size_t n);
    // Reads up to n bytes and throws them away; returns how many were there.
    std::uint64_t skip(std::uint64_t n);
    // Plain tar on a file seeks instead of reading.
    virtual bool can_seek() const { return false; }
    std::uint64_t pos() const { return pos_; }

protected:
    std::uint64_t pos_ = 0; // bytes handed out so far
    virtual std::uint64_t skip_impl(std::uint64_t n);
};

// What a gzip header said about the file it holds.
struct StreamMeta {
    std::string name;           // gzip FNAME
    std::int64_t mtime = 0;     // gzip MTIME, 0 = unset
    std::uint64_t size = 0;     // from a trailer or frame header, if any
    bool size_known = false;
};

bool is_stream_format(Format f);
// Opens [start, source end) as a stream of format f. Plain bytes for Tar.
// threads: decoders that can use several (xz, bzip2) take that many.
std::unique_ptr<InStream> open_stream(Format f, const Source &src, std::uint64_t start, int threads,
                                      Context *ctx = nullptr);
// bzip2 split at block boundaries and decoded on several threads; falls
// back to one thread for small files or when the split looks wrong.
std::unique_ptr<InStream> open_bzip2_parallel(const Source &src, std::uint64_t start, int threads);
std::unique_ptr<InStream> open_bzip2_serial(const Source &src, std::uint64_t start);

// Cheap look at the header/trailer of a stream, without decoding it.
StreamMeta stream_meta(Format f, const Source &src, std::uint64_t start);

// Compresses into out (which is not finished by finish()).
// name/mtime go into the gzip header when given.
std::unique_ptr<Sink> compress_sink(Format f, Sink &out, const WriteOptions &opts, Context &ctx,
                                    const std::string &name = {}, std::int64_t mtime = 0);

// Bytes of memory the parallel encoders may use together.
std::uint64_t memory_budget();
// Most a decoder may allocate (enough for any real xz/lzma dictionary).
std::uint64_t decode_memlimit();

} // namespace raye::archive::detail
