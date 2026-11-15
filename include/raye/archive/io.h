// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace raye::archive {

// Random-access input. read_at must be safe to call from several threads
// at once (drivers decode independent entries in parallel).
class Source {
public:
    virtual ~Source() = default;
    virtual std::uint64_t size() const = 0;
    // Reads up to n bytes at offset; returns bytes read (short only at end).
    virtual std::size_t read_at(std::uint64_t offset, void *buf, std::size_t n) const = 0;
    virtual std::string name() const { return {}; }

    // Reads exactly n bytes or throws Truncated.
    void read_exact(std::uint64_t offset, void *buf, std::size_t n) const;
};

// Sequential output.
class Sink {
public:
    virtual ~Sink() = default;
    virtual void write(const void *data, std::size_t n) = 0;
    // Called once after the last write; a sink that is destroyed without
    // finish() throws its data away (temporary files are removed).
    virtual void finish() {}
    // Overwrites n bytes already written at offset (a header only known at
    // the end). Returns false when the sink cannot go back.
    virtual bool rewrite(std::uint64_t /*offset*/, const void * /*data*/, std::size_t /*n*/) { return false; }
};

// pread-backed file. Throws Io / NotFound.
std::unique_ptr<Source> open_file_source(const std::filesystem::path &path);
// Bytes held in memory (copied).
std::unique_ptr<Source> memory_source(std::vector<std::uint8_t> bytes, std::string name = {});
// Window [offset, offset+length) of another source (self-extracting archives).
std::unique_ptr<Source> sub_source(std::shared_ptr<Source> base, std::uint64_t offset, std::uint64_t length);
// Several files read back to back as one (name.7z.001, .002 ...; split ZIP .z01...zip).
std::unique_ptr<Source> concat_source(const std::vector<std::filesystem::path> &parts);

// Collects everything written (tests, small entries).
class MemorySink : public Sink {
public:
    void write(const void *data, std::size_t n) override;
    bool rewrite(std::uint64_t offset, const void *data, std::size_t n) override;
    std::vector<std::uint8_t> &bytes() { return bytes_; }

private:
    std::vector<std::uint8_t> bytes_;
};

// Throws everything away (archive test).
class NullSink : public Sink {
public:
    void write(const void *, std::size_t n) override { count_ += n; }
    std::uint64_t count() const { return count_; }

private:
    std::uint64_t count_ = 0;
};

// Writes to a temporary file next to path and renames it over path on
// finish(); never leaves a half-written file behind.
std::unique_ptr<Sink> atomic_file_sink(const std::filesystem::path &path, unsigned mode = 0644);

// Cuts the output into path.001, path.002 ... of volume_size bytes each.
// Formats with their own volume layout (ZIP split, 7z) can use it as is;
// the names follow the 7-Zip convention.
std::unique_ptr<Sink> volume_sink(const std::filesystem::path &path, std::uint64_t volume_size);

} // namespace raye::archive
