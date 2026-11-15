// SPDX-License-Identifier: GPL-3.0-or-later
// What a format implements. One Driver per format, registered from
// src/formats/<name>/register.cpp.
#pragma once

#include <raye/archive/archive.h>

#include "context.h"

#include <algorithm>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace raye::archive::detail {

struct ProbeInput {
    const Source &source;
    std::uint64_t size;
    std::span<const std::uint8_t> head;  // first min(size, kProbeHead) bytes
    std::span<const std::uint8_t> tail;  // last min(size, kProbeTail) bytes
    std::string_view name;               // file name hint, may be empty
};
inline constexpr std::size_t kProbeHead = 1 << 20;
inline constexpr std::size_t kProbeTail = 128 << 10;

// Searches head for a signature after an executable stub (MZ or ELF).
// Returns the offset, or nullopt. Used by the self-extracting probes.
std::optional<std::uint64_t> find_after_stub(std::span<const std::uint8_t> head,
                                             std::span<const std::uint8_t> signature);
bool has_executable_stub(std::span<const std::uint8_t> head);
bool name_ends_with(std::string_view name, std::string_view suffix); // case-insensitive
// True if data holds sig at offset (sig may contain NULs: pass a sized view).
inline bool has_at(std::span<const std::uint8_t> data, std::size_t off, std::string_view sig)
{
    return off + sig.size() <= data.size() &&
           std::equal(sig.begin(), sig.end(), data.begin() + std::ptrdiff_t(off),
                      [](char a, std::uint8_t b) { return static_cast<std::uint8_t>(a) == b; });
}

// Receives decoded entries. All methods are thread-safe: a driver may
// decode independent entries on ctx.pool() at the same time.
class EntryHandler {
public:
    virtual ~EntryHandler() = default;
    // Should this index be produced at all? (solid formats still decode
    // skipped data, they just drop it).
    virtual bool wants(std::size_t index) const = 0;
    // Returns where to write the data, or nullptr to skip this entry.
    // For directories and links nothing is written: begin() creates them.
    virtual Sink *begin(const Entry &entry) = 0;
    // Data complete and checksum verified.
    virtual void end(const Entry &entry, Sink *sink) = 0;
    // Entry failed (checksum, password ...). The handler decides whether
    // to rethrow (extract) or record and go on (test).
    virtual void failed(const Entry &entry, Sink *sink, const Error &error) = 0;
};

class ReaderImpl {
public:
    virtual ~ReaderImpl() = default;
    virtual ArchiveInfo info() const = 0;
    // Entry::index must equal the position in the returned vector.
    virtual std::vector<Entry> list(Context &ctx) = 0;
    // indexes: sorted, unique. Must call handler.begin/end for each one
    // (or handler.failed). Verify CRCs/MACs before calling end().
    virtual void extract(const std::vector<std::size_t> &indexes, EntryHandler &handler, Context &ctx) = 0;
    // Raw copy of an entry's stored bytes, for writers that keep unchanged
    // entries without recompressing (ZIP). Optional.
    virtual bool copy_raw(std::size_t /*index*/, Sink & /*out*/, Context & /*ctx*/) { return false; }
};

struct OpenRequest {
    std::shared_ptr<Source> source;           // whole file (or concatenated split parts)
    Detection detection;                      // offset is where the archive starts
    std::vector<std::filesystem::path> volumes; // all volumes in order (RAR opens them itself)
    std::string name;                         // file name, for messages
};

// One line of what the new archive will contain, in order.
struct PlanItem {
    enum class Kind { Add, Keep } kind = Kind::Add;
    std::string archive_path;                 // normalized, '/' separated, no leading '/'
    std::filesystem::path disk;               // Add: file on disk (empty for a directory made up)
    Entry stat;                               // Add: type, size, times, mode, link target
    std::size_t keep_index = 0;               // Keep: index in the existing archive
};

class WriterImpl {
public:
    virtual ~WriterImpl() = default;
    // existing is set for add/update/sync/remove; out is a temp file that
    // replaces the archive once finish() returns.
    virtual void write(const std::vector<PlanItem> &plan, ReaderImpl *existing, Sink &out,
                       const WriteOptions &opts, Context &ctx) = 0;
};

class Driver {
public:
    virtual ~Driver() = default;
    virtual Format format() const = 0;
    virtual std::vector<std::string> extensions() const = 0; // ".zip", ".tar.gz" ...
    // Score how much the content looks like this format; nullopt = not at all.
    virtual std::optional<Detection> probe(const ProbeInput &in) const = 0;
    // Default: throws NotImplemented ("<format> reading is not ready yet").
    virtual std::unique_ptr<ReaderImpl> open(const OpenRequest &req, Context &ctx) const;
    virtual bool can_write() const { return false; }
    virtual std::unique_ptr<WriterImpl> writer() const;
};

// Common shape of a driver whose probe is a plain signature check.
class SimpleDriver : public Driver {
public:
    SimpleDriver(Format f, std::vector<std::string> ext) : f_(f), ext_(std::move(ext)) {}
    Format format() const override { return f_; }
    std::vector<std::string> extensions() const override { return ext_; }

private:
    Format f_;
    std::vector<std::string> ext_;
};

void register_driver(std::unique_ptr<Driver> driver);
const std::vector<std::unique_ptr<Driver>> &drivers();
const Driver *driver_for(Format f);

} // namespace raye::archive::detail
