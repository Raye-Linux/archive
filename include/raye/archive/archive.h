// SPDX-License-Identifier: GPL-3.0-or-later
// Raye archive engine, public API. One include for everything.
#pragma once

#include <raye/archive/entry.h>
#include <raye/archive/error.h>
#include <raye/archive/format.h>
#include <raye/archive/io.h>
#include <raye/archive/options.h>

#include <filesystem>
#include <memory>
#include <vector>

namespace raye::archive {

namespace detail { class ReaderImpl; }

struct OpenOptions {
    std::optional<std::string> password;
    std::optional<Format> force_format; // skip detection
    Callbacks callbacks;                // password asked here when headers are encrypted
};

struct ArchiveInfo {
    Format format = Format::Unknown;
    std::string detail;                 // "RAR 5.0, solid", "7z LZMA2:26 BCJ"
    std::uint64_t offset = 0;           // > 0 for self-extracting archives
    bool self_extracting = false;
    bool solid = false;
    bool encrypted_headers = false;
    bool has_encrypted_entries = false;
    std::size_t volume_count = 1;
    std::string comment;
};

struct TestResult {
    std::size_t entries_ok = 0;
    std::vector<std::pair<std::string, Error>> failures; // entry path, what went wrong
    bool ok() const { return failures.empty(); }
};

class Archive {
public:
    // Opens any volume of an archive; detection is by content.
    static Archive open(const std::filesystem::path &path, const OpenOptions &opts = {});
    // Opens from memory or any Source (no volumes).
    static Archive open(std::shared_ptr<Source> source, const OpenOptions &opts = {});

    Archive(Archive &&) noexcept;
    Archive &operator=(Archive &&) noexcept;
    ~Archive();

    const ArchiveInfo &info() const;
    // Every entry, read once and cached.
    const std::vector<Entry> &entries();

    // Extracts everything under destination (created if missing).
    void extract_all(const std::filesystem::path &destination, const ExtractOptions &opts = {},
                     const Callbacks &cb = {});
    // Extracts only the given indexes (folders do not pull their children in).
    void extract(const std::vector<std::size_t> &indexes, const std::filesystem::path &destination,
                 const ExtractOptions &opts = {}, const Callbacks &cb = {});
    // Streams one file entry into sink (no disk, no safety checks needed).
    void extract_to(std::size_t index, Sink &sink, const ExtractOptions &opts = {}, const Callbacks &cb = {});
    // Decodes everything and checks checksums, writes nothing.
    TestResult test(const ExtractOptions &opts = {}, const Callbacks &cb = {});

    detail::ReaderImpl &impl();
    struct State; // opaque

private:
    Archive();
    std::unique_ptr<State> s_;
};

// One file or folder to put in an archive.
struct InputItem {
    std::filesystem::path source;   // on disk; a folder adds its whole tree
    std::string archive_path;       // empty = file name of source
};

// Creates a new archive (replaces an existing file atomically).
void create(const std::filesystem::path &archive, const std::vector<InputItem> &items,
            const WriteOptions &opts, const Callbacks &cb = {});
// Adds items, replacing entries with the same path.
void add(const std::filesystem::path &archive, const std::vector<InputItem> &items,
         const WriteOptions &opts, const Callbacks &cb = {});
// Adds items that are new or newer (mtime/size) than their entry.
void update(const std::filesystem::path &archive, const std::vector<InputItem> &items,
            const WriteOptions &opts, const Callbacks &cb = {});
// Like update, and removes entries whose file no longer exists under the items.
void sync(const std::filesystem::path &archive, const std::vector<InputItem> &items,
          const WriteOptions &opts, const Callbacks &cb = {});
// Removes entries matching the paths (a folder path removes its tree).
void remove(const std::filesystem::path &archive, const std::vector<std::string> &paths,
            const WriteOptions &opts, const Callbacks &cb = {});

// Library version, "0.5~beta1".
const char *version() noexcept;

} // namespace raye::archive
