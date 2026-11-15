// SPDX-License-Identifier: GPL-3.0-or-later
// Writing entries to disk without ever leaving the destination folder.
#pragma once

#include <raye/archive/archive.h>

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace raye::archive::detail {

class Context;

// Turns a stored name into a clean relative path ("a/b/c"), or throws
// UnsafePath. Backslashes count as separators, "." and empty parts go away.
std::string sanitize_path(std::string_view stored, const SafetyPolicy &policy);
// CON, PRN, AUX, NUL, COM0-9, LPT0-9 (with or without extension, any case).
bool is_windows_reserved(std::string_view component);
// Would a link stored at link_path with this target land outside the root?
bool link_escapes(std::string_view link_path, std::string_view target);

// Counts output and stops decompression bombs.
class BombGuard {
public:
    BombGuard(const SafetyPolicy &p, std::uint64_t input_size) : p_(p), in_(input_size) {}
    void add(std::uint64_t n);

private:
    const SafetyPolicy &p_;
    std::uint64_t in_, out_ = 0;
    std::mutex m_;
};

class Extractor {
public:
    Extractor(const std::filesystem::path &dest, const ExtractOptions &opts, const Callbacks &cb, Context &ctx,
              std::uint64_t archive_size);
    ~Extractor();

    // Returns a sink for a file entry, or nullptr if it is skipped (conflict
    // resolved as Skip). Directories and links are made right away.
    std::unique_ptr<Sink> begin(const Entry &e);
    // Puts the data in place (rename over / keep both), sets mode and times.
    void commit(const Entry &e, std::unique_ptr<Sink> sink);
    // Folder times last, deepest first, once every file is in.
    void finish();
    // Refuses up front when the declared sizes do not fit on the disk.
    void check_space(std::uint64_t declared_total);

private:
    struct Impl;
    std::unique_ptr<Impl> d_;
};

} // namespace raye::archive::detail
