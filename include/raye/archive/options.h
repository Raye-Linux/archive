// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <raye/archive/entry.h>
#include <raye/archive/format.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace raye::archive {

// Pause / Resume / Cancel, shared between the UI thread and the workers.
class Control {
public:
    void pause();
    void resume();
    void cancel();
    bool paused() const;
    bool cancelled() const { return cancelled_.load(); }
    // Workers call this often: blocks while paused, throws Cancelled.
    void checkpoint() const;

private:
    mutable std::mutex m_;
    mutable std::condition_variable cv_;
    bool paused_ = false;
    std::atomic<bool> cancelled_{false};
};

struct Progress {
    std::uint64_t bytes_done = 0;   // unpacked bytes read or written so far
    std::uint64_t bytes_total = 0;  // 0 if unknown
    std::uint64_t files_done = 0;
    std::uint64_t files_total = 0;
    std::string current;            // archive path being processed
    double bytes_per_second = 0;    // smoothed over the last seconds
};

struct PasswordRequest {
    std::string archive;            // archive file name
    std::string entry;              // empty when the headers themselves are encrypted
    int attempt = 1;                // 2, 3 ... after a wrong password
};

enum class ConflictChoice { Replace, Skip, KeepBoth, ReplaceAll, SkipAll, KeepBothAll, Cancel };

struct Conflict {
    std::string destination;        // file that already exists
    const Entry *entry = nullptr;   // what would replace it
};

struct Callbacks {
    // Called at most ~20 times a second, from any thread (serialized).
    std::function<void(const Progress &)> progress;
    // Return nullopt to give up (PasswordRequired is thrown).
    std::function<std::optional<std::string>(const PasswordRequest &)> password;
    // Without a callback the extract options decide.
    std::function<ConflictChoice(const Conflict &)> conflict;
    Control *control = nullptr;
};

// What extraction refuses. Defaults are safe; loosen only for trusted input.
struct SafetyPolicy {
    bool allow_absolute = false;       // strip and refuse otherwise
    bool allow_dotdot = false;
    bool allow_links_outside = false;  // symlink or hard link resolving out of the destination
    bool create_symlinks = true;       // false: skip links
    bool keep_setuid = false;
    bool refuse_windows_reserved = true; // CON, NUL, COM1, LPT1 ... as a path component
    // Bomb guard: fail once output > max_ratio * input after the first ratio_grace bytes.
    double max_ratio = 2000.0;
    std::uint64_t ratio_grace = 256ull << 20;
    std::uint64_t max_total_size = 0;  // 0 = no fixed limit
    std::uint64_t max_entries = 10'000'000;
    bool check_free_space = true;      // refuse when the declared sizes do not fit
};

enum class OverwriteMode { Ask, Replace, Skip, KeepBoth, Fail };

struct ExtractOptions {
    OverwriteMode overwrite = OverwriteMode::Ask; // Ask falls back to Fail without a callback
    bool restore_mtime = true;
    bool restore_permissions = true;
    bool flat = false;                 // ignore folders inside the archive
    int threads = 0;                   // 0 = one per core
    std::optional<std::string> password;
    SafetyPolicy safety;
};

enum class Method {
    Default, Store, Deflate, Deflate64, Bzip2, Lzma, Lzma2, Ppmd, Zstd, Xz, Lz4, Brotli, Lzip,
};
const char *method_name(Method m) noexcept;
std::optional<Method> method_from_name(std::string_view s) noexcept;

enum class Encryption { Default, ZipCrypto, Aes128, Aes192, Aes256 };

struct WriteOptions {
    Format format = Format::SevenZip;
    Method method = Method::Default;   // Default: best for the format and level
    int level = 5;                     // 0 (store) .. 9 (ultra)
    std::uint64_t dictionary = 0;      // bytes, 0 = from level
    int word_size = 0;                 // fast bytes / match length, 0 = from level
    bool solid = true;                 // 7z only
    std::uint64_t solid_block_size = 0;      // 0 = from level
    std::uint64_t solid_files_per_block = 0; // 0 = no limit
    int threads = 0;                   // 0 = one per core
    std::uint64_t volume_size = 0;     // 0 = single file
    std::optional<std::string> password;
    Encryption encryption = Encryption::Default;
    bool encrypt_names = false;        // 7z: encrypt headers too
    bool store_mtime = true, store_atime = false, store_ctime = false;
    bool store_links = true;           // false: follow symlinks and store targets
    bool filters = true;               // BCJ/ARM/delta when content looks like it helps
    std::vector<std::string> exclude;  // glob patterns on archive paths ("*.tmp", "build/**")
    std::string comment;
};

} // namespace raye::archive
