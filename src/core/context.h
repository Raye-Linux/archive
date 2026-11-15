// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <raye/archive/options.h>

#include "threadpool.h"

#include <chrono>
#include <mutex>
#include <optional>
#include <string>

namespace raye::archive::detail {

// Everything a driver needs from the caller during one operation.
class Context {
public:
    Context(const Callbacks &cb, int threads, std::optional<std::string> password, std::string archive_name);

    // Blocks while paused, throws Cancelled. Call between blocks.
    void checkpoint() const;

    // Password to try. First call returns the one given in the options, if
    // any; after a wrong one, call with attempt+1 to ask the user again.
    // Throws PasswordRequired when nobody can answer.
    std::string password(const std::string &entry, int attempt);
    // Remember the password that worked, so later entries try it first.
    void password_ok(const std::string &pw);

    // Progress, thread-safe. add_bytes is cheap: call it per block.
    void set_totals(std::uint64_t bytes, std::uint64_t files);
    void add_bytes(std::uint64_t n);
    void file_started(const std::string &path);
    void file_done();
    Progress progress() const;

    ThreadPool &pool();
    int threads() const { return threads_; }
    const Callbacks &callbacks() const { return cb_; }
    const std::string &archive_name() const { return name_; }

private:
    void report_locked(bool force);

    const Callbacks &cb_;
    int threads_;
    std::optional<std::string> given_password_;
    std::optional<std::string> good_password_;
    std::string name_;
    std::unique_ptr<ThreadPool> pool_;
    mutable std::mutex m_;
    Progress p_;
    std::chrono::steady_clock::time_point start_, last_report_, rate_time_;
    std::uint64_t rate_bytes_ = 0;
};

} // namespace raye::archive::detail
