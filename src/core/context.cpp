// SPDX-License-Identifier: GPL-3.0-or-later
#include "context.h"

#include <raye/archive/error.h>

namespace raye::archive {

void Control::pause()
{
    std::lock_guard l(m_);
    paused_ = true;
}

void Control::resume()
{
    {
        std::lock_guard l(m_);
        paused_ = false;
    }
    cv_.notify_all();
}

void Control::cancel()
{
    cancelled_ = true;
    cv_.notify_all();
}

bool Control::paused() const
{
    std::lock_guard l(m_);
    return paused_;
}

void Control::checkpoint() const
{
    if (cancelled_) fail(ErrorCode::Cancelled, "cancelled");
    std::unique_lock l(m_);
    cv_.wait(l, [this] { return !paused_ || cancelled_.load(); });
    if (cancelled_) fail(ErrorCode::Cancelled, "cancelled");
}

namespace detail {

Context::Context(const Callbacks &cb, int threads, std::optional<std::string> password, std::string name)
    : cb_(cb), threads_(int(default_threads(threads))), given_password_(std::move(password)), name_(std::move(name))
{
    start_ = last_report_ = rate_time_ = std::chrono::steady_clock::now();
}

void Context::checkpoint() const
{
    if (cb_.control) cb_.control->checkpoint();
}

std::string Context::password(const std::string &entry, int attempt)
{
    std::lock_guard l(m_);
    if (attempt <= 1) {
        if (good_password_) return *good_password_;
        if (given_password_) return *given_password_;
    }
    if (!cb_.password)
        fail(attempt <= 1 ? ErrorCode::PasswordRequired : ErrorCode::WrongPassword,
             attempt <= 1 ? "this archive needs a password" : "the password is wrong", entry);
    // Attempt numbering seen by the user starts after the given password.
    const int asked = attempt - (given_password_ ? 1 : 0);
    auto pw = cb_.password(PasswordRequest{name_, entry, asked < 1 ? 1 : asked});
    if (!pw) fail(attempt <= 1 ? ErrorCode::PasswordRequired : ErrorCode::WrongPassword, "no password given", entry);
    return *pw;
}

void Context::password_ok(const std::string &pw)
{
    std::lock_guard l(m_);
    good_password_ = pw;
}

ThreadPool &Context::pool()
{
    std::lock_guard l(m_);
    if (!pool_) pool_ = std::make_unique<ThreadPool>(unsigned(threads_));
    return *pool_;
}

void Context::set_totals(std::uint64_t bytes, std::uint64_t files)
{
    std::lock_guard l(m_);
    p_.bytes_total = bytes;
    p_.files_total = files;
    report_locked(true);
}

void Context::add_bytes(std::uint64_t n)
{
    std::lock_guard l(m_);
    p_.bytes_done += n;
    report_locked(false);
}

void Context::file_started(const std::string &path)
{
    std::lock_guard l(m_);
    p_.current = path;
    report_locked(false);
}

void Context::file_done()
{
    std::lock_guard l(m_);
    ++p_.files_done;
    report_locked(p_.files_done == p_.files_total);
}

Progress Context::progress() const
{
    std::lock_guard l(m_);
    return p_;
}

void Context::report_locked(bool force)
{
    if (!cb_.progress) return;
    const auto now = std::chrono::steady_clock::now();
    const auto since = now - last_report_;
    if (!force && since < std::chrono::milliseconds(50)) return;
    const double dt = std::chrono::duration<double>(now - rate_time_).count();
    if (dt >= 0.5) {
        const double inst = double(p_.bytes_done - rate_bytes_) / dt;
        p_.bytes_per_second = p_.bytes_per_second == 0 ? inst : 0.7 * p_.bytes_per_second + 0.3 * inst;
        rate_time_ = now;
        rate_bytes_ = p_.bytes_done;
    }
    last_report_ = now;
    cb_.progress(p_);
}

} // namespace detail
} // namespace raye::archive
