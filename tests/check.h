// SPDX-License-Identifier: GPL-3.0-or-later
// Small test runner: TEST(name) { CHECK(...); }, one binary per file.
#pragma once

#include <raye/archive/error.h>

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace check {

struct Case { const char *name; std::function<void()> fn; };
inline std::vector<Case> &cases() { static std::vector<Case> c; return c; }
inline int &failures() { static int f = 0; return f; }

struct Reg {
    Reg(const char *n, std::function<void()> f) { cases().push_back({n, std::move(f)}); }
};

inline void report(const char *file, int line, const std::string &what)
{
    std::fprintf(stderr, "%s:%d: %s\n", file, line, what.c_str());
    ++failures();
}

} // namespace check

#define TEST(name) \
    static void name(); \
    static check::Reg reg_##name(#name, name); \
    static void name()

#define CHECK(cond) \
    do { if (!(cond)) check::report(__FILE__, __LINE__, "CHECK(" #cond ") failed"); } while (0)

#define CHECK_EQ(a, b) \
    do { \
        const auto &va_ = (a); const auto &vb_ = (b); \
        if (!(va_ == vb_)) check::report(__FILE__, __LINE__, "CHECK_EQ(" #a ", " #b ") failed"); \
    } while (0)

// Expects a raye::archive::Error with this code.
#define CHECK_THROWS_CODE(expr, ecode) \
    do { \
        bool thrown_ = false; \
        try { expr; } catch (const raye::archive::Error &e_) { \
            thrown_ = true; \
            if (e_.code() != (ecode)) check::report(__FILE__, __LINE__, std::string("wrong error: ") + e_.what()); \
        } \
        if (!thrown_) check::report(__FILE__, __LINE__, "expected an error from " #expr); \
    } while (0)

#define CHECK_MAIN() \
    int main() \
    { \
        for (auto &c : check::cases()) { \
            const int before = check::failures(); \
            try { c.fn(); } catch (const std::exception &e) { check::report(c.name, 0, std::string("threw: ") + e.what()); } \
            std::printf("%s %s\n", check::failures() == before ? "ok  " : "FAIL", c.name); \
        } \
        return check::failures() ? 1 : 0; \
    }
