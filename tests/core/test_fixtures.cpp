// SPDX-License-Identifier: GPL-3.0-or-later
// Every archive in tests/fixtures/MANIFEST: detected right, and once its
// reader exists, extracted to exactly the tree it was made from.
#include "../check.h"
#include "../tree.h"

#include <raye/archive/archive.h>

#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>
#include <unistd.h>

using namespace raye::archive;
namespace fs = std::filesystem;

static fs::path g_dir;

static std::set<std::string> expected_ready()
{
    std::set<std::string> s;
    if (const char *e = std::getenv("RAYE_ARCHIVE_EXPECT_READY")) {
        std::stringstream ss(e);
        for (std::string t; std::getline(ss, t, ',');) s.insert(t);
    }
    return s;
}

TEST(manifest_fixtures)
{
    std::ifstream m(g_dir / "MANIFEST");
    CHECK(m.good());
    const auto ready = expected_ready();
    int total = 0, pending = 0;
    for (std::string line; std::getline(m, line);) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ls(line);
        std::string file, fmt, hash, password;
        ls >> file >> fmt >> hash >> password;
        ++total;
        const fs::path path = g_dir / file;
        const Detection d = detect(path);
        if (format_name(d.format) != fmt) {
            check::report(file.c_str(), 0, std::string("detected as ") + format_name(d.format) + ", expected " + fmt);
            continue;
        }
        const fs::path out = fs::temp_directory_path() / ("raye-fixture-" + std::to_string(::getpid()));
        fs::remove_all(out);
        try {
            OpenOptions oo;
            if (!password.empty()) oo.password = password;
            auto a = Archive::open(path, oo);
            ExtractOptions eo;
            eo.password = oo.password;
            a.extract_all(out, eo);
            if (hash != "-") {
                const std::string got = check::tree_hash(out);
                if (got != hash) check::report(file.c_str(), 0, "extracted tree differs: " + got);
            }
            std::printf("  read  %s\n", file.c_str());
        } catch (const Error &e) {
            if (e.code() == ErrorCode::NotImplemented && !ready.count(fmt)) {
                ++pending;
                std::printf("  wait  %s (%s)\n", file.c_str(), e.what());
            } else {
                check::report(file.c_str(), 0, e.what());
            }
        }
        fs::remove_all(out);
    }
    std::printf("  %d fixtures, %d waiting for their reader\n", total, pending);
    CHECK(total > 0);
}

TEST(detection_ignores_the_name)
{
    // Same bytes, no extension or a lying one: the content decides.
    std::ifstream m(g_dir / "MANIFEST");
    for (std::string line; std::getline(m, line);) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ls(line);
        std::string file, fmt;
        ls >> file >> fmt;
        if (fmt == "br" || fmt == "lzma") continue; // no magic: name-only by design
        auto src = open_file_source(g_dir / file);
        const Detection plain = detect(*src, "");
        const Detection lying = detect(*src, "photo.jpg");
        if (format_name(plain.format) != fmt || format_name(lying.format) != fmt)
            check::report(file.c_str(), 0, "detection depends on the name");
    }
}

int main(int argc, char **argv)
{
    g_dir = argc > 1 ? argv[1] : "tests/fixtures";
    for (auto &c : check::cases()) {
        const int before = check::failures();
        try { c.fn(); } catch (const std::exception &e) { check::report(c.name, 0, e.what()); }
        std::printf("%s %s\n", check::failures() == before ? "ok  " : "FAIL", c.name);
    }
    return check::failures() ? 1 : 0;
}
