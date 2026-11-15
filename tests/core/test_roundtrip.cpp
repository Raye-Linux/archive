// SPDX-License-Identifier: GPL-3.0-or-later
// For every format that can be written: create from the corpus, test,
// extract, and compare the tree. Formats still without a writer are listed.
#include "../check.h"
#include "../tree.h"

#include <raye/archive/archive.h>

#include <unistd.h>

using namespace raye::archive;
namespace fs = std::filesystem;

static fs::path g_corpus;

TEST(roundtrip_every_writable_format)
{
    const std::string want = check::tree_hash(g_corpus);
    const fs::path work = fs::temp_directory_path() / ("raye-roundtrip-" + std::to_string(::getpid()));
    for (Format f : {Format::SevenZip, Format::Zip, Format::Tar, Format::Gzip, Format::Xz, Format::Zstd}) {
        if (!format_can_write(f)) {
            std::printf("  wait  %s has no writer yet\n", format_name(f));
            continue;
        }
        fs::remove_all(work);
        fs::create_directories(work / "out");
        WriteOptions w;
        w.format = f;
        w.level = 3;
        const fs::path arc = work / (std::string("corpus.") + format_name(f));
        // The corpus folder goes in under its own name, so compare its copy.
        create(arc, {InputItem{g_corpus, "corpus"}}, w);
        auto a = Archive::open(arc);
        auto r = a.test();
        if (!r.ok()) check::report(format_name(f), 0, "test failed after create");
        a.extract_all(work / "out");
        if (check::tree_hash(work / "out" / "corpus") != want) check::report(format_name(f), 0, "round trip changed the files");
        std::printf("  ok    %s %ju bytes\n", format_name(f), std::uintmax_t(fs::file_size(arc)));
    }
    fs::remove_all(work);
}

int main(int argc, char **argv)
{
    if (argc < 2) { std::fprintf(stderr, "usage: test_roundtrip CORPUS\n"); return 2; }
    g_corpus = argv[1];
    for (auto &c : check::cases()) {
        const int before = check::failures();
        try { c.fn(); } catch (const std::exception &e) { check::report(c.name, 0, e.what()); }
        std::printf("%s %s\n", check::failures() == before ? "ok  " : "FAIL", c.name);
    }
    return check::failures() ? 1 : 0;
}
