// SPDX-License-Identifier: GPL-3.0-or-later
#include "check.h"
#include "tree.h"

#include "formats/zip/zip.h"

#include <raye/archive/archive.h>

#include <fstream>
#include <random>
#include <unistd.h>

using namespace raye::archive;
namespace fs = std::filesystem;

static fs::path g_corpus;

static fs::path scratch(const std::string &tag)
{
    fs::path p = fs::temp_directory_path() / ("raye-zipw-" + tag + "-" + std::to_string(::getpid()));
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

static std::string roundtrip(const fs::path &arc, const fs::path &src, WriteOptions w, std::optional<std::string> pw = {})
{
    w.format = Format::Zip;
    create(arc, {InputItem{src, "in"}}, w);
    OpenOptions oo;
    oo.password = pw;
    auto a = Archive::open(arc, oo);
    if (!a.test().ok()) return "test failed";
    const fs::path out = arc.parent_path() / (arc.filename().string() + ".out");
    fs::remove_all(out);
    ExtractOptions eo;
    eo.password = pw;
    a.extract_all(out, eo);
    std::string h = check::tree_hash(out / "in");
    fs::remove_all(out);
    return h;
}

static void write_file(const fs::path &p, std::size_t size, unsigned seed, bool text)
{
    std::mt19937 rng(seed);
    std::ofstream f(p, std::ios::binary);
    std::string chunk;
    while (chunk.size() < size) {
        if (text) chunk += "row " + std::to_string(rng() % 5000) + " of the big table, value " + std::to_string(rng() % 97) + "\n";
        else chunk += char(rng());
    }
    f.write(chunk.data(), std::streamsize(size));
}

TEST(every_method_round_trips)
{
    const fs::path d = scratch("methods");
    const std::string want = check::tree_hash(g_corpus);
    for (Method m : {Method::Store, Method::Deflate, Method::Bzip2, Method::Lzma, Method::Zstd, Method::Xz}) {
        for (int level : {1, 9}) {
            WriteOptions w;
            w.method = m;
            w.level = level;
            const fs::path arc = d / (std::string(method_name(m)) + std::to_string(level) + ".zip");
            if (roundtrip(arc, g_corpus, w) != want) check::report(method_name(m), level, "round trip changed the files");
        }
    }
    fs::remove_all(d);
}

TEST(encryption_round_trips)
{
    const fs::path d = scratch("crypt");
    const std::string want = check::tree_hash(g_corpus);
    for (Encryption e : {Encryption::Aes128, Encryption::Aes192, Encryption::Aes256, Encryption::ZipCrypto}) {
        WriteOptions w;
        w.password = "s3cret é";
        w.encryption = e;
        const fs::path arc = d / ("e" + std::to_string(int(e)) + ".zip");
        CHECK_EQ(roundtrip(arc, g_corpus, w, std::string("s3cret é")), want);
        // Names are readable without the password, data is not.
        auto a = Archive::open(arc);
        CHECK(a.entries().size() > 10);
        CHECK(a.info().has_encrypted_entries);
        ExtractOptions bad;
        bad.password = "s3cret";
        CHECK_THROWS_CODE(a.extract_all(d / "bad", bad), ErrorCode::WrongPassword);
    }
    fs::remove_all(d);
}

TEST(big_files_are_streamed)
{
    const fs::path d = scratch("big");
    fs::create_directories(d / "src");
    write_file(d / "src" / "table.txt", 23 << 20, 1, true);
    write_file(d / "src" / "noise.bin", 9 << 20, 2, false);
    write_file(d / "src" / "small.txt", 1000, 3, true);
    const std::string want = check::tree_hash(d / "src");
    struct Case { Method m; std::optional<std::string> pw; Encryption e; };
    for (const Case &c : {Case{Method::Deflate, {}, Encryption::Default}, Case{Method::Zstd, {}, Encryption::Default},
                          Case{Method::Store, {}, Encryption::Default}, Case{Method::Deflate, "pw", Encryption::Aes256},
                          Case{Method::Bzip2, "pw", Encryption::ZipCrypto}}) {
        WriteOptions w;
        w.method = c.m;
        w.level = 5;
        w.password = c.pw;
        w.encryption = c.e;
        const fs::path arc = d / (std::string(method_name(c.m)) + (c.pw ? "-pw" : "") + ".zip");
        if (roundtrip(arc, d / "src", w, c.pw) != want) check::report(method_name(c.m), 0, "big file round trip failed");
        // Random data is stored, not inflated by a compressor.
        auto a = Archive::open(arc, OpenOptions{c.pw, {}, {}});
        for (auto &e : a.entries())
            if (e.path == "in/noise.bin") CHECK(e.method.rfind("Store", 0) == 0);
    }
    fs::remove_all(d);
}

TEST(forced_zip64_round_trips)
{
    const fs::path d = scratch("z64");
    detail::zip::g_force_zip64 = true;
    const std::string got = roundtrip(d / "a.zip", g_corpus, WriteOptions{});
    detail::zip::g_force_zip64 = false;
    CHECK_EQ(got, check::tree_hash(g_corpus));
    auto a = Archive::open(d / "a.zip");
    CHECK_EQ(a.info().detail, std::string("ZIP64"));
    fs::remove_all(d);
}

TEST(add_and_remove_keep_old_entries_as_stored)
{
    const fs::path d = scratch("edit");
    fs::create_directories(d / "one");
    fs::create_directories(d / "two");
    write_file(d / "one" / "a.txt", 5000, 4, true);
    write_file(d / "two" / "b.txt", 5000, 5, true);
    WriteOptions w;
    w.format = Format::Zip;
    w.password = "first";
    w.comment = "made by raye";
    create(d / "x.zip", {InputItem{d / "one", "one"}}, w);
    // Second file with another password: the first one is copied, not re-encrypted.
    WriteOptions w2;
    w2.password = "second";
    add(d / "x.zip", {InputItem{d / "two", "two"}}, w2);
    auto a = Archive::open(d / "x.zip");
    CHECK_EQ(a.entries().size(), std::size_t(4));
    CHECK_EQ(a.info().comment, std::string("made by raye"));
    MemorySink one, two;
    ExtractOptions p1, p2;
    p1.password = "first";
    p2.password = "second";
    for (auto &e : a.entries()) {
        if (e.path == "one/a.txt") a.extract_to(e.index, one, p1);
        if (e.path == "two/b.txt") a.extract_to(e.index, two, p2);
    }
    CHECK_EQ(one.bytes().size(), std::size_t(5000));
    CHECK_EQ(two.bytes().size(), std::size_t(5000));
    remove(d / "x.zip", {"one"}, WriteOptions{});
    auto b = Archive::open(d / "x.zip");
    CHECK_EQ(b.entries().size(), std::size_t(2));
    CHECK(b.test(p2).ok());
    fs::remove_all(d);
}

TEST(volumes_round_trip)
{
    const fs::path d = scratch("vol");
    WriteOptions w;
    w.format = Format::Zip;
    w.volume_size = 200 << 10;
    create(d / "v.zip", {InputItem{g_corpus, "in"}}, w);
    CHECK(fs::exists(d / "v.zip.002"));
    auto a = Archive::open(d / "v.zip.002");
    CHECK(a.test().ok());
    a.extract_all(d / "out");
    CHECK_EQ(check::tree_hash(d / "out" / "in"), check::tree_hash(g_corpus));
    fs::remove_all(d);
}

TEST(refuses_what_zip_cannot_hold)
{
    const fs::path d = scratch("refuse");
    WriteOptions w;
    w.format = Format::Zip;
    w.method = Method::Deflate64;
    CHECK_THROWS_CODE(create(d / "a.zip", {InputItem{g_corpus, "in"}}, w), ErrorCode::InvalidOption);
    w.method = Method::Default;
    w.password = "x";
    w.encrypt_names = true;
    CHECK_THROWS_CODE(create(d / "b.zip", {InputItem{g_corpus, "in"}}, w), ErrorCode::InvalidOption);
    CHECK(!fs::exists(d / "a.zip"));
    fs::remove_all(d);
}

int main(int argc, char **argv)
{
    if (argc < 2) { std::fprintf(stderr, "usage: test_zip_write CORPUS\n"); return 2; }
    g_corpus = argv[1];
    for (auto &c : check::cases()) {
        const int before = check::failures();
        try { c.fn(); } catch (const std::exception &e) { check::report(c.name, 0, std::string("threw: ") + e.what()); }
        std::printf("%s %s\n", check::failures() == before ? "ok  " : "FAIL", c.name);
    }
    return check::failures() ? 1 : 0;
}
