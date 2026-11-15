// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../check.h"
#include "../../tree.h"

#include <raye/archive/archive.h>

#include "core/bytes.h"
#include "core/codec.h"
#include "formats/tar/tar.h"

#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <random>
#include <sys/stat.h>
#include <unistd.h>

using namespace raye::archive;
using namespace raye::archive::detail;
namespace fs = std::filesystem;

namespace {

fs::path g_fixtures;

fs::path temp_dir(const std::string &tag)
{
    fs::path p = fs::temp_directory_path() / ("raye-tar-" + std::to_string(::getpid()) + "-" + tag);
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

std::vector<std::uint8_t> text_bytes(std::size_t n, unsigned seed)
{
    std::mt19937 r(seed);
    static const char *words[] = {"archive", "raye", "window", "folder", "tar", "stream", "block", "zero", "the", "of"};
    std::vector<std::uint8_t> v;
    v.reserve(n);
    while (v.size() < n) {
        const char *w = words[r() % 10];
        v.insert(v.end(), w, w + std::strlen(w));
        v.push_back(r() % 9 ? ' ' : '\n');
    }
    v.resize(n);
    return v;
}

void put(const fs::path &p, const std::vector<std::uint8_t> &d)
{
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char *>(d.data()), std::streamsize(d.size()));
}

// A tree with the awkward cases: long names, unicode, empty things, links, old dates.
fs::path make_tree(const fs::path &root)
{
    const fs::path t = root / "tree";
    put(t / "text.txt", text_bytes(3 << 20, 1));
    std::vector<std::uint8_t> rnd(700000);
    std::mt19937 r(7);
    for (auto &b : rnd) b = std::uint8_t(r());
    put(t / "bin/random.bin", rnd);
    put(t / "empty", {});
    fs::create_directories(t / "empty-dir");
    const std::string long_dir(120, 'd'), long_file(150, 'f');
    put(t / long_dir / long_file, text_bytes(1000, 2));
    put(t / "été/日本語.txt", text_bytes(100, 3));
    fs::create_symlink("text.txt", t / "link");
    fs::create_symlink(std::string(130, 'x'), t / "long-link");
    fs::create_hard_link(t / "text.txt", t / "hard.txt");
    put(t / "old.txt", text_bytes(10, 4));
    struct timespec ts[2] = {{-86400 * 365, 0}, {-86400 * 365, 0}};
    utimensat(AT_FDCWD, (t / "old.txt").c_str(), ts, 0);
    return t;
}

std::string extract_hash(const fs::path &arc, const fs::path &out)
{
    auto a = Archive::open(arc);
    auto r = a.test();
    if (!r.ok()) check::report(arc.c_str(), 0, "test failed: " + std::string(r.failures[0].second.what()));
    ExtractOptions eo;
    eo.overwrite = OverwriteMode::Replace;
    a.extract_all(out, eo);
    return check::tree_hash(out / "tree");
}

const Format kWritable[] = {Format::Tar, Format::Gzip, Format::Bzip2, Format::Xz, Format::Zstd,
                            Format::Lz4, Format::Lzip, Format::Lzma, Format::Brotli};

std::string ext(Format f) { return f == Format::Tar ? ".tar" : std::string(".tar.") + format_name(f); }

} // namespace

TEST(every_stream_format_round_trips)
{
    const fs::path w = temp_dir("rt");
    const fs::path tree = make_tree(w);
    const std::string want = check::tree_hash(tree);
    for (Format f : kWritable) {
        WriteOptions o;
        o.format = f;
        o.level = 3;
        const fs::path arc = w / ("a" + ext(f));
        create(arc, {InputItem{tree, "tree"}}, o);
        const fs::path out = w / ("out-" + std::string(format_name(f)));
        if (extract_hash(arc, out) != want) check::report(format_name(f), 0, "round trip changed the files");
        // Old mtime and the hard link survive.
        struct stat a{}, b{};
        stat((out / "tree/old.txt").c_str(), &a);
        if (a.st_mtime != -86400 * 365) check::report(format_name(f), 0, "negative mtime lost");
        stat((out / "tree/text.txt").c_str(), &a);
        stat((out / "tree/hard.txt").c_str(), &b);
        if (a.st_ino != b.st_ino) check::report(format_name(f), 0, "hard link became a copy");
    }
    fs::remove_all(w);
}

TEST(one_file_makes_a_bare_stream)
{
    const fs::path w = temp_dir("bare");
    const auto data = text_bytes(200000, 9);
    put(w / "notes.txt", data);
    for (Format f : {Format::Gzip, Format::Xz, Format::Zstd, Format::Bzip2, Format::Lzip}) {
        WriteOptions o;
        o.format = f;
        const fs::path arc = w / (std::string("notes.txt.") + format_name(f));
        create(arc, {InputItem{w / "notes.txt", "notes.txt"}}, o);
        auto a = Archive::open(arc);
        CHECK_EQ(a.entries().size(), std::size_t(1));
        CHECK_EQ(a.entries()[0].path, std::string("notes.txt"));
        MemorySink m;
        a.extract_to(0, m);
        CHECK(m.bytes() == data);
    }
    fs::remove_all(w);
}

TEST(parallel_gzip_is_one_valid_member)
{
    // Several 1 MiB blocks joined: zlib must read it as a single gzip stream.
    const fs::path w = temp_dir("pgz");
    const auto data = text_bytes(9 << 20, 5);
    put(w / "big", data);
    WriteOptions o;
    o.format = Format::Gzip;
    o.level = 6;
    o.threads = 8;
    create(w / "big.gz", {InputItem{w / "big", "big"}}, o);
    std::ifstream in(w / "big.gz", std::ios::binary);
    std::vector<std::uint8_t> gz((std::istreambuf_iterator<char>(in)), {});
    auto back = decode_buffer(Codec::Gzip, gz, data.size() + 1);
    CHECK(back == data);
    // Exactly one member: the trailer size matches the whole input.
    CHECK_EQ(le32(&gz[gz.size() - 4]), std::uint32_t(data.size()));
    fs::remove_all(w);
}

TEST(parallel_bzip2_matches_serial)
{
    // One bzip2 stream with many blocks, made by libbz2 itself.
    const fs::path w = temp_dir("pbz");
    std::vector<std::uint8_t> data(8 << 20);
    std::mt19937 r(3);
    for (auto &b : data) b = std::uint8_t('A' + r() % 40); // compresses to well over 4 MiB
    CodecParams p;
    p.level = 9;
    auto bz = encode_buffer(Codec::Bzip2, data, p);
    CHECK(bz.size() > (4u << 20)); // big enough for the parallel path
    put(w / "one.bz2", bz);
    for (int threads : {1, 8}) {
        auto a = Archive::open(w / "one.bz2");
        MemorySink m;
        ExtractOptions eo;
        eo.threads = threads;
        a.extract_to(0, m, eo);
        CHECK(m.bytes() == data);
    }
    // A flipped bit inside the stream: an error, from both paths.
    bz[bz.size() / 2] ^= 0x10;
    put(w / "bad.bz2", bz);
    for (int threads : {1, 8}) {
        auto a = Archive::open(w / "bad.bz2");
        ExtractOptions eo;
        eo.threads = threads;
        auto t = a.test(eo);
        CHECK(!t.ok());
    }
    fs::remove_all(w);
}

TEST(damaged_archives_fail_cleanly)
{
    const fs::path w = temp_dir("bad");
    const fs::path tree = w / "tree";
    put(tree / "a.txt", text_bytes(300000, 1));
    put(tree / "b/c.txt", text_bytes(5000, 2));
    std::mt19937 r(42);
    for (Format f : kWritable) {
        WriteOptions o;
        o.format = f;
        const fs::path arc = w / ("a" + ext(f));
        create(arc, {InputItem{tree, "tree"}}, o);
        std::ifstream in(arc, std::ios::binary);
        const std::vector<std::uint8_t> good((std::istreambuf_iterator<char>(in)), {});
        for (int k = 0; k < 40; ++k) {
            std::vector<std::uint8_t> bad = good;
            if (k % 2) bad.resize(r() % bad.size()); // cut short
            else for (int n = 0; n < 4; ++n) bad[r() % bad.size()] ^= std::uint8_t(1 + r() % 255);
            try {
                auto a = Archive::open(std::shared_ptr<Source>(memory_source(bad, "x" + ext(f))));
                a.entries();
                a.test();
            } catch (const Error &) {
                // expected for most of them
            }
        }
    }
    fs::remove_all(w);
}

TEST(truncated_tar_is_reported)
{
    const fs::path w = temp_dir("trunc");
    put(w / "tree/a.txt", text_bytes(100000, 1));
    WriteOptions o;
    o.format = Format::Tar;
    create(w / "a.tar", {InputItem{w / "tree", "tree"}}, o);
    std::ifstream in(w / "a.tar", std::ios::binary);
    std::vector<std::uint8_t> d((std::istreambuf_iterator<char>(in)), {});
    d.resize(50000);
    auto a = Archive::open(std::shared_ptr<Source>(memory_source(d, "a.tar")));
    CHECK_THROWS_CODE(a.entries(), ErrorCode::Truncated);
    fs::remove_all(w);
}

TEST(pax_headers_only_when_needed)
{
    TarHeaderIn h;
    h.path = "short.txt";
    h.size = 10;
    h.mtime = {1700000000, 0};
    CHECK_EQ(tar_header(h).size(), std::size_t(512));
    h.path = std::string(300, 'n');
    CHECK(tar_header(h).size() > 512);
    h.path = "a/b";
    h.size = 10ull << 30; // above the 8 GiB a ustar size field holds
    auto b = tar_header(h);
    CHECK(b.size() > 512);
    CHECK(std::string(b.begin() + 512, b.begin() + 1024).find("size=10737418240") != std::string::npos);
}

TEST(sparse_fixtures_expand)
{
    // GNU 1.13 old sparse, pax 0.0, 0.1 and 1.0 all hold the same files.
    std::string first;
    for (const char *n : {"test_read_format_gtar_sparse_1_13.tar", "test_read_format_gtar_sparse_1_17_posix00.tar",
                          "test_read_format_gtar_sparse_1_17_posix01.tar", "test_read_format_gtar_sparse_1_17_posix10.tar"}) {
        auto a = Archive::open(g_fixtures / n);
        bool sparse_found = false;
        for (auto &e : a.entries())
            if (e.path == "sparse") { sparse_found = true; CHECK_EQ(e.size, std::uint64_t(3145728)); }
        CHECK(sparse_found);
        const fs::path out = temp_dir("sp");
        a.extract_all(out);
        const std::string h = check::tree_hash(out);
        if (first.empty()) first = h;
        else if (h != first) check::report(n, 0, "sparse variants disagree");
        fs::remove_all(out);
    }
}

TEST(compressed_stream_options)
{
    // Level above 9 means the strongest settings (zstd ultra, xz extreme) and still reads back.
    const fs::path w = temp_dir("opt");
    const auto data = text_bytes(1 << 20, 8);
    put(w / "f", data);
    for (Format f : {Format::Zstd, Format::Xz, Format::Lzip}) {
        WriteOptions o;
        o.format = f;
        o.level = 22;
        o.dictionary = 8 << 20;
        const fs::path arc = w / (std::string("f.") + format_name(f));
        create(arc, {InputItem{w / "f", "f"}}, o);
        auto a = Archive::open(arc);
        MemorySink m;
        a.extract_to(0, m);
        CHECK(m.bytes() == data);
    }
    fs::remove_all(w);
}

int main(int argc, char **argv)
{
    if (argc < 2) { std::fprintf(stderr, "usage: test_tar FIXTURES\n"); return 2; }
    g_fixtures = argv[1];
    for (auto &c : check::cases()) {
        const int before = check::failures();
        try { c.fn(); } catch (const std::exception &e) { check::report(c.name, 0, std::string("threw: ") + e.what()); }
        std::printf("%s %s\n", check::failures() == before ? "ok  " : "FAIL", c.name);
    }
    return check::failures() ? 1 : 0;
}
