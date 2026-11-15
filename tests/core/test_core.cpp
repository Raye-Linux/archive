// SPDX-License-Identifier: GPL-3.0-or-later
#include "../check.h"

#include <raye/archive/archive.h>

#include "core/checksum.h"
#include "core/codec.h"
#include "core/crypto.h"
#include "core/extract.h"
#include "core/threadpool.h"
#include "core/walk.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <fstream>
#include <random>
#include <thread>

using namespace raye::archive;
using namespace raye::archive::detail;
namespace fs = std::filesystem;

static std::vector<std::uint8_t> bytes_of(std::string_view s) { return {s.begin(), s.end()}; }

static fs::path temp_dir(const char *tag)
{
    fs::path p = fs::temp_directory_path() / ("raye-archive-test-" + std::to_string(::getpid()) + "-" + tag);
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

TEST(crc32_known_value) { CHECK_EQ(crc32(0, "123456789", 9), 0xCBF43926u); }

TEST(crc32_incremental)
{
    std::uint32_t c = crc32(0, "1234", 4);
    c = crc32(c, "56789", 5);
    CHECK_EQ(c, 0xCBF43926u);
    CHECK_EQ(crc32_combine(crc32(0, "1234", 4), crc32(0, "56789", 5), 5), 0xCBF43926u);
}

TEST(crc32c_known_value)
{
    CHECK_EQ(crc32c(0, "123456789", 9), 0xE3069283u);
    std::vector<std::uint8_t> big(100003);
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = std::uint8_t(i * 7);
    std::uint32_t c = crc32c(0, big.data(), 5000);
    c = crc32c(c, big.data() + 5000, big.size() - 5000);
    CHECK_EQ(c, crc32c(0, big.data(), big.size()));
}

TEST(pbkdf2_rfc6070)
{
    std::uint8_t out[20];
    const auto salt = bytes_of("salt");
    pbkdf2(Hash::Sha1, "password", salt, 2, out);
    const std::uint8_t want[20] = {0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e,
                                   0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57};
    CHECK(std::memcmp(out, want, 20) == 0);
}

TEST(sha256_abc)
{
    std::uint8_t d[32];
    sha256("abc", 3, d);
    CHECK_EQ(d[0], 0xba);
    CHECK_EQ(d[31], 0xad);
    Sha256 h;
    h.update("a", 1);
    h.update("bc", 2);
    CHECK(std::memcmp(h.final().data(), d, 32) == 0);
}

TEST(aes_cbc_roundtrip)
{
    std::vector<std::uint8_t> key(32, 7), iv(16, 3), plain(64);
    for (std::size_t i = 0; i < plain.size(); ++i) plain[i] = std::uint8_t(i);
    std::vector<std::uint8_t> enc(64), dec(64);
    Aes(key, Aes::Mode::Cbc, true, iv).process(plain.data(), enc.data(), 64);
    Aes(key, Aes::Mode::Cbc, false, iv).process(enc.data(), dec.data(), 64);
    CHECK(enc != plain);
    CHECK(dec == plain);
}

TEST(aes_ctr_le_is_symmetric)
{
    std::vector<std::uint8_t> key(16, 1), data(100, 0x55), orig = data;
    AesCtrLE(key).process(data.data(), data.size());
    CHECK(data != orig);
    AesCtrLE(key).process(data.data(), data.size());
    CHECK(data == orig);
}

TEST(codecs_roundtrip)
{
    std::mt19937 rng(42);
    std::vector<std::uint8_t> in(300000);
    for (std::size_t i = 0; i < in.size(); ++i) in[i] = std::uint8_t(i % 251 < 200 ? 'a' + i % 13 : rng());
    for (Codec c : {Codec::Deflate, Codec::Zlib, Codec::Gzip, Codec::Bzip2, Codec::Xz, Codec::LzmaAlone,
                    Codec::Lzma1Raw, Codec::Lzma2Raw, Codec::Zstd, Codec::Lz4Frame, Codec::Brotli}) {
        CodecParams p;
        p.level = 5;
        auto packed = encode_buffer(c, in, p);
        CHECK(packed.size() < in.size());
        auto back = decode_buffer(c, packed, in.size() + 1, p);
        if (back != in) std::fprintf(stderr, "codec %d does not round-trip\n", int(c));
        CHECK(back == in);
    }
}

TEST(xz_and_zstd_threads)
{
    std::vector<std::uint8_t> in(8 << 20);
    for (std::size_t i = 0; i < in.size(); ++i) in[i] = std::uint8_t((i * 2654435761u) >> 24);
    for (Codec c : {Codec::Xz, Codec::Zstd}) {
        CodecParams p;
        p.level = 1;
        p.threads = 4;
        auto packed = encode_buffer(c, in, p);
        CHECK(decode_buffer(c, packed, in.size(), p) == in);
    }
}

TEST(truncated_stream_is_an_error)
{
    std::vector<std::uint8_t> in(10000, 'x');
    CodecParams p;
    auto packed = encode_buffer(Codec::Xz, in, p);
    packed.resize(packed.size() / 2);
    bool threw = false;
    try { decode_buffer(Codec::Xz, packed, in.size(), p); } catch (const Error &) { threw = true; }
    CHECK(threw);
}

TEST(sanitize_paths)
{
    SafetyPolicy p;
    CHECK_EQ(sanitize_path("a/./b//c", p), std::string("a/b/c"));
    CHECK_EQ(sanitize_path("dir\\file.txt", p), std::string("dir/file.txt"));
    CHECK_THROWS_CODE(sanitize_path("../etc/passwd", p), ErrorCode::UnsafePath);
    CHECK_THROWS_CODE(sanitize_path("a/../../b", p), ErrorCode::UnsafePath);
    CHECK_THROWS_CODE(sanitize_path("/etc/passwd", p), ErrorCode::UnsafePath);
    CHECK_THROWS_CODE(sanitize_path("C:\\Windows\\x", p), ErrorCode::UnsafePath);
    CHECK_THROWS_CODE(sanitize_path("docs/CON.txt", p), ErrorCode::UnsafePath);
    CHECK_THROWS_CODE(sanitize_path("lpt1", p), ErrorCode::UnsafePath);
    CHECK_THROWS_CODE(sanitize_path(std::string("a\0b", 3), p), ErrorCode::UnsafePath);
    CHECK_THROWS_CODE(sanitize_path("./", p), ErrorCode::UnsafePath);
    CHECK_EQ(sanitize_path("console.txt", p), std::string("console.txt"));
    p.allow_absolute = true;
    CHECK_EQ(sanitize_path("/etc/passwd", p), std::string("etc/passwd"));
}

TEST(reserved_names)
{
    CHECK(is_windows_reserved("NUL"));
    CHECK(is_windows_reserved("nul.tar.gz"));
    CHECK(is_windows_reserved("Com9"));
    CHECK(is_windows_reserved("AUX. "));
    CHECK(!is_windows_reserved("COM"));
    CHECK(!is_windows_reserved("NULL"));
}

TEST(link_escape_rules)
{
    CHECK(!link_escapes("a/b/link", "../c"));
    CHECK(link_escapes("a/link", "../../x"));
    CHECK(link_escapes("link", "/etc/passwd"));
    CHECK(!link_escapes("link", "a/b/../c"));
    CHECK(link_escapes("link", "a/../../c"));
}

TEST(glob_rules)
{
    CHECK(glob_match("*.tmp", "a/b/c.tmp"));
    CHECK(glob_match(".git", "src/.git/config"));
    CHECK(!glob_match("*.tmp", "a/tmp"));
    CHECK(glob_match("build/*", "build/x/y"));
    CHECK(!glob_match("build/*", "src/build/x"));
}

TEST(format_names)
{
    CHECK_EQ(std::string(format_name(Format::SevenZip)), std::string("7z"));
    CHECK(format_from_name("7ZIP") == Format::SevenZip);
    CHECK(format_from_name("tgz") == Format::Gzip);
    CHECK(!format_from_name("nope"));
    CHECK(!format_can_write(Format::Rar));
    CHECK(!format_can_write(Format::Rar5));
    CHECK(method_from_name("LZMA2") == Method::Lzma2);
}

TEST(thread_pool_runs_everything)
{
    ThreadPool pool(4);
    std::atomic<int> sum{0};
    pool.parallel_for(1000, [&](std::size_t i) { sum += int(i); });
    CHECK_EQ(sum.load(), 499500);
    bool threw = false;
    try {
        pool.parallel_for(100, [](std::size_t i) { if (i == 50) fail(ErrorCode::Corrupt, "x"); });
    } catch (const Error &e) { threw = e.code() == ErrorCode::Corrupt; }
    CHECK(threw);
}

TEST(control_pause_and_cancel)
{
    Control c;
    c.pause();
    std::atomic<bool> passed{false};
    std::thread t([&] { c.checkpoint(); passed = true; });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(!passed.load());
    c.resume();
    t.join();
    CHECK(passed.load());
    c.cancel();
    CHECK_THROWS_CODE(c.checkpoint(), ErrorCode::Cancelled);
}

TEST(volume_discovery)
{
    auto d = temp_dir("vol");
    for (auto n : {"a.part1.rar", "a.part2.rar", "a.part3.rar", "b.7z.001", "b.7z.002", "c.rar", "c.r00", "c.r01",
                   "z.z01", "z.z02", "z.zip"})
        std::ofstream(d / n) << n;
    auto v = find_volumes(d / "a.part2.rar");
    CHECK(v.kind == VolumeSet::Kind::RarNew);
    CHECK_EQ(v.volumes.size(), std::size_t(3));
    CHECK_EQ(v.volumes.front().filename().string(), std::string("a.part1.rar"));
    v = find_volumes(d / "b.7z.002");
    CHECK(v.kind == VolumeSet::Kind::Split && v.volumes.size() == 2);
    v = find_volumes(d / "c.r01");
    CHECK(v.kind == VolumeSet::Kind::RarOld && v.volumes.size() == 3);
    CHECK_EQ(v.volumes.front().filename().string(), std::string("c.rar"));
    v = find_volumes(d / "z.z02");
    CHECK(v.kind == VolumeSet::Kind::ZipSplit && v.volumes.size() == 3);
    CHECK_EQ(v.volumes.back().filename().string(), std::string("z.zip"));

    auto src = concat_source(find_volumes(d / "b.7z.001").volumes);
    std::string all(src->size(), '\0');
    src->read_exact(0, all.data(), all.size());
    CHECK_EQ(all, std::string("b.7z.001b.7z.002"));
    fs::remove_all(d);
}

TEST(atomic_sink_leaves_nothing_on_failure)
{
    auto d = temp_dir("sink");
    {
        auto s = atomic_file_sink(d / "out.bin");
        s->write("abc", 3);
    } // no finish
    CHECK(fs::is_empty(d));
    {
        auto s = atomic_file_sink(d / "out.bin");
        s->write("abc", 3);
        s->finish();
    }
    CHECK_EQ(fs::file_size(d / "out.bin"), std::uintmax_t(3));
    fs::remove_all(d);
}

TEST(volume_sink_splits)
{
    auto d = temp_dir("vsink");
    auto s = volume_sink(d / "x.7z", 4);
    s->write("0123456789", 10);
    s->finish();
    CHECK_EQ(fs::file_size(d / "x.7z.001"), std::uintmax_t(4));
    CHECK_EQ(fs::file_size(d / "x.7z.003"), std::uintmax_t(2));
    fs::remove_all(d);
}

TEST(sub_source_window)
{
    std::shared_ptr<Source> m = memory_source(bytes_of("SFXSTUBPK..."));
    auto w = sub_source(m, 7, 100);
    CHECK_EQ(w->size(), std::uint64_t(5));
    char b[2];
    w->read_exact(0, b, 2);
    CHECK(b[0] == 'P' && b[1] == 'K');
    CHECK_EQ(w->read_at(5, b, 2), std::size_t(0));
}

TEST(walk_cuts_link_loops)
{
    auto d = temp_dir("walk");
    fs::create_directories(d / "top/sub");
    std::ofstream(d / "top/sub/a.txt") << "a";
    fs::create_directory_symlink("..", d / "top/sub/up");
    fs::create_symlink("nowhere", d / "top/dangling");
    WriteOptions o;
    o.store_links = false;
    std::vector<std::string> names;
    for (auto &it : walk_inputs({InputItem{d / "top", ""}}, o)) names.push_back(it.archive_path);
    std::sort(names.begin(), names.end());
    CHECK((names == std::vector<std::string>{"top", "top/dangling", "top/sub", "top/sub/a.txt"}));
    fs::remove_all(d);
}

CHECK_MAIN()
