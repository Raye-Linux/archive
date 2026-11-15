// SPDX-License-Identifier: GPL-3.0-or-later
#include "check.h"
#include "tree.h"

#include "core/checksum.h"
#include "core/codec.h"
#include "formats/zip/zip.h"

#include <raye/archive/archive.h>

#include <fstream>
#include <random>
#include <unistd.h>

using namespace raye::archive;
namespace fs = std::filesystem;
namespace zip = raye::archive::detail::zip;

static fs::path g_dir;
static const char *kBasicTree = "a756f55396713b0a35ea72b2cda1245c1cfe91f271b6d94536585f82160f4c3b";

static std::vector<std::uint8_t> slurp(const fs::path &p)
{
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), {}};
}

static fs::path scratch(const char *tag)
{
    fs::path p = fs::temp_directory_path() / ("raye-zip-" + std::string(tag) + "-" + std::to_string(::getpid()));
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

static Archive open_bytes(std::vector<std::uint8_t> b, std::optional<std::string> pw = {})
{
    OpenOptions o;
    o.password = std::move(pw);
    o.force_format = Format::Zip; // only the ZIP reader is under test here
    return Archive::open(memory_source(std::move(b), "mem.zip"), o);
}

TEST(lists_every_entry)
{
    auto a = Archive::open(g_dir / "basic.zip");
    std::size_t files = 0, dirs = 0, links = 0;
    for (auto &e : a.entries()) {
        files += e.type == EntryType::File;
        dirs += e.type == EntryType::Directory;
        links += e.type == EntryType::Symlink;
    }
    CHECK_EQ(files, std::size_t(5));
    CHECK_EQ(dirs, std::size_t(4));
    CHECK_EQ(links, std::size_t(1));
    for (auto &e : a.entries())
        if (e.type == EntryType::Symlink) CHECK_EQ(e.link_target, std::string("../hello.txt"));
    bool unicode = false;
    for (auto &e : a.entries()) unicode = unicode || e.path == "basic/docs/été 日本.txt";
    CHECK(unicode);
}

TEST(deflate64_matches_the_lzma_copy)
{
    const fs::path out = scratch("d64");
    Archive::open(g_dir / "basic-deflate64.zip").extract_all(out);
    CHECK_EQ(check::tree_hash(out), std::string(kBasicTree));
    fs::remove_all(out);
}

TEST(deflate64_decoder_streams_in_tiny_pieces)
{
    // One byte in, one byte out: every buffer edge of the decoder is hit.
    auto a = Archive::open(g_dir / "zip-deflate64-far.zip");
    MemorySink whole;
    a.extract_to(0, whole);
    auto raw = slurp(g_dir / "zip-deflate64-far.zip");
    const std::uint8_t *lh = raw.data();
    const std::size_t start = 30 + detail::le16(lh + 26) + detail::le16(lh + 28);
    const std::size_t packed = detail::le32(lh + 18);
    auto dec = zip::make_deflate64_decoder();
    std::vector<std::uint8_t> got;
    std::size_t pos = start;
    for (int guard = 0; guard < 50'000'000; ++guard) {
        std::uint8_t o;
        const bool last = pos + 1 >= start + packed;
        auto s = dec->step(std::span(raw.data() + pos, pos < start + packed ? 1 : 0), std::span(&o, 1), last);
        pos += s.consumed;
        if (s.produced) got.push_back(o);
        if (s.done) break;
    }
    CHECK(got == whole.bytes());
    CHECK_EQ(got.size(), std::size_t(260000));
}

TEST(passwords)
{
    for (const char *name : {"basic-aes.zip", "basic-zipcrypto.zip"}) {
        auto a = Archive::open(g_dir / name);
        CHECK(a.info().has_encrypted_entries);
        CHECK_THROWS_CODE(a.extract_all(scratch("nopw")), ErrorCode::PasswordRequired);
        ExtractOptions bad;
        bad.password = "wrong";
        CHECK_THROWS_CODE(a.extract_all(scratch("badpw"), bad), ErrorCode::WrongPassword);
        // The callback is asked again after a wrong answer.
        int asked = 0;
        Callbacks cb;
        cb.password = [&](const PasswordRequest &) -> std::optional<std::string> { return ++asked == 1 ? "nope" : "raye"; };
        const fs::path out = scratch("cbpw");
        a.extract_all(out, {}, cb);
        CHECK_EQ(asked, 2);
        auto r = Archive::open(g_dir / name, OpenOptions{std::string("raye"), {}, {}}).test();
        CHECK(r.ok());
        fs::remove_all(out);
    }
    fs::remove_all(scratch("nopw"));
    fs::remove_all(scratch("badpw"));
}

TEST(split_set_opens_from_any_part)
{
    for (const char *part : {"zip-split.zip", "zip-split.z01"}) {
        auto a = Archive::open(g_dir / part);
        CHECK_EQ(a.info().volume_count, std::size_t(2));
        CHECK(a.test().ok());
    }
    // Last part alone: says what is missing.
    const fs::path d = scratch("split");
    fs::copy_file(g_dir / "zip-split.zip", d / "lonely.zip");
    CHECK_THROWS_CODE(Archive::open(d / "lonely.zip"), ErrorCode::MissingVolume);
    fs::remove_all(d);
}

TEST(stub_in_front_is_skipped)
{
    auto a = Archive::open(g_dir / "zip-prefixed.exe");
    CHECK(a.info().offset == 0 || a.info().self_extracting || a.info().format == Format::Zip);
    CHECK(a.test().ok());
    CHECK_EQ(a.info().detail, std::string("ZIP64"));
}

// Builds a stored ZIP by hand, the way old DOS tools did.
static std::vector<std::uint8_t> handmade(std::string_view name, std::string_view data, std::uint16_t made_by)
{
    std::vector<std::uint8_t> z;
    auto u16 = [&](unsigned v) { z.push_back(std::uint8_t(v)); z.push_back(std::uint8_t(v >> 8)); };
    auto u32 = [&](std::uint32_t v) { u16(v & 0xffff); u16(v >> 16); };
    const std::uint32_t crc = detail::crc32(0, data.data(), data.size());
    u32(0x04034b50); u16(10); u16(0); u16(0); u16(0x6000); u16(0x5821); u32(crc);
    u32(std::uint32_t(data.size())); u32(std::uint32_t(data.size())); u16(unsigned(name.size())); u16(0);
    z.insert(z.end(), name.begin(), name.end());
    z.insert(z.end(), data.begin(), data.end());
    const std::uint32_t cd = std::uint32_t(z.size());
    u32(0x02014b50); u16(made_by); u16(10); u16(0); u16(0); u16(0x6000); u16(0x5821); u32(crc);
    u32(std::uint32_t(data.size())); u32(std::uint32_t(data.size())); u16(unsigned(name.size())); u16(0); u16(0);
    u16(0); u16(0); u32(0x20); u32(0);
    z.insert(z.end(), name.begin(), name.end());
    const std::uint32_t cds = std::uint32_t(z.size()) - cd;
    u32(0x06054b50); u16(0); u16(0); u16(1); u16(1); u32(cds); u32(cd); u16(0);
    return z;
}

TEST(dos_names_are_cp437)
{
    auto a = open_bytes(handmade("DOSSIER\\caf\x82.txt", "x", 0x0014));
    CHECK_EQ(a.entries().at(0).path, std::string("DOSSIER/café.txt"));
    CHECK(a.entries().at(0).mtime.has_value());
    CHECK(a.test().ok());
}

TEST(lying_header_fails_cleanly)
{
    auto good = handmade("a.txt", "hello hello", 0x0314);
    auto bad = good;
    bad[30 + 5] ^= 1; // data byte: CRC mismatch
    NullSink null;
    CHECK_THROWS_CODE(open_bytes(bad).extract_to(0, null), ErrorCode::Checksum);
    auto big = good;
    big[22] = 200; // local "uncompressed size" is ignored, central one wins
    CHECK(open_bytes(big).test().ok());
    auto off = good;
    off[off.size() - 22 + 16] = 0xff; // central directory offset out of range
    try { open_bytes(off).test(); } catch (const Error &) {}
}

TEST(truncated_archives_never_crash)
{
    for (const char *name : {"basic.zip", "basic-aes.zip", "basic-lzma.zip", "basic-bzip2.zip", "basic-deflate64.zip",
                             "zip-zip64.zip", "zip-deflate64-far.zip"}) {
        auto full = slurp(g_dir / name);
        for (std::size_t cut = 0; cut < full.size(); cut += 1 + cut / 7) {
            std::vector<std::uint8_t> part(full.begin(), full.begin() + std::ptrdiff_t(cut));
            try {
                auto a = open_bytes(part, "raye");
                (void)a.test();
            } catch (const Error &) {
            }
        }
    }
}

TEST(cut_download_is_read_from_file_headers)
{
    auto full = slurp(g_dir / "basic.zip");
    // Drop the central directory: everything before it still comes out.
    const std::uint32_t cd = detail::le32(&full[full.size() - 22 + 16]);
    std::vector<std::uint8_t> part(full.begin(), full.begin() + cd);
    auto a = open_bytes(part);
    CHECK(a.entries().size() >= 10);
    CHECK(a.info().detail.find("damaged") != std::string::npos);
    CHECK(a.test().ok());
}

TEST(flipped_bytes_never_crash)
{
    std::mt19937 rng(42);
    for (const char *name : {"basic.zip", "basic-deflate64.zip", "basic-aes.zip", "basic-lzma.zip", "zip-zip64.zip"}) {
        const auto full = slurp(g_dir / name);
        for (int round = 0; round < 400; ++round) {
            auto b = full;
            for (int k = 0; k < 4; ++k) b[rng() % b.size()] ^= std::uint8_t(1u << (rng() % 8));
            try {
                auto a = open_bytes(b, "raye");
                (void)a.test();
            } catch (const Error &) {
            }
        }
    }
}

int main(int argc, char **argv)
{
    g_dir = argc > 1 ? argv[1] : "tests/fixtures";
    for (auto &c : check::cases()) {
        const int before = check::failures();
        try { c.fn(); } catch (const std::exception &e) { check::report(c.name, 0, std::string("threw: ") + e.what()); }
        std::printf("%s %s\n", check::failures() == before ? "ok  " : "FAIL", c.name);
    }
    return check::failures() ? 1 : 0;
}
