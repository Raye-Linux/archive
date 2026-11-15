// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../check.h"
#include "../../tree.h"

#include <raye/archive/archive.h>

#include <cstring>
#include <fstream>
#include <random>
#include <unistd.h>

using namespace raye::archive;
namespace fs = std::filesystem;

namespace {

fs::path g_fixtures;

std::vector<std::uint8_t> read_all(const fs::path &p)
{
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}

// The ISO samples are kept as .Z (they are mostly zeros): unpack in memory.
std::shared_ptr<Source> unpack(const char *name)
{
    auto z = Archive::open(g_fixtures / name);
    MemorySink m;
    z.extract_to(0, m);
    return std::shared_ptr<Source>(memory_source(std::move(m.bytes()), std::string(name, std::strlen(name) - 2)));
}

fs::path temp_dir(const std::string &tag)
{
    fs::path p = fs::temp_directory_path() / ("raye-other-" + std::to_string(::getpid()) + "-" + tag);
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

} // namespace

TEST(iso_samples_match_bsdtar)
{
    // Hashes of what bsdtar extracts from the same images.
    static const std::pair<const char *, const char *> want[] = {
        {"test_read_format_iso.iso.Z", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"test_read_format_iso_2.iso.Z", "bd44670a11fa2cca917c338fa012196ce9af5964b5633d82edd17871c3395e0d"},
        {"test_read_format_iso_3.iso.Z", "bd44670a11fa2cca917c338fa012196ce9af5964b5633d82edd17871c3395e0d"},
        {"test_read_format_iso_joliet.iso.Z", "04fae666f16aaaad625e411bf566b379336dd2e0e544f5462059d6337e871161"},
        {"test_read_format_iso_joliet_rockridge.iso.Z", "04fae666f16aaaad625e411bf566b379336dd2e0e544f5462059d6337e871161"},
        {"test_read_format_iso_multi_extent.iso.Z", "e1e9ffb235dd57244b4629062bf0f5a7219c1622d9e6a6bc04b34b44d08ff4d2"},
        {"test_read_format_iso_rockridge.iso.Z", "f12599c96625f848e15c314c4f1a6fa29e1e7fb1f0ecb3acb0a6d2b27f5aaaf0"},
        {"test_read_format_iso_rockridge_ce.iso.Z", "72998ff04f1479f5d4c6960190e753a1d6018cdc060909adb669ae72fe62a25b"},
        {"test_read_format_iso_rockridge_rr_moved.iso.Z", "bc410e117d89753a97ec2bb85411ecd38b879f3ffb4ece1f10715cb6e3c84a14"},
        {"test_read_format_iso_zisofs.iso.Z", "ab1ecc4a79c36427b56d8280c9d657cb29146ebbc1642baee994e83d7466ec06"},
    };
    for (auto [name, hash] : want) {
        auto a = Archive::open(unpack(name));
        CHECK(a.info().format == Format::Iso9660);
        const fs::path out = temp_dir("iso");
        ExtractOptions eo;
        eo.safety.allow_links_outside = true; // some samples hold links to /tmp
        a.extract_all(out, eo);
        if (check::tree_hash(out) != hash) check::report(name, 0, "extracted tree differs from bsdtar");
        fs::remove_all(out);
    }
}

TEST(iso_absolute_links_are_refused_by_default)
{
    auto a = Archive::open(unpack("test_read_format_iso_rockridge.iso.Z"));
    const fs::path out = temp_dir("isolink");
    CHECK_THROWS_CODE(a.extract_all(out), ErrorCode::LinkOutside);
    fs::remove_all(out);
}

TEST(cab_names_and_checksums)
{
    auto a = Archive::open(g_fixtures / "test_read_format_cab_filename_cp932.cab");
    CHECK_EQ(a.entries().size(), std::size_t(2));
    CHECK_EQ(a.entries()[0].path, std::string("\xe8\xa1\xa8\xe3\x81\xa0\xe3\x82\x88/\xe6\xbc\xa2\xe5\xad\x97.txt"));
    // A damaged LZX data block is caught by its checksum.
    auto bytes = read_all(g_fixtures / "test_read_format_cab_3.cab");
    bytes[bytes.size() - 20] ^= 0x55;
    auto b = Archive::open(std::shared_ptr<Source>(memory_source(bytes, "x.cab")));
    CHECK(!b.test().ok());
}

TEST(mutated_samples_never_crash)
{
    std::mt19937 r(1234);
    std::vector<std::vector<std::uint8_t>> samples;
    for (const char *n : {"basic.cpio", "basic-newc.cpio", "basic.a", "basic.iso", "test_read_format_cab_1.cab",
                          "test_read_format_cab_2.cab", "test_read_format_cab_3.cab", "test_read_format_ar.ar",
                          "test_read_format_cpio_svr4_gzip_rpm.rpm", "test_read_format_cpio_svr4_bzip2_rpm.rpm"})
        samples.push_back(read_all(g_fixtures / n));
    samples.push_back([] {
        MemorySink m;
        auto z = Archive::open(g_fixtures / "test_read_format_iso_rockridge_ce.iso.Z");
        z.extract_to(0, m);
        return m.bytes();
    }());
    int errors = 0;
    for (std::size_t s = 0; s < samples.size(); ++s) {
        for (int k = 0; k < 300; ++k) {
            auto bad = samples[s];
            const int kind = k % 3;
            if (kind == 0) bad.resize(r() % bad.size());
            else {
                const int n = 1 + int(r() % 8);
                for (int i = 0; i < n; ++i) bad[r() % bad.size()] = std::uint8_t(r());
            }
            if (bad.empty()) continue;
            try {
                auto a = Archive::open(std::shared_ptr<Source>(memory_source(bad, "m")));
                a.entries();
                a.test();
            } catch (const Error &) {
                ++errors;
            }
        }
    }
    CHECK(errors > 0);
}

int main(int argc, char **argv)
{
    if (argc < 2) { std::fprintf(stderr, "usage: test_other FIXTURES\n"); return 2; }
    g_fixtures = argv[1];
    for (auto &c : check::cases()) {
        const int before = check::failures();
        try { c.fn(); } catch (const std::exception &e) { check::report(c.name, 0, std::string("threw: ") + e.what()); }
        std::printf("%s %s\n", check::failures() == before ? "ok  " : "FAIL", c.name);
    }
    return check::failures() ? 1 : 0;
}
