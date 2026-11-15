// SPDX-License-Identifier: GPL-3.0-or-later
// RAR reader: hashes, passwords, volumes, comments, solid reads, and
// damaged input that must end in a clean error, never a crash.
#include "../../check.h"
#include "../../tree.h"

#include "core/checksum.h"
#include "formats/rar/rar.h"

#include <raye/archive/archive.h>

#include <fstream>
#include <random>
#include <sstream>
#include <unistd.h>

using namespace raye::archive;
namespace fs = std::filesystem;
namespace rar = raye::archive::detail::rar;

static fs::path g_dir;

static std::vector<std::uint8_t> slurp(const fs::path &p)
{
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), {}};
}

static fs::path scratch(const char *tag)
{
    auto d = fs::temp_directory_path() / ("raye-rar-" + std::string(tag) + "-" + std::to_string(::getpid()));
    fs::remove_all(d);
    fs::create_directories(d);
    return d;
}

static std::string b2sp_hex(const std::vector<std::uint8_t> &d, std::size_t chunk)
{
    raye::archive::detail::Blake2sp h;
    for (std::size_t i = 0; i < d.size(); i += chunk) h.update(d.data() + i, std::min(chunk, d.size() - i));
    auto r = h.final();
    return check::hex(r.data(), r.size());
}

TEST(blake2sp_vectors)
{
    // Reference values from Python's hashlib.blake2s tree mode.
    CHECK_EQ(b2sp_hex({}, 1), std::string("dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"));
    std::vector<std::uint8_t> a;
    for (int k = 0; k < 4; ++k)
        for (int i = 0; i < 256; ++i) a.push_back(std::uint8_t(i));
    a.push_back('x');
    for (std::size_t chunk : {std::size_t(1), std::size_t(7), std::size_t(64), std::size_t(1000)})
        CHECK_EQ(b2sp_hex(a, chunk), std::string("40aa4715e128840f34ad00fb28bb11f1a25c42d7af956e6ccda7f7ebc0088a98"));
    std::vector<std::uint8_t> b;
    for (int i = 0; i < 512; ++i) b.push_back(std::uint8_t(i * 7 % 251));
    CHECK_EQ(b2sp_hex(b, 512), std::string("c32ac442faff0839e3b3af097f32402369128bb1e7fd4693e70ba005a47f2671"));
}

TEST(sha1_short_input_is_plain_sha1)
{
    auto d = rar::sha1_rar29({'a', 'b', 'c'});
    CHECK_EQ(check::hex(d.data(), d.size()), std::string("a9993e364706816aba3e25717850c26c9cd0d89d"));
}

TEST(wrong_password_rar5)
{
    auto a = Archive::open(g_dir / "rar5-psw-blake.rar");
    ExtractOptions eo;
    eo.password = "nope";
    CHECK_THROWS_CODE(a.extract_all(scratch("pw5"), eo), ErrorCode::WrongPassword);
}

TEST(wrong_password_rar3)
{
    auto a = Archive::open(g_dir / "rar3-comment-psw.rar");
    ExtractOptions eo;
    eo.password = "nope";
    auto r = a.test(eo);
    CHECK(!r.ok());
    for (auto &f : r.failures) CHECK(f.second.code() == ErrorCode::WrongPassword);
}

TEST(wrong_password_encrypted_headers)
{
    OpenOptions oo;
    oo.password = "nope";
    CHECK_THROWS_CODE(Archive::open(g_dir / "rar5-hpsw.rar", oo), ErrorCode::WrongPassword);
    CHECK_THROWS_CODE(Archive::open(g_dir / "rar3-comment-hpsw.rar", oo), ErrorCode::WrongPassword);
    CHECK_THROWS_CODE(Archive::open(g_dir / "rar5-hpsw.rar"), ErrorCode::PasswordRequired);
}

TEST(password_asked_again)
{
    OpenOptions oo;
    int asked = 0;
    oo.callbacks.password = [&](const PasswordRequest &) -> std::optional<std::string> {
        return ++asked == 1 ? std::string("first try") : std::string("password");
    };
    auto a = Archive::open(g_dir / "rar5-hpsw.rar", oo);
    CHECK_EQ(asked, 2);
    CHECK(!a.entries().empty());
}

TEST(comments)
{
    auto a = Archive::open(g_dir / "rar15-comment.rar");
    CHECK_EQ(a.info().comment, std::string("RARcomment -----"));
    OpenOptions oo;
    oo.password = "password";
    auto b = Archive::open(g_dir / "rar3-comment-psw.rar", oo);
    CHECK_EQ(b.info().comment, std::string("RARcomment\n"));
}

TEST(solid_last_file_alone)
{
    for (const char *name : {"rar5-solid.rar", "rar3-solid.rar", "test_read_format_rar5_multiarchive_solid.part01.rar"}) {
        auto a = Archive::open(g_dir / name);
        const auto &e = a.entries();
        std::size_t last = 0;
        for (std::size_t i = 0; i < e.size(); ++i)
            if (e[i].type == EntryType::File) last = i;
        MemorySink one;
        a.extract_to(last, one);
        const auto all = scratch("solid");
        a.extract_all(all);
        CHECK(one.bytes() == slurp(all / e[last].path));
        CHECK(e[last].solid);
    }
}

TEST(missing_volume)
{
    const auto d = scratch("vol");
    fs::copy_file(g_dir / "rar5-vols.part1.rar", d / "rar5-vols.part1.rar");
    fs::copy_file(g_dir / "rar5-vols.part2.rar", d / "rar5-vols.part2.rar");
    auto a = Archive::open(d / "rar5-vols.part1.rar");
    CHECK(a.info().detail.find("damaged") != std::string::npos);
    auto r = a.test();
    CHECK(!r.ok());
}

TEST(damaged_archive_reads_what_it_can)
{
    auto bytes = slurp(g_dir / "test_read_format_rar5_multiple_files_solid.rar");
    bytes.resize(bytes.size() * 3 / 4);
    auto a = Archive::open(memory_source(bytes, "cut.rar"));
    CHECK(a.info().detail.find("damaged") != std::string::npos);
    CHECK(!a.entries().empty());
    auto r = a.test();
    CHECK(!r.ok());
    CHECK(r.entries_ok > 0);
}

// Every RAR fixture, cut short and with random bits flipped: any outcome
// but a crash, a hang or an exception that is not an archive Error.
TEST(corrupt_input_never_crashes)
{
    std::ifstream m(g_dir / "MANIFEST");
    std::mt19937 rng(1234);
    int cases = 0;
    for (std::string line; std::getline(m, line);) {
        std::istringstream ls(line);
        std::string file, fmt, hash, pw;
        ls >> file >> fmt >> hash >> pw;
        if (fmt != "rar" && fmt != "rar5") continue;
        const auto orig = slurp(g_dir / file);
        if (orig.size() > (256 << 10)) continue;
        for (int round = 0; round < 40; ++round) {
            auto b = orig;
            if (round < 10) {
                b.resize(b.size() * std::size_t(round + 1) / 11);
            } else {
                const int flips = 1 + round % 5;
                for (int k = 0; k < flips; ++k) b[rng() % b.size()] ^= std::uint8_t(1u << (rng() % 8));
            }
            ++cases;
            try {
                OpenOptions oo;
                if (!pw.empty()) oo.password = pw;
                auto a = Archive::open(memory_source(b, file), oo);
                a.entries();
                ExtractOptions eo;
                eo.password = oo.password;
                a.test(eo);
            } catch (const Error &) {
            }
        }
    }
    std::printf("  %d damaged archives handled\n", cases);
    CHECK(cases > 100);
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
