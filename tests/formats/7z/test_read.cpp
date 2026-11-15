// SPDX-License-Identifier: GPL-3.0-or-later
// 7z reading: header numbers, names, filters and PPMd both ways, passwords,
// and damaged archives that must fail cleanly.
#include "check.h"
#include "tree.h"

#include "core/codec.h"
#include "formats/7z/filters.h"
#include "formats/7z/lzma2mt.h"
#include "formats/7z/ppmd.h"
#include "formats/7z/sevenz.h"

#include <raye/archive/archive.h>

#include <fstream>
#include <random>
#include <unistd.h>

using namespace raye::archive;
using namespace raye::archive::detail;
namespace fs = std::filesystem;

static fs::path g_fixtures;

static std::vector<std::uint8_t> slurp(const fs::path &p)
{
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), {}};
}

// Something that looks like x86 code, with calls and jumps to convert.
static std::vector<std::uint8_t> code_like(std::size_t n, unsigned seed)
{
    std::mt19937 rng(seed);
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned r = rng() % 16;
        v[i] = r == 0 ? 0xE8 : r == 1 ? 0xE9 : r == 2 ? 0x0F : r == 3 ? 0x85 : r == 4 ? 0xEB : r < 8 ? 0 : std::uint8_t(rng());
    }
    return v;
}

TEST(numbers_round_trip)
{
    for (std::uint64_t v : {0ull, 1ull, 127ull, 128ull, 16383ull, 16384ull, 0x1FFFFFull, 0x200000ull, 0xFFFFFFFFull,
                            0x00FFFFFFFFFFFFFFull, 0x0100000000000000ull, ~0ull}) {
        std::vector<std::uint8_t> b;
        sevenz::write_number(b, v);
        ByteReader r(b);
        CHECK_EQ(sevenz::read_number(r), v);
        CHECK(r.eof());
    }
}

TEST(utf16_names)
{
    const std::string s = "été/日本/😀 x";
    auto u = sevenz::utf8_to_utf16le(s);
    CHECK_EQ(sevenz::utf16le_to_utf8(u.data(), u.size() / 2), s);
}

TEST(filters_round_trip)
{
    using K = filters::Kind;
    for (K k : {K::X86, K::Arm, K::Armt, K::Arm64, K::Ppc, K::Sparc, K::Ia64, K::Delta}) {
        for (std::size_t n : {0u, 3u, 17u, 4096u, 100003u}) {
            const auto orig = code_like(n, unsigned(n) + unsigned(k));
            auto data = orig;
            // Fed in uneven pieces, as a stream would be.
            auto pass = [&](bool enc) {
                auto f = filters::make_filter(k, enc, 0, 4);
                std::vector<std::uint8_t> out, pend;
                std::mt19937 rng(7);
                for (std::size_t at = 0; at < data.size();) {
                    const std::size_t take = std::min(data.size() - at, std::size_t(1 + rng() % 9000));
                    pend.insert(pend.end(), data.begin() + std::ptrdiff_t(at), data.begin() + std::ptrdiff_t(at + take));
                    at += take;
                    const std::size_t done = f->run(pend.data(), pend.size());
                    out.insert(out.end(), pend.begin(), pend.begin() + std::ptrdiff_t(done));
                    pend.erase(pend.begin(), pend.begin() + std::ptrdiff_t(done));
                }
                out.insert(out.end(), pend.begin(), pend.end());
                data = out;
            };
            pass(true);
            if (k == K::X86 && n > 64) CHECK(data != orig);
            pass(false);
            CHECK(data == orig);
        }
    }
}

static std::size_t bcj2_pull(void *ctx, int s, std::uint8_t *buf, std::size_t n)
{
    auto *st = static_cast<std::pair<std::vector<std::uint8_t> *, std::size_t> *>(ctx);
    auto &[v, at] = st[s];
    n = std::min(n, v->size() - at);
    std::copy(v->begin() + std::ptrdiff_t(at), v->begin() + std::ptrdiff_t(at + n), buf);
    at += n;
    return n;
}

TEST(bcj2_round_trip)
{
    for (std::size_t n : {1u, 5u, 1000u, 300000u}) {
        const auto orig = code_like(n, 99);
        filters::Bcj2Encoder enc(n);
        enc.write(orig.data(), orig.size() / 3);
        enc.write(orig.data() + orig.size() / 3, orig.size() - orig.size() / 3);
        enc.finish();
        std::pair<std::vector<std::uint8_t> *, std::size_t> st[4] = {{&enc.main, 0}, {&enc.call, 0}, {&enc.jump, 0}, {&enc.rc, 0}};
        filters::Bcj2Decoder dec(bcj2_pull, st, n);
        std::vector<std::uint8_t> out(n);
        std::size_t got = 0;
        while (got < n) {
            const std::size_t r = dec.read(out.data() + got, n - got);
            if (!r) break;
            got += r;
        }
        CHECK_EQ(got, n);
        CHECK(out == orig);
        if (n > 1000) CHECK(!enc.call.empty());
    }
}

struct Bytes {
    const std::vector<std::uint8_t> *v;
    std::size_t at = 0;
};
static int next_byte(void *p)
{
    auto *b = static_cast<Bytes *>(p);
    return b->at < b->v->size() ? (*b->v)[b->at++] : 0;
}

TEST(ppmd_round_trip)
{
    std::string text;
    std::mt19937 rng(1);
    const char *words[] = {"raye ", "archive ", "solid ", "block ", "the ", "of ", "7z ", "\n"};
    while (text.size() < 400000) text += words[rng() % 8];
    std::vector<std::uint8_t> bin(200000);
    for (auto &b : bin) b = std::uint8_t(rng());
    for (auto [order, mem] : {std::pair{6u, 16u << 20}, {2u, 1u << 20}, {32u, 1u << 16}, {64u, 2048u}}) {
        for (const std::vector<std::uint8_t> *in : std::initializer_list<const std::vector<std::uint8_t> *>{&bin, nullptr}) {
            std::vector<std::uint8_t> data = in ? *in : std::vector<std::uint8_t>(text.begin(), text.end());
            ppmd7::Encoder enc(order, mem);
            enc.encode(data.data(), data.size());
            enc.finish();
            if (!in && mem >= (1u << 20)) CHECK(enc.out.size() < data.size() / 3);
            Bytes src{&enc.out};
            ppmd7::Decoder dec(order, mem, next_byte, &src);
            bool same = true;
            for (std::size_t i = 0; i < data.size() && same; ++i) same = dec.decode() == data[i];
            CHECK(same);
        }
    }
}

static std::vector<std::uint8_t> lzma2_raw(const std::vector<std::uint8_t> &data, std::uint8_t *props)
{
    using namespace raye::archive::detail;
    CodecParams p;
    p.level = 1;
    p.dictionary = 1 << 20;
    auto enc = make_encoder(Codec::Lzma2Raw, p);
    *props = p.props.at(0);
    std::vector<std::uint8_t> out(data.size() + data.size() / 2 + 4096);
    std::size_t at = 0, made = 0;
    for (;;) {
        auto st = enc->step({data.data() + at, data.size() - at}, {out.data() + made, out.size() - made}, true);
        at += st.consumed;
        made += st.produced;
        if (st.done) break;
    }
    out.resize(made);
    return out;
}

// Two streams glued the way 7-Zip cuts one with several threads: the second
// starts with a dictionary reset.
TEST(lzma2_pieces_in_parallel)
{
    namespace sz = raye::archive::detail::sevenz;
    const auto a = code_like(9 << 20, 3), b = code_like(10 << 20, 4);
    std::uint8_t pa = 0, pb = 0;
    auto ea = lzma2_raw(a, &pa), eb = lzma2_raw(b, &pb);
    CHECK(!ea.empty() && ea.back() == 0);
    ea.pop_back();
    ea.insert(ea.end(), eb.begin(), eb.end());
    std::vector<std::uint8_t> want(a);
    want.insert(want.end(), b.begin(), b.end());
    auto src = raye::archive::memory_source(ea);

    CHECK(!sz::open_lzma2_parallel(*src, 0, ea.size(), pa, want.size(), 1));
    CHECK(!sz::open_lzma2_parallel(*src, 0, ea.size(), pa, want.size() + 1, 4));
    auto pull = sz::open_lzma2_parallel(*src, 0, ea.size(), pa, want.size(), 4);
    CHECK(pull != nullptr);
    if (!pull) return;
    std::vector<std::uint8_t> got(want.size());
    std::size_t n = 0;
    while (n < got.size()) {
        const std::size_t r = pull->read(got.data() + n, std::min<std::size_t>(got.size() - n, 70000));
        if (!r) break;
        n += r;
    }
    CHECK_EQ(n, want.size());
    CHECK(got == want);
}

TEST(passwords)
{
    // Right password, missing password, wrong password, and asking again.
    for (const char *name : {"basic-encrypted.7z", "basic-encrypted-names.7z"}) {
        const fs::path p = g_fixtures / name;
        const bool names = std::string(name).find("names") != std::string::npos;
        if (names) {
            CHECK_THROWS_CODE(Archive::open(p), ErrorCode::PasswordRequired);
            CHECK_THROWS_CODE(Archive::open(p, OpenOptions{std::string("nope"), {}, {}}), ErrorCode::WrongPassword);
        } else {
            auto a = Archive::open(p);
            CHECK(a.info().has_encrypted_entries);
            ExtractOptions eo;
            auto r = a.test(eo);
            CHECK(!r.ok());
            CHECK(r.failures.front().second.code() == ErrorCode::PasswordRequired);
            eo.password = "nope";
            r = a.test(eo);
            CHECK(!r.ok() && r.failures.front().second.code() == ErrorCode::WrongPassword);
        }
        int asked = 0;
        OpenOptions oo;
        oo.password = "wrong";
        oo.callbacks.password = [&](const PasswordRequest &) -> std::optional<std::string> {
            ++asked;
            return std::string("raye");
        };
        auto a = Archive::open(p, oo);
        Callbacks cb;
        cb.password = oo.callbacks.password;
        ExtractOptions eo;
        eo.password = "wrong";
        auto r = a.test(eo, cb);
        CHECK(r.ok());
        CHECK(r.entries_ok > 0);
        CHECK(asked >= 1);
    }
}

TEST(damaged_archives_fail_cleanly)
{
    // Every way of breaking a real archive gives an Error, never a crash or a hang.
    for (const char *name : {"basic.7z", "basic-ppmd.7z", "basic-bcj2.7z", "basic-encrypted-names.7z",
                             "test_read_format_7zip_delta_lzma2.7z"}) {
        const auto orig = slurp(g_fixtures / name);
        CHECK(!orig.empty());
        std::mt19937 rng(42);
        int errors = 0, total = 0;
        auto attempt = [&](std::vector<std::uint8_t> v) {
            ++total;
            try {
                OpenOptions oo;
                oo.password = "raye";
                auto a = Archive::open(std::shared_ptr<Source>(memory_source(std::move(v), name)), oo);
                ExtractOptions eo;
                eo.password = "raye";
                auto r = a.test(eo);
                if (!r.ok()) ++errors;
            } catch (const Error &) {
                ++errors;
            }
        };
        for (std::size_t cut : {std::size_t(1), std::size_t(10), std::size_t(32), orig.size() / 2, orig.size() - 1})
            attempt(std::vector<std::uint8_t>(orig.begin(), orig.begin() + std::ptrdiff_t(cut)));
        for (int i = 0; i < 300; ++i) {
            auto v = orig;
            const int flips = 1 + int(rng() % 4);
            for (int k = 0; k < flips; ++k) v[rng() % v.size()] ^= std::uint8_t(1u << (rng() % 8));
            attempt(std::move(v));
        }
        CHECK(errors >= 5); // at least the cut ones
        std::printf("  %s: %d of %d damaged copies refused\n", name, errors, total);
    }
}

TEST(self_extracting_and_info)
{
    auto a = Archive::open(g_fixtures / "test_read_format_7zip_sfx_pe.exe");
    CHECK(a.info().self_extracting);
    CHECK(a.info().offset > 0);
    CHECK(!a.entries().empty());
    auto b = Archive::open(g_fixtures / "basic-bcj2.7z");
    CHECK(b.info().detail.find("BCJ2") != std::string::npos);
    CHECK(b.test().ok());
}

int main(int argc, char **argv)
{
    g_fixtures = argc > 1 ? argv[1] : "tests/fixtures";
    for (auto &c : check::cases()) {
        const int before = check::failures();
        try { c.fn(); } catch (const std::exception &e) { check::report(c.name, 0, std::string("threw: ") + e.what()); }
        std::printf("%s %s\n", check::failures() == before ? "ok  " : "FAIL", c.name);
    }
    return check::failures() ? 1 : 0;
}
