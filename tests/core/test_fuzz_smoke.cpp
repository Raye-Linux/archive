// SPDX-License-Identifier: GPL-3.0-or-later
// Mutation fuzzer over the fixtures: flipped bits, cut tails, inserted and
// repeated bytes. Anything but a raye::archive::Error (or a sanitizer
// report, in the sanitizer build) is a failure. Runs RAYE_FUZZ_SECONDS (5).
#include <raye/archive/archive.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <random>

using namespace raye::archive;
namespace fs = std::filesystem;

static void one(std::vector<std::uint8_t> data)
{
    std::shared_ptr<Source> src = memory_source(std::move(data), "fuzz");
    try {
        auto all = detect_all(*src, "");
        for (auto &d : all) (void)d;
        OpenOptions oo;
        oo.password = "fuzz";
        auto a = Archive::open(src, oo);
        (void)a.entries();
        ExtractOptions eo;
        eo.threads = 1;
        eo.safety.max_total_size = 64 << 20;
        (void)a.test(eo);
        for (std::size_t i = 0; i < a.entries().size() && i < 8; ++i) {
            NullSink n;
            try { a.extract_to(i, n, eo); } catch (const Error &) {}
        }
    } catch (const Error &) {
    }
}

int main(int argc, char **argv)
{
    const fs::path dir = argc > 1 ? argv[1] : "tests/fixtures";
    const char *secs_env = std::getenv("RAYE_FUZZ_SECONDS");
    const double secs = secs_env ? std::atof(secs_env) : 5.0;
    std::vector<std::vector<std::uint8_t>> seeds;
    for (auto &e : fs::directory_iterator(dir)) {
        if (!e.is_regular_file() || e.path().filename() == "MANIFEST" || e.path().extension() == ".md") continue;
        std::ifstream f(e.path(), std::ios::binary);
        seeds.emplace_back(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    }
    if (seeds.empty()) { std::fprintf(stderr, "no seeds in %s\n", dir.c_str()); return 1; }
    std::mt19937_64 rng(std::random_device{}());
    const auto end = std::chrono::steady_clock::now() + std::chrono::duration<double>(secs);
    std::uint64_t runs = 0;
    for (auto &s : seeds) one(s);
    while (std::chrono::steady_clock::now() < end) {
        auto d = seeds[rng() % seeds.size()];
        if (d.empty()) continue;
        const int edits = 1 + int(rng() % 8);
        for (int k = 0; k < edits; ++k) {
            switch (rng() % 5) {
            case 0: d[rng() % d.size()] ^= std::uint8_t(1u << (rng() % 8)); break;
            case 1: d[rng() % d.size()] = std::uint8_t(rng()); break;
            case 2: d.resize(rng() % d.size() + 1); break;
            case 3: d.insert(d.begin() + std::ptrdiff_t(rng() % d.size()), std::uint8_t(rng())); break;
            case 4: { // poke a large number into a likely length field
                const std::size_t at = rng() % d.size();
                for (std::size_t j = at; j < at + 4 && j < d.size(); ++j) d[j] = 0xff;
                break;
            }
            }
        }
        one(std::move(d));
        ++runs;
    }
    std::printf("%llu mutated inputs, no crash\n", static_cast<unsigned long long>(runs));
    return 0;
}
