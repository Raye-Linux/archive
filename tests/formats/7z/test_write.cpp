// SPDX-License-Identifier: GPL-3.0-or-later
// 7z writing: every method and level comes back identical, executables get
// their filter, passwords and hidden names work, updates keep what they should.
#include "check.h"
#include "tree.h"

#include <raye/archive/archive.h>

#include <fstream>
#include <random>
#include <unistd.h>

using namespace raye::archive;
namespace fs = std::filesystem;

static fs::path g_work;

static void put(const fs::path &p, const std::vector<std::uint8_t> &d)
{
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f.write(reinterpret_cast<const char *>(d.data()), std::streamsize(d.size()));
}

static std::vector<std::uint8_t> text(std::size_t n, unsigned seed)
{
    std::mt19937 rng(seed);
    const char *w[] = {"raye ", "archive ", "window ", "solid ", "the ", "of ", "\n"};
    std::string s;
    while (s.size() < n) s += w[rng() % 7];
    s.resize(n);
    return {s.begin(), s.end()};
}

static std::vector<std::uint8_t> fake_elf(std::size_t n, unsigned seed)
{
    std::mt19937 rng(seed);
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned r = rng() % 12;
        v[i] = r == 0 ? 0xE8 : r < 4 ? 0 : std::uint8_t(rng() % 32);
    }
    const std::uint8_t head[20] = {0x7F, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x3E, 0};
    std::copy(head, head + 20, v.begin());
    return v;
}

static fs::path make_tree()
{
    const fs::path t = g_work / "tree";
    if (fs::exists(t)) return t;
    put(t / "docs/a.txt", text(300000, 1));
    put(t / "docs/b.txt", text(70000, 2));
    put(t / "docs/empty.txt", {});
    put(t / "bin/tool", fake_elf(400000, 3));
    std::vector<std::uint8_t> rnd(150000);
    std::mt19937 rng(4);
    for (auto &b : rnd) b = std::uint8_t(rng());
    put(t / "data/random.bin", rnd);
    put(t / "data/zeros.bin", std::vector<std::uint8_t>(500000, 0));
    put(t / "Été/naïve 😀.txt", text(1000, 5));
    fs::create_directories(t / "empty folder");
    fs::create_symlink("../docs/a.txt", t / "data/link");
    fs::permissions(t / "bin/tool", fs::perms::owner_all | fs::perms::group_read | fs::perms::others_read);
    return t;
}

static bool same_after(const fs::path &arc, const fs::path &tree, const OpenOptions &oo = {})
{
    const fs::path out = g_work / "out";
    fs::remove_all(out);
    auto a = Archive::open(arc, oo);
    ExtractOptions eo;
    eo.password = oo.password;
    if (!a.test(eo).ok()) return false;
    a.extract_all(out, eo);
    return check::tree_hash(out / "tree") == check::tree_hash(tree);
}

TEST(every_method_and_level)
{
    const fs::path tree = make_tree();
    struct Case { Method m; int level; bool solid; };
    for (Case c : {Case{Method::Default, 0, true}, Case{Method::Default, 1, true}, Case{Method::Default, 5, true},
                   Case{Method::Default, 9, true}, Case{Method::Default, 5, false}, Case{Method::Lzma, 7, true},
                   Case{Method::Lzma, 9, true}, Case{Method::Ppmd, 5, true}, Case{Method::Ppmd, 9, true},
                   Case{Method::Bzip2, 9, true}, Case{Method::Deflate, 5, true}, Case{Method::Zstd, 5, true},
                   Case{Method::Store, 5, true}}) {
        WriteOptions w;
        w.method = c.m;
        w.level = c.level;
        w.solid = c.solid;
        const fs::path arc = g_work / "m.7z";
        fs::remove(arc);
        create(arc, {InputItem{tree, "tree"}}, w);
        if (!same_after(arc, tree))
            check::report("every_method_and_level", c.level, std::string("round trip failed for ") + method_name(c.m));
    }
}

TEST(executables_get_a_filter)
{
    const fs::path tree = make_tree();
    for (int level : {5, 9}) {
        WriteOptions w;
        w.level = level;
        const fs::path arc = g_work / "f.7z";
        fs::remove(arc);
        create(arc, {InputItem{tree, "tree"}}, w);
        auto a = Archive::open(arc);
        CHECK(a.info().detail.find(level >= 7 ? "BCJ2" : "BCJ") != std::string::npos);
        CHECK(same_after(arc, tree));
    }
}

TEST(passwords_and_hidden_names)
{
    const fs::path tree = make_tree();
    for (bool names : {false, true}) {
        for (int level : {3, 9}) {
            WriteOptions w;
            w.level = level;
            w.password = "secret";
            w.encrypt_names = names;
            const fs::path arc = g_work / "p.7z";
            fs::remove(arc);
            create(arc, {InputItem{tree, "tree"}}, w);
            OpenOptions oo;
            oo.password = "secret";
            CHECK(same_after(arc, tree, oo));
            if (names) {
                CHECK_THROWS_CODE(Archive::open(arc), ErrorCode::PasswordRequired);
            } else {
                auto a = Archive::open(arc);
                CHECK(!a.entries().empty());
                ExtractOptions eo;
                eo.password = "wrong";
                CHECK(!a.test(eo).ok());
            }
        }
    }
}

TEST(volumes)
{
    const fs::path tree = make_tree();
    WriteOptions w;
    w.level = 1;
    w.volume_size = 100000;
    const fs::path arc = g_work / "v.7z";
    create(arc, {InputItem{tree, "tree"}}, w);
    CHECK(fs::exists(g_work / "v.7z.001"));
    CHECK(fs::exists(g_work / "v.7z.003"));
    CHECK(same_after(g_work / "v.7z.002", tree));
}

TEST(update_add_replace_remove)
{
    const fs::path tree = make_tree();
    const fs::path copy = g_work / "copy/tree";
    fs::remove_all(g_work / "copy");
    fs::create_directories(copy.parent_path());
    fs::copy(tree, copy, fs::copy_options::recursive | fs::copy_options::copy_symlinks);
    const fs::path arc = g_work / "u.7z";
    fs::remove(arc);
    WriteOptions w;
    w.level = 5;
    w.solid_block_size = 200000; // several folders, so some stay untouched
    create(arc, {InputItem{copy, "tree"}}, w);
    CHECK(same_after(arc, copy));

    // Replace one file, add one, then remove a folder.
    put(copy / "docs/b.txt", text(5000, 9));
    put(copy / "new/c.txt", text(9000, 10));
    add(arc, {InputItem{copy / "docs/b.txt", "tree/docs/b.txt"}, InputItem{copy / "new", "tree/new"}}, w);
    CHECK(same_after(arc, copy));
    remove(arc, {"tree/data"}, w);
    fs::remove_all(copy / "data");
    CHECK(same_after(arc, copy));
    auto a = Archive::open(arc);
    for (auto &e : a.entries()) CHECK(e.path.rfind("tree/data", 0) != 0);
}

TEST(empty_archive)
{
    const fs::path empty = g_work / "nothing";
    fs::create_directories(empty);
    const fs::path arc = g_work / "e.7z";
    WriteOptions w;
    create(arc, {InputItem{empty, "nothing"}}, w);
    auto a = Archive::open(arc);
    CHECK_EQ(a.entries().size(), std::size_t(1));
    CHECK(a.entries()[0].type == EntryType::Directory);
}

int main()
{
    g_work = fs::temp_directory_path() / ("raye-7z-write-" + std::to_string(::getpid()));
    fs::remove_all(g_work);
    fs::create_directories(g_work);
    for (auto &c : check::cases()) {
        const int before = check::failures();
        try { c.fn(); } catch (const std::exception &e) { check::report(c.name, 0, std::string("threw: ") + e.what()); }
        std::printf("%s %s\n", check::failures() == before ? "ok  " : "FAIL", c.name);
    }
    fs::remove_all(g_work);
    return check::failures() ? 1 : 0;
}
