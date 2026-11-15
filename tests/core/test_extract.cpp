// SPDX-License-Identifier: GPL-3.0-or-later
#include "../check.h"

#include <raye/archive/archive.h>

#include "core/context.h"
#include "core/extract.h"

#include <fstream>
#include <unistd.h>

using namespace raye::archive;
using namespace raye::archive::detail;
namespace fs = std::filesystem;

namespace {

fs::path temp_dir(const char *tag)
{
    fs::path p = fs::temp_directory_path() / ("raye-archive-x-" + std::to_string(::getpid()) + "-" + tag);
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

Entry file(std::string path, std::uint32_t mode = 0644)
{
    Entry e;
    e.path = std::move(path);
    e.mode = mode;
    e.mtime = Timestamp{1700000000, 0};
    return e;
}

Entry mklink(std::string path, std::string target, EntryType t = EntryType::Symlink)
{
    Entry e;
    e.path = std::move(path);
    e.type = t;
    e.link_target = std::move(target);
    return e;
}

void put(Extractor &x, const Entry &e, std::string_view data)
{
    auto s = x.begin(e);
    if (!s) return;
    s->write(data.data(), data.size());
    x.commit(e, std::move(s));
}

std::string slurp(const fs::path &p)
{
    std::ifstream f(p);
    return {std::istreambuf_iterator<char>(f), {}};
}

struct Fixture {
    fs::path dir;
    Callbacks cb;
    ExtractOptions opts;
    Context ctx{cb, 1, std::nullopt, "t"};
    explicit Fixture(const char *tag) : dir(temp_dir(tag)) {}
    ~Fixture() { fs::remove_all(dir); }
};

} // namespace

TEST(writes_file_with_mode_and_time)
{
    Fixture f("basic");
    Extractor x(f.dir, f.opts, f.cb, f.ctx, 100);
    put(x, file("a/b/c.txt", 0755), "hello");
    x.finish();
    CHECK_EQ(slurp(f.dir / "a/b/c.txt"), std::string("hello"));
    CHECK((fs::status(f.dir / "a/b/c.txt").permissions() & fs::perms::owner_exec) != fs::perms::none);
    CHECK_EQ(fs::last_write_time(f.dir / "a/b/c.txt").time_since_epoch().count() != 0, true);
    // No temporary file left behind.
    int n = 0;
    for (auto &e : fs::directory_iterator(f.dir / "a/b")) { (void)e; ++n; }
    CHECK_EQ(n, 1);
}

TEST(setuid_is_dropped)
{
    Fixture f("suid");
    Extractor x(f.dir, f.opts, f.cb, f.ctx, 100);
    put(x, file("s", 04755), "x");
    CHECK((fs::status(f.dir / "s").permissions() & fs::perms::set_uid) == fs::perms::none);
}

TEST(symlink_outside_is_refused)
{
    Fixture f("lnk");
    Extractor x(f.dir, f.opts, f.cb, f.ctx, 100);
    CHECK_THROWS_CODE(x.begin(mklink("evil", "/etc")), ErrorCode::LinkOutside);
    CHECK_THROWS_CODE(x.begin(mklink("d/evil", "../../x")), ErrorCode::LinkOutside);
    x.begin(mklink("ok", "a/b"));
    CHECK(fs::is_symlink(f.dir / "ok"));
}

TEST(writing_through_a_link_is_refused)
{
    Fixture f("through");
    f.opts.safety.allow_links_outside = true; // even when links themselves are allowed
    Extractor x(f.dir, f.opts, f.cb, f.ctx, 100);
    const fs::path outside = temp_dir("outside");
    x.begin(mklink("out", outside.string()));
    CHECK_THROWS_CODE(x.begin(file("out/owned.txt")), ErrorCode::LinkOutside);
    CHECK(fs::is_empty(outside));
    fs::remove_all(outside);
}

TEST(hardlink_must_target_extracted_file)
{
    Fixture f("hard");
    Extractor x(f.dir, f.opts, f.cb, f.ctx, 100);
    CHECK_THROWS_CODE(x.begin(mklink("h", "../../etc/passwd", EntryType::Hardlink)), ErrorCode::UnsafePath);
    CHECK_THROWS_CODE(x.begin(mklink("h", "missing", EntryType::Hardlink)), ErrorCode::LinkOutside);
    put(x, file("real"), "data");
    x.begin(mklink("h", "real", EntryType::Hardlink));
    CHECK_EQ(slurp(f.dir / "h"), std::string("data"));
}

TEST(conflict_modes)
{
    Fixture f("conflict");
    {
        Extractor x(f.dir, f.opts, f.cb, f.ctx, 100); // Ask with no callback: fails
        put(x, file("same.txt"), "one");
        auto s = x.begin(file("same.txt"));
        s->write("two", 3);
        CHECK_THROWS_CODE(x.commit(file("same.txt"), std::move(s)), ErrorCode::Exists);
    }
    f.opts.overwrite = OverwriteMode::KeepBoth;
    {
        Extractor x(f.dir, f.opts, f.cb, f.ctx, 100);
        put(x, file("same.txt"), "two");
    }
    CHECK_EQ(slurp(f.dir / "same (2).txt"), std::string("two"));
    f.opts.overwrite = OverwriteMode::Skip;
    {
        Extractor x(f.dir, f.opts, f.cb, f.ctx, 100);
        put(x, file("same.txt"), "three");
    }
    CHECK_EQ(slurp(f.dir / "same.txt"), std::string("one"));
    f.opts.overwrite = OverwriteMode::Ask;
    int asked = 0;
    f.cb.conflict = [&](const Conflict &) { ++asked; return ConflictChoice::ReplaceAll; };
    {
        Extractor x(f.dir, f.opts, f.cb, f.ctx, 100);
        put(x, file("same.txt"), "four");
        put(x, file("same (2).txt"), "five");
    }
    CHECK_EQ(asked, 1);
    CHECK_EQ(slurp(f.dir / "same.txt"), std::string("four"));
    CHECK_EQ(slurp(f.dir / "same (2).txt"), std::string("five"));
}

TEST(bomb_ratio_stops_output)
{
    Fixture f("bomb");
    f.opts.safety.ratio_grace = 1000;
    f.opts.safety.max_ratio = 10;
    Extractor x(f.dir, f.opts, f.cb, f.ctx, 50); // a 50-byte "archive"
    auto s = x.begin(file("big"));
    std::string chunk(400, 'z');
    s->write(chunk.data(), chunk.size()); // 400: inside the grace
    s->write(chunk.data(), chunk.size()); // 800: still inside
    CHECK_THROWS_CODE(s->write(chunk.data(), chunk.size()), ErrorCode::Bomb); // 1200 > 1000 and > 10 x 50
}

TEST(declared_size_over_limit)
{
    Fixture f("space");
    f.opts.safety.max_total_size = 1000;
    Extractor x(f.dir, f.opts, f.cb, f.ctx, 50);
    CHECK_THROWS_CODE(x.check_space(5000), ErrorCode::Bomb);
    f.opts.safety.max_total_size = 0;
    // 5000 bytes from 50 is 100 times, over a limit of 10 once past the grace
    f.opts.safety.ratio_grace = 1000;
    f.opts.safety.max_ratio = 10;
    CHECK_THROWS_CODE(x.check_space(5000), ErrorCode::Bomb);
    f.opts.safety.max_ratio = 1e30;
    CHECK_THROWS_CODE(x.check_space(std::uint64_t(1) << 62), ErrorCode::NoSpace);
}

TEST(flat_extraction)
{
    Fixture f("flat");
    f.opts.flat = true;
    Extractor x(f.dir, f.opts, f.cb, f.ctx, 100);
    put(x, file("deep/down/x.txt"), "x");
    CHECK(fs::exists(f.dir / "x.txt"));
    CHECK(!fs::exists(f.dir / "deep"));
}

CHECK_MAIN()
