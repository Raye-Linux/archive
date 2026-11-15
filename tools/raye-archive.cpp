// SPDX-License-Identifier: GPL-3.0-or-later
// raye-archive: command line front end of the Raye archive engine.
#include <raye/archive/archive.h>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <vector>

namespace ra = raye::archive;
namespace fs = std::filesystem;

namespace {

void usage(std::FILE *f)
{
    std::fprintf(f,
        "Usage: raye-archive <command> [options] <archive> [files...]\n"
        "\n"
        "Commands:\n"
        "  l   list the contents\n"
        "  x   extract (with folders)\n"
        "  t   test: decode everything, check checksums\n"
        "  a   add files (creates the archive if needed)\n"
        "  u   update: add files that are new or changed\n"
        "  s   sync: update, and drop entries whose file is gone\n"
        "  d   delete entries\n"
        "  i   show what the file is (format detection)\n"
        "\n"
        "Options:\n"
        "  -o DIR              extract into DIR (default: current folder)\n"
        "  -p[PASSWORD]        password; -p alone asks for it\n"
        "  --overwrite=MODE    ask, replace, skip, rename, fail (default: ask)\n"
        "  -t FORMAT           7z, zip, tar, gz, xz, zst ... (default: from the name, else 7z)\n"
        "  -mx N               level 0-9 (default 5)\n"
        "  -mm METHOD          store, deflate, bzip2, lzma, lzma2, ppmd, zstd, xz, lz4, brotli\n"
        "  -md SIZE            dictionary, like 64m or 1g\n"
        "  -mfb N              word size (fast bytes)\n"
        "  -mt N               threads (default: all cores)\n"
        "  -ms on|off|SIZE     solid (7z), or solid block size\n"
        "  -v SIZE             split into volumes of SIZE\n"
        "  -x PATTERN          exclude (repeatable)\n"
        "  --encrypt-names     encrypt file names too (7z)\n"
        "  --flat              extract without folders\n"
        "  -y                  assume yes: replace existing files\n");
}

std::uint64_t parse_size(const std::string &s)
{
    if (s.empty()) throw ra::Error(ra::ErrorCode::InvalidOption, "empty size");
    std::size_t pos = 0;
    double v = std::stod(s, &pos);
    std::uint64_t mul = 1;
    if (pos < s.size()) {
        switch (std::tolower(static_cast<unsigned char>(s[pos]))) {
        case 'k': mul = 1ull << 10; break;
        case 'm': mul = 1ull << 20; break;
        case 'g': mul = 1ull << 30; break;
        case 'b': break;
        default: throw ra::Error(ra::ErrorCode::InvalidOption, "bad size '" + s + "'");
        }
    }
    return std::uint64_t(v * double(mul));
}

std::string human(std::uint64_t n)
{
    const char *u[] = {"B", "KB", "MB", "GB", "TB"};
    double v = double(n);
    int i = 0;
    while (v >= 1024 && i < 4) { v /= 1024; ++i; }
    char buf[32];
    std::snprintf(buf, sizeof buf, i ? "%.1f %s" : "%.0f %s", v, u[i]);
    return buf;
}

std::optional<std::string> ask_password(const std::string &prompt)
{
    if (!isatty(STDIN_FILENO)) {
        std::string line;
        if (!std::getline(std::cin, line)) return std::nullopt;
        return line;
    }
    std::fprintf(stderr, "%s", prompt.c_str());
    termios old{}, quiet{};
    tcgetattr(STDIN_FILENO, &old);
    quiet = old;
    quiet.c_lflag &= ~tcflag_t(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
    std::string line;
    const bool ok = bool(std::getline(std::cin, line));
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    std::fprintf(stderr, "\n");
    if (!ok) return std::nullopt;
    return line;
}

struct Args {
    std::string cmd;
    fs::path archive;
    std::vector<std::string> files;
    fs::path out = ".";
    std::optional<std::string> password;
    bool ask_pw = false;
    ra::OverwriteMode overwrite = ra::OverwriteMode::Ask;
    ra::WriteOptions w;
    bool format_given = false;
    bool flat = false;
};

Args parse(int argc, char **argv)
{
    Args a;
    if (argc < 2) { usage(stderr); std::exit(2); }
    a.cmd = argv[1];
    if (a.cmd == "-h" || a.cmd == "--help") { usage(stdout); std::exit(0); }
    if (a.cmd == "--version") { std::printf("raye-archive %s\n", ra::version()); std::exit(0); }
    auto need = [&](int &i) -> std::string {
        if (i + 1 >= argc) throw ra::Error(ra::ErrorCode::InvalidOption, std::string(argv[i]) + " needs a value");
        return argv[++i];
    };
    for (int i = 2; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "-o") a.out = need(i);
        else if (s.rfind("-o", 0) == 0 && s.size() > 2 && s[2] != '-') a.out = s.substr(2);
        else if (s == "-p") a.ask_pw = true;
        else if (s.rfind("-p", 0) == 0 && s.size() > 2) a.password = s.substr(2);
        else if (s.rfind("--overwrite=", 0) == 0) {
            std::string m = s.substr(12);
            if (m == "ask") a.overwrite = ra::OverwriteMode::Ask;
            else if (m == "replace") a.overwrite = ra::OverwriteMode::Replace;
            else if (m == "skip") a.overwrite = ra::OverwriteMode::Skip;
            else if (m == "rename") a.overwrite = ra::OverwriteMode::KeepBoth;
            else if (m == "fail") a.overwrite = ra::OverwriteMode::Fail;
            else throw ra::Error(ra::ErrorCode::InvalidOption, "unknown overwrite mode '" + m + "'");
        } else if (s == "-y") a.overwrite = ra::OverwriteMode::Replace;
        else if (s == "-t") {
            auto f = ra::format_from_name(need(i));
            if (!f) throw ra::Error(ra::ErrorCode::InvalidOption, "unknown format '" + std::string(argv[i]) + "'");
            a.w.format = *f;
            a.format_given = true;
        } else if (s == "-mx") a.w.level = std::stoi(need(i));
        else if (s.rfind("-mx", 0) == 0 && s.size() > 3) a.w.level = std::stoi(s.substr(3));
        else if (s == "-mm") {
            auto m = ra::method_from_name(need(i));
            if (!m) throw ra::Error(ra::ErrorCode::InvalidOption, "unknown method '" + std::string(argv[i]) + "'");
            a.w.method = *m;
        } else if (s == "-md") a.w.dictionary = parse_size(need(i));
        else if (s == "-mfb") a.w.word_size = std::stoi(need(i));
        else if (s == "-mt") a.w.threads = std::stoi(need(i));
        else if (s == "-ms") {
            std::string v = need(i);
            if (v == "on") a.w.solid = true;
            else if (v == "off") a.w.solid = false;
            else { a.w.solid = true; a.w.solid_block_size = parse_size(v); }
        } else if (s == "-v") a.w.volume_size = parse_size(need(i));
        else if (s == "-x") a.w.exclude.push_back(need(i));
        else if (s == "--encrypt-names") a.w.encrypt_names = true;
        else if (s == "--flat") a.flat = true;
        else if (s.size() > 1 && s[0] == '-' && s != "-") throw ra::Error(ra::ErrorCode::InvalidOption, "unknown option " + s);
        else if (a.archive.empty()) a.archive = s;
        else a.files.push_back(s);
    }
    if (a.archive.empty()) throw ra::Error(ra::ErrorCode::InvalidOption, "no archive given");
    if (!a.format_given) {
        const std::string n = a.archive.filename().string();
        auto ends = [&](const char *x) { return n.size() >= std::strlen(x) && n.compare(n.size() - std::strlen(x), std::string::npos, x) == 0; };
        if (ends(".zip")) a.w.format = ra::Format::Zip;
        else if (ends(".tar")) a.w.format = ra::Format::Tar;
        else if (ends(".gz") || ends(".tgz")) a.w.format = ra::Format::Gzip;
        else if (ends(".xz") || ends(".txz")) a.w.format = ra::Format::Xz;
        else if (ends(".zst") || ends(".tzst")) a.w.format = ra::Format::Zstd;
        else if (ends(".bz2") || ends(".tbz2") || ends(".tbz")) a.w.format = ra::Format::Bzip2;
        else if (ends(".lz4")) a.w.format = ra::Format::Lz4;
        else if (ends(".lz") || ends(".tlz")) a.w.format = ra::Format::Lzip;
        else if (ends(".lzma")) a.w.format = ra::Format::Lzma;
        else if (ends(".br")) a.w.format = ra::Format::Brotli;
    }
    return a;
}

ra::Callbacks make_callbacks(Args &a, ra::Control &ctl)
{
    ra::Callbacks cb;
    cb.control = &ctl;
    const std::string name = a.archive.filename().string();
    cb.password = [a](const ra::PasswordRequest &r) -> std::optional<std::string> {
        std::string p = r.attempt > 1 ? "Wrong password. Try again: " : "Password for " + r.archive + ": ";
        return ask_password(p);
    };
    if (isatty(STDERR_FILENO)) {
        cb.progress = [](const ra::Progress &p) {
            if (!p.bytes_total) return;
            const int pct = int(100.0 * double(p.bytes_done) / double(p.bytes_total));
            std::fprintf(stderr, "\r%3d%%  %s/s  %-50.50s", pct, human(std::uint64_t(p.bytes_per_second)).c_str(), p.current.c_str());
        };
    }
    if (a.overwrite == ra::OverwriteMode::Ask && isatty(STDIN_FILENO)) {
        cb.conflict = [](const ra::Conflict &c) {
            std::fprintf(stderr, "\n%s already exists. [r]eplace, [s]kip, [k]eep both, [R/S/K] for all, [c]ancel? ",
                         c.destination.c_str());
            std::string l;
            std::getline(std::cin, l);
            char ch = l.empty() ? 'c' : l[0];
            switch (ch) {
            case 'r': return ra::ConflictChoice::Replace;
            case 's': return ra::ConflictChoice::Skip;
            case 'k': return ra::ConflictChoice::KeepBoth;
            case 'R': return ra::ConflictChoice::ReplaceAll;
            case 'S': return ra::ConflictChoice::SkipAll;
            case 'K': return ra::ConflictChoice::KeepBothAll;
            default: return ra::ConflictChoice::Cancel;
            }
        };
    }
    return cb;
}

std::string time_str(const std::optional<ra::Timestamp> &t)
{
    if (!t) return "                   ";
    std::time_t s = std::time_t(t->seconds);
    std::tm tm{};
    localtime_r(&s, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

int list(Args &a, ra::Callbacks &cb)
{
    auto ar = ra::Archive::open(a.archive, ra::OpenOptions{a.password, {}, cb});
    const auto &info = ar.info();
    std::printf("Archive: %s\nFormat:  %s%s%s\n", a.archive.c_str(), ra::format_name(info.format),
                info.detail.empty() ? "" : ", ", info.detail.c_str());
    if (info.volume_count > 1) std::printf("Volumes: %zu\n", info.volume_count);
    std::printf("\n%-19s %5s %14s %14s  %s\n", "Modified", "Attr", "Size", "Packed", "Name");
    std::uint64_t total = 0, packed = 0;
    std::size_t files = 0, dirs = 0;
    for (const auto &e : ar.entries()) {
        const char attr[] = {e.type == ra::EntryType::Directory ? 'D' : e.type == ra::EntryType::Symlink ? 'L' : '.',
                             e.encrypted ? '*' : '.', e.solid ? 'S' : '.', '.', '.', 0};
        std::printf("%s %5s %14llu %14llu  %s%s%s\n", time_str(e.mtime).c_str(), attr,
                    static_cast<unsigned long long>(e.size), static_cast<unsigned long long>(e.packed_size), e.path.c_str(),
                    e.link_target.empty() ? "" : " -> ", e.link_target.c_str());
        if (e.type == ra::EntryType::Directory) ++dirs;
        else ++files;
        total += e.size;
        packed += e.packed_size;
    }
    std::printf("\n%zu files, %zu folders, %s (%s packed)\n", files, dirs, human(total).c_str(), human(packed).c_str());
    return 0;
}

} // namespace

int main(int argc, char **argv)
{
    try {
        Args a = parse(argc, argv);
        if (a.ask_pw) a.password = ask_password("Password: ");
        ra::Control ctl;
        ra::Callbacks cb = make_callbacks(a, ctl);

        if (a.cmd == "i") {
            for (auto &d : [&] { auto s = ra::open_file_source(a.archive); return ra::detect_all(*s, a.archive.filename().string()); }())
                std::printf("%-6s score %3d  offset %llu%s%s\n", ra::format_name(d.format), d.score,
                            static_cast<unsigned long long>(d.offset), d.detail.empty() ? "" : "  ", d.detail.c_str());
            return 0;
        }
        if (a.cmd == "l") return list(a, cb);
        if (a.cmd == "x" || a.cmd == "e") {
            ra::ExtractOptions o;
            o.overwrite = a.overwrite;
            o.password = a.password;
            o.flat = a.flat || a.cmd == "e";
            auto ar = ra::Archive::open(a.archive, ra::OpenOptions{a.password, {}, cb});
            if (a.files.empty()) {
                ar.extract_all(a.out, o, cb);
            } else {
                std::vector<std::size_t> sel;
                for (const auto &e : ar.entries())
                    for (const auto &f : a.files)
                        if (e.path == f || e.path.rfind(f + "/", 0) == 0) { sel.push_back(e.index); break; }
                if (sel.empty()) throw ra::Error(ra::ErrorCode::NotFound, "nothing in the archive matches");
                ar.extract(sel, a.out, o, cb);
            }
            if (cb.progress) std::fprintf(stderr, "\n");
            std::printf("Everything is extracted to %s\n", a.out.c_str());
            return 0;
        }
        if (a.cmd == "t") {
            ra::ExtractOptions o;
            o.password = a.password;
            auto ar = ra::Archive::open(a.archive, ra::OpenOptions{a.password, {}, cb});
            auto r = ar.test(o, cb);
            if (cb.progress) std::fprintf(stderr, "\n");
            for (auto &[p, e] : r.failures) std::printf("FAILED  %s: %s\n", p.empty() ? "(archive)" : p.c_str(), e.message().c_str());
            std::printf("%zu entries OK, %zu failed\n", r.entries_ok, r.failures.size());
            return r.ok() ? 0 : 1;
        }
        if (a.cmd == "a" || a.cmd == "u" || a.cmd == "s") {
            if (a.files.empty()) throw ra::Error(ra::ErrorCode::InvalidOption, "nothing to add");
            std::vector<ra::InputItem> items;
            for (auto &f : a.files) items.push_back({f, {}});
            a.w.password = a.password;
            if (a.cmd == "a") ra::add(a.archive, items, a.w, cb);
            else if (a.cmd == "u") ra::update(a.archive, items, a.w, cb);
            else ra::sync(a.archive, items, a.w, cb);
            if (cb.progress) std::fprintf(stderr, "\n");
            return 0;
        }
        if (a.cmd == "d") {
            if (a.files.empty()) throw ra::Error(ra::ErrorCode::InvalidOption, "nothing to delete");
            a.w.password = a.password;
            ra::remove(a.archive, a.files, a.w, cb);
            return 0;
        }
        usage(stderr);
        return 2;
    } catch (const ra::Error &e) {
        std::fprintf(stderr, "\nraye-archive: %s (%s)\n", e.what(), ra::error_code_name(e.code()));
        return e.code() == ra::ErrorCode::InvalidOption ? 2 : e.code() == ra::ErrorCode::Cancelled ? 130 : 1;
    } catch (const std::exception &e) {
        std::fprintf(stderr, "\nraye-archive: %s\n", e.what());
        return 1;
    }
}
