// SPDX-License-Identifier: GPL-3.0-or-later
#include <raye/archive/format.h>
#include <raye/archive/io.h>

#include "driver.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <regex>

namespace raye::archive {

namespace {
struct Name { Format f; const char *name; };
constexpr std::array kNames = {
    Name{Format::Zip, "zip"},     Name{Format::SevenZip, "7z"},  Name{Format::Rar, "rar"},
    Name{Format::Rar5, "rar5"},   Name{Format::Tar, "tar"},      Name{Format::Gzip, "gz"},
    Name{Format::Bzip2, "bz2"},   Name{Format::Xz, "xz"},        Name{Format::Lzma, "lzma"},
    Name{Format::Zstd, "zst"},    Name{Format::Lz4, "lz4"},      Name{Format::Lzip, "lz"},
    Name{Format::Brotli, "br"},   Name{Format::Compress, "Z"},   Name{Format::Iso9660, "iso"},
    Name{Format::Udf, "udf"},     Name{Format::Cab, "cab"},      Name{Format::Cpio, "cpio"},
    Name{Format::Ar, "ar"},       Name{Format::Rpm, "rpm"},      Name{Format::Arj, "arj"},
    Name{Format::Lzh, "lzh"},
};
std::string lower(std::string_view s)
{
    std::string r(s);
    for (auto &c : r) c = char(std::tolower(static_cast<unsigned char>(c)));
    return r;
}
} // namespace

const char *format_name(Format f) noexcept
{
    for (auto &n : kNames)
        if (n.f == f) return n.name;
    return "unknown";
}

std::optional<Format> format_from_name(std::string_view s) noexcept
{
    const std::string l = lower(s);
    for (auto &n : kNames)
        if (l == lower(n.name)) return n.f;
    static const std::pair<const char *, Format> aliases[] = {
        {"7zip", Format::SevenZip}, {"sevenzip", Format::SevenZip}, {"gzip", Format::Gzip},
        {"bzip2", Format::Bzip2}, {"zstd", Format::Zstd}, {"lzip", Format::Lzip}, {"brotli", Format::Brotli},
        {"tgz", Format::Gzip}, {"txz", Format::Xz}, {"tbz2", Format::Bzip2}, {"deb", Format::Ar},
        {"jar", Format::Zip}, {"z", Format::Compress},
    };
    for (auto &[a, f] : aliases)
        if (l == a) return f;
    return std::nullopt;
}

bool format_can_write(Format f) noexcept
{
    if (f == Format::Rar || f == Format::Rar5 || f == Format::Unknown) return false;
    const auto *d = detail::driver_for(f);
    return d && d->can_write();
}

std::vector<Detection> detect_all(Source &src, std::string_view name)
{
    const std::uint64_t size = src.size();
    std::vector<std::uint8_t> head(std::min<std::uint64_t>(size, detail::kProbeHead));
    std::vector<std::uint8_t> tail(std::min<std::uint64_t>(size, detail::kProbeTail));
    src.read_exact(0, head.data(), head.size());
    src.read_exact(size - tail.size(), tail.data(), tail.size());
    detail::ProbeInput in{src, size, head, tail, name};

    std::vector<Detection> out;
    for (const auto &d : detail::drivers()) {
        auto r = d->probe(in);
        if (!r || r->score <= 0) continue;
        r->format = d->format();
        // The extension only breaks ties, it never makes a format.
        for (const auto &ext : d->extensions())
            if (detail::name_ends_with(name, ext)) { r->score += 1; break; }
        out.push_back(*r);
    }
    std::stable_sort(out.begin(), out.end(), [](const Detection &a, const Detection &b) {
        if (a.score != b.score) return a.score > b.score;
        return a.offset < b.offset;
    });
    return out;
}

Detection detect(Source &src, std::string_view name)
{
    auto all = detect_all(src, name);
    return all.empty() ? Detection{} : all.front();
}

Detection detect(const std::filesystem::path &path)
{
    auto src = open_file_source(path);
    return detect(*src, path.filename().string());
}

// ---------------------------------------------------------------- volumes

namespace {
namespace fs = std::filesystem;

std::string pad(unsigned n, std::size_t width)
{
    std::string s = std::to_string(n);
    return s.size() >= width ? s : std::string(width - s.size(), '0') + s;
}

bool is_file(const fs::path &p)
{
    std::error_code ec;
    return fs::is_regular_file(p, ec);
}

// Collects base+fmt(i) for i = first.. while the files exist.
template <class F> std::vector<fs::path> collect(unsigned first, F name_of)
{
    std::vector<fs::path> v;
    for (unsigned i = first; i < 100000; ++i) {
        fs::path p = name_of(i);
        if (!is_file(p)) break;
        v.push_back(p);
    }
    return v;
}
} // namespace

VolumeSet find_volumes(const fs::path &any)
{
    VolumeSet set;
    const fs::path dir = any.parent_path();
    const std::string file = any.filename().string();
    const std::string lf = lower(file);
    std::smatch m;

    // name.part1.rar / name.part001.rar (RAR 3+ naming)
    static const std::regex rar_new(R"(^(.*)\.part([0-9]+)\.rar$)", std::regex::icase);
    if (std::regex_match(file, m, rar_new)) {
        const std::string base = m[1];
        const std::size_t width = m[2].length();
        const std::string ext = file.substr(file.size() - 4);
        set.kind = VolumeSet::Kind::RarNew;
        set.volumes = collect(1, [&](unsigned i) { return dir / (base + ".part" + pad(i, width) + ext); });
        if (set.volumes.empty() || set.volumes.front().filename() != fs::path(base + ".part" + pad(1, width) + ext))
            set.complete = false;
        if (set.volumes.empty()) set.volumes.push_back(any);
        return set;
    }

    // name.7z.001, name.zip.001, name.001 (plain split, concatenate)
    static const std::regex split(R"(^(.*)\.([0-9]{3,})$)");
    if (std::regex_match(file, m, split)) {
        const std::string base = m[1];
        const std::size_t width = m[2].length();
        set.kind = VolumeSet::Kind::Split;
        set.volumes = collect(1, [&](unsigned i) { return dir / (base + "." + pad(i, width)); });
        if (set.volumes.empty()) { set.volumes.push_back(any); set.complete = false; }
        return set;
    }

    // name.rar + name.r00, name.r01 ... (RAR 2 naming) or name.s00 for SFX
    static const std::regex rar_old(R"(^(.*)\.(rar|r[0-9]{2}|[s-z][0-9]{2})$)", std::regex::icase);
    if (std::regex_match(file, m, rar_old)) {
        const std::string base = m[1];
        const bool upper = std::isupper(static_cast<unsigned char>(m[2].str()[0]));
        const fs::path rar = dir / (base + (upper ? ".RAR" : ".rar"));
        auto rN = [&](unsigned i) {
            // .r00-.r99, then .s00-.s99 ...
            char letter = char((upper ? 'R' : 'r') + i / 100);
            return dir / (base + "." + letter + pad(i % 100, 2));
        };
        if (is_file(rar) && is_file(rN(0))) {
            set.kind = VolumeSet::Kind::RarOld;
            set.volumes.push_back(rar);
            for (auto &p : collect(0, rN)) set.volumes.push_back(p);
            return set;
        }
    }

    // name.z01, name.z02 ... name.zip (split ZIP, the .zip is the LAST part)
    static const std::regex zsplit(R"(^(.*)\.(zip|z[0-9]{2,})$)", std::regex::icase);
    if (std::regex_match(file, m, zsplit)) {
        const std::string base = m[1];
        auto zN = [&](unsigned i) { return dir / (base + ".z" + pad(i, 2)); };
        if (is_file(zN(1))) {
            set.kind = VolumeSet::Kind::ZipSplit;
            set.volumes = collect(1, zN);
            const fs::path last = dir / (base + ".zip");
            if (is_file(last)) set.volumes.push_back(last);
            else set.complete = false;
            return set;
        }
    }

    set.volumes.push_back(any);
    return set;
}

} // namespace raye::archive
