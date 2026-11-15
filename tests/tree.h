// SPDX-License-Identifier: GPL-3.0-or-later
// Hash of a folder tree, same rules as tests/tree_hash.py: lines
// "D path", "F path sha256", "L path target", sorted by path, then sha256.
#pragma once

#include "core/crypto.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace check {

inline std::string hex(const std::uint8_t *d, std::size_t n)
{
    static const char *h = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < n; ++i) { s += h[d[i] >> 4]; s += h[d[i] & 15]; }
    return s;
}

inline std::string file_sha256(const std::filesystem::path &p)
{
    raye::archive::detail::Sha256 h;
    std::ifstream f(p, std::ios::binary);
    std::vector<char> buf(1 << 16);
    while (f) {
        f.read(buf.data(), std::streamsize(buf.size()));
        h.update(buf.data(), std::size_t(f.gcount()));
    }
    auto d = h.final();
    return hex(d.data(), d.size());
}

inline std::string tree_hash(const std::filesystem::path &root)
{
    namespace fs = std::filesystem;
    std::vector<std::pair<std::string, std::string>> lines;
    for (auto it = fs::recursive_directory_iterator(root); it != fs::recursive_directory_iterator(); ++it) {
        const std::string rel = it->path().lexically_relative(root).generic_string();
        if (it->is_symlink()) lines.emplace_back(rel, "L " + rel + " " + fs::read_symlink(it->path()).string());
        else if (it->is_directory()) lines.emplace_back(rel, "D " + rel);
        else lines.emplace_back(rel, "F " + rel + " " + file_sha256(it->path()));
    }
    std::sort(lines.begin(), lines.end());
    std::string all;
    for (auto &l : lines) all += l.second + "\n";
    std::uint8_t d[32];
    raye::archive::detail::sha256(all.data(), all.size(), d);
    return hex(d, 32);
}

} // namespace check
