// SPDX-License-Identifier: GPL-3.0-or-later
#include "driver.h"

#include "../formats/formats.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>

namespace raye::archive::detail {

namespace {
std::vector<std::unique_ptr<Driver>> &table()
{
    static std::vector<std::unique_ptr<Driver>> t;
    return t;
}
std::once_flag g_once;
} // namespace

void register_driver(std::unique_ptr<Driver> d) { table().push_back(std::move(d)); }

const std::vector<std::unique_ptr<Driver>> &drivers()
{
    std::call_once(g_once, register_all_formats);
    return table();
}

const Driver *driver_for(Format f)
{
    for (const auto &d : drivers())
        if (d->format() == f) return d.get();
    return nullptr;
}

std::unique_ptr<ReaderImpl> Driver::open(const OpenRequest &, Context &) const
{
    fail(ErrorCode::NotImplemented, std::string(format_name(format())) + " reading is not ready yet");
}

std::unique_ptr<WriterImpl> Driver::writer() const
{
    fail(ErrorCode::NotImplemented, std::string(format_name(format())) + " writing is not ready yet");
}

bool has_executable_stub(std::span<const std::uint8_t> h)
{
    return (h.size() >= 2 && h[0] == 'M' && h[1] == 'Z') ||
           (h.size() >= 4 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F');
}

std::optional<std::uint64_t> find_after_stub(std::span<const std::uint8_t> h, std::span<const std::uint8_t> sig)
{
    if (!has_executable_stub(h) || sig.empty()) return std::nullopt;
    auto it = std::search(h.begin() + 1, h.end(), sig.begin(), sig.end());
    if (it == h.end()) return std::nullopt;
    return std::uint64_t(it - h.begin());
}

bool name_ends_with(std::string_view name, std::string_view suffix)
{
    if (suffix.size() > name.size()) return false;
    auto tail = name.substr(name.size() - suffix.size());
    for (std::size_t i = 0; i < suffix.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(tail[i])) != std::tolower(static_cast<unsigned char>(suffix[i])))
            return false;
    return true;
}

} // namespace raye::archive::detail
