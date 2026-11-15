// SPDX-License-Identifier: GPL-3.0-or-later
// Reading only: RAR archives are never created.
#include "../../core/driver.h"
#include "../formats.h"
#include "../../core/bytes.h"
#include "../../core/checksum.h"

#include <algorithm>
#include <cstring>

using namespace std::literals;

namespace raye::archive::detail {

namespace rar {
std::unique_ptr<ReaderImpl> open_rar(const OpenRequest &req, Context &ctx, bool rar5);
}

namespace {

constexpr auto kRar4 = "Rar!\x1a\x07\x00"sv;
constexpr auto kRar5 = "Rar!\x1a\x07\x01\x00"sv;
constexpr auto kRar14 = "RE~^"sv; // RAR 1.4

std::span<const std::uint8_t> bytes(std::string_view s)
{
    return {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()};
}

class RarDriver final : public SimpleDriver {
public:
    RarDriver(Format f, std::string_view sig) : SimpleDriver(f, {".rar", ".r00", ".part1.rar", ".exe"}), sig_(sig) {}

    std::optional<Detection> probe(const ProbeInput &in) const override
    {
        const char *what = format() == Format::Rar5 ? "RAR 5.0" : "RAR 1.5-4.x";
        if (has_at(in.head, 0, sig_)) return Detection{format(), 100, 0, false, what};
        if (format() == Format::Rar && has_at(in.head, 0, kRar14)) return Detection{format(), 100, 0, false, "RAR 1.4"};
        if (auto off = find_after_stub(in.head, bytes(sig_)))
            return Detection{format(), 90, *off, true, std::string(what) + ", self-extracting"};
        // Some self-extractors pad the stub with something that is not an
        // executable header: accept a signature followed by a valid header.
        const auto sig = bytes(sig_);
        for (auto it = in.head.begin() + 1; (it = std::search(it, in.head.end(), sig.begin(), sig.end())) != in.head.end(); ++it) {
            const std::size_t off = std::size_t(it - in.head.begin());
            if (valid_header(in.head, off + sig.size()))
                return Detection{format(), 70, off, true, std::string(what) + ", self-extracting"};
        }
        return std::nullopt;
    }

    std::unique_ptr<ReaderImpl> open(const OpenRequest &req, Context &ctx) const override
    {
        std::uint8_t head[4] = {};
        req.source->read_at(req.detection.offset, head, 4);
        if (std::memcmp(head, "RE~^", 4) == 0)
            fail(ErrorCode::UnsupportedMethod, "RAR 1.4 archives are not supported", req.name);
        return rar::open_rar(req, ctx, format() == Format::Rar5);
    }

private:
    bool valid_header(std::span<const std::uint8_t> h, std::size_t p) const
    {
        if (format() == Format::Rar) {
            if (p + 13 > h.size() || h[p + 2] != 0x73) return false;
            const std::size_t size = le16(&h[p + 5]);
            return size >= 13 && p + size <= h.size() && (crc32(0, &h[p + 2], size - 2) & 0xffff) == le16(&h[p]);
        }
        if (p + 6 > h.size()) return false;
        ByteReader r(h.subspan(p + 4, std::min<std::size_t>(h.size() - p - 4, 3)));
        std::uint64_t size = 0;
        try { size = r.vint(); } catch (const Error &) { return false; }
        const std::size_t total = 4 + r.pos() + std::size_t(size);
        return size > 0 && size < 4096 && p + total <= h.size() && crc32(0, &h[p + 4], total - 4) == le32(&h[p]);
    }

    std::string_view sig_;
};

} // namespace

void register_rar_formats()
{
    register_driver(std::make_unique<RarDriver>(Format::Rar, kRar4));
    register_driver(std::make_unique<RarDriver>(Format::Rar5, kRar5));
}

} // namespace raye::archive::detail
