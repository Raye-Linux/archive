// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../core/driver.h"
#include "../formats.h"

#include "../../core/bytes.h"
#include "readers.h"

using namespace std::literals;

namespace raye::archive::detail {

namespace {

class OtherDriver final : public SimpleDriver {
public:
    using Probe = std::optional<Detection> (*)(const ProbeInput &);
    using Open = std::unique_ptr<ReaderImpl> (*)(const OpenRequest &);
    OtherDriver(Format f, std::vector<std::string> ext, Probe p, Open o = nullptr)
        : SimpleDriver(f, std::move(ext)), p_(p), o_(o) {}
    std::optional<Detection> probe(const ProbeInput &in) const override { return p_(in); }
    std::unique_ptr<ReaderImpl> open(const OpenRequest &req, Context &ctx) const override
    {
        return o_ ? o_(req) : Driver::open(req, ctx);
    }

private:
    Probe p_;
    Open o_;
};

std::optional<Detection> hit(Format f, int score, std::string detail = {}) { return Detection{f, score, 0, false, std::move(detail)}; }

std::optional<Detection> probe_iso(const ProbeInput &in)
{
    // Volume descriptors start at sector 16; "CD001" sits one byte in.
    for (std::size_t s = 16; s < 32; ++s) {
        const std::size_t off = s * 2048 + 1;
        if (has_at(in.head, off, "CD001"sv)) return hit(Format::Iso9660, 95);
    }
    return std::nullopt;
}

std::optional<Detection> probe_udf(const ProbeInput &in)
{
    for (std::size_t s = 16; s < 32; ++s)
        if (has_at(in.head, s * 2048 + 1, "NSR02"sv) || has_at(in.head, s * 2048 + 1, "NSR03"sv))
            return hit(Format::Udf, 96); // beats the ISO bridge descriptor
    return std::nullopt;
}

std::optional<Detection> probe_cab(const ProbeInput &in)
{
    if (!has_at(in.head, 0, "MSCF\0\0\0\0"sv)) {
        static const std::uint8_t sig[] = {'M', 'S', 'C', 'F', 0, 0, 0, 0};
        if (auto off = find_after_stub(in.head, sig)) return Detection{Format::Cab, 85, *off, true, "self-extracting"};
        return std::nullopt;
    }
    return hit(Format::Cab, 100);
}

std::optional<Detection> probe_cpio(const ProbeInput &in)
{
    if (has_at(in.head, 0, "070701"sv) || has_at(in.head, 0, "070702"sv)) return hit(Format::Cpio, 95, "newc");
    if (has_at(in.head, 0, "070707"sv)) return hit(Format::Cpio, 95, "odc");
    if (in.head.size() >= 2 && ((in.head[0] == 0xc7 && in.head[1] == 0x71) || (in.head[0] == 0x71 && in.head[1] == 0xc7)))
        return hit(Format::Cpio, 60, "binary");
    return std::nullopt;
}

std::optional<Detection> probe_ar(const ProbeInput &in)
{
    if (!has_at(in.head, 0, "!<arch>\n"sv)) return std::nullopt;
    return hit(Format::Ar, 100, has_at(in.head, 8, "debian-binary"sv) ? "deb" : "");
}

std::optional<Detection> probe_rpm(const ProbeInput &in)
{
    if (has_at(in.head, 0, "\xed\xab\xee\xdb"sv)) return hit(Format::Rpm, 100);
    return std::nullopt;
}

std::optional<Detection> probe_arj(const ProbeInput &in)
{
    if (in.head.size() < 4 || in.head[0] != 0x60 || in.head[1] != 0xea) return std::nullopt;
    const std::uint16_t hsize = le16(&in.head[2]);
    if (hsize == 0 || hsize > 2600) return std::nullopt;
    return hit(Format::Arj, 80);
}

std::optional<Detection> probe_lzh(const ProbeInput &in)
{
    if (in.head.size() < 7 || in.head[2] != '-' || in.head[6] != '-') return std::nullopt;
    if (in.head[3] != 'l' || (in.head[4] != 'h' && in.head[4] != 'z')) return std::nullopt;
    return hit(Format::Lzh, 80);
}

} // namespace

void register_other_formats()
{
    register_driver(std::make_unique<OtherDriver>(Format::Iso9660, std::vector<std::string>{".iso"}, probe_iso, open_iso));
    register_driver(std::make_unique<OtherDriver>(Format::Udf, std::vector<std::string>{".iso", ".udf"}, probe_udf));
    register_driver(std::make_unique<OtherDriver>(Format::Cab, std::vector<std::string>{".cab"}, probe_cab, open_cab));
    register_driver(std::make_unique<OtherDriver>(Format::Cpio, std::vector<std::string>{".cpio"}, probe_cpio, open_cpio));
    register_driver(std::make_unique<OtherDriver>(Format::Ar, std::vector<std::string>{".a", ".ar", ".deb", ".ipk"}, probe_ar, open_ar));
    register_driver(std::make_unique<OtherDriver>(Format::Rpm, std::vector<std::string>{".rpm"}, probe_rpm, open_rpm));
    register_driver(std::make_unique<OtherDriver>(Format::Arj, std::vector<std::string>{".arj"}, probe_arj));
    register_driver(std::make_unique<OtherDriver>(Format::Lzh, std::vector<std::string>{".lzh", ".lha"}, probe_lzh));
}

} // namespace raye::archive::detail
