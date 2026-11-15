// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../core/driver.h"
#include "../formats.h"
#include "reader.h"
#include "writer.h"

using namespace std::literals;

namespace raye::archive::detail {

namespace {

constexpr auto kSig = "7z\xbc\xaf\x27\x1c"sv;

class SevenZipDriver final : public SimpleDriver {
public:
    SevenZipDriver() : SimpleDriver(Format::SevenZip, {".7z", ".7z.001"}) {}

    std::optional<Detection> probe(const ProbeInput &in) const override
    {
        if (has_at(in.head, 0, kSig)) return Detection{Format::SevenZip, 100, 0, false, {}};
        const std::span<const std::uint8_t> sig(reinterpret_cast<const std::uint8_t *>(kSig.data()), kSig.size());
        if (auto off = find_after_stub(in.head, sig)) return Detection{Format::SevenZip, 90, *off, true, "self-extracting"};
        return std::nullopt;
    }

    std::unique_ptr<ReaderImpl> open(const OpenRequest &req, Context &ctx) const override
    {
        return std::make_unique<sevenz::Reader>(req, ctx);
    }
    bool can_write() const override { return true; }
    std::unique_ptr<WriterImpl> writer() const override { return sevenz::make_writer(); }
};

} // namespace

void register_7z_formats() { register_driver(std::make_unique<SevenZipDriver>()); }

} // namespace raye::archive::detail
