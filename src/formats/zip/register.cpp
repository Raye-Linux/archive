// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../core/driver.h"
#include "../formats.h"

#include "../../core/bytes.h"
#include "reader.h"
#include "writer.h"

using namespace std::literals;

namespace raye::archive::detail {

namespace {

class ZipDriver final : public SimpleDriver {
public:
    ZipDriver() : SimpleDriver(Format::Zip, {".zip", ".zipx", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".epub", ".z01"}) {}

    std::optional<Detection> probe(const ProbeInput &in) const override
    {
        if (has_at(in.head, 0, "PK\x03\x04"sv) || has_at(in.head, 0, "PK\x07\x08PK\x03\x04"sv))
            return Detection{Format::Zip, 100, 0, false, {}};
        if (has_at(in.head, 0, "PK\x05\x06"sv)) return Detection{Format::Zip, 95, 0, false, "empty"};
        // Self-extracting or with a prefix: the end record is near the end.
        for (std::size_t i = in.tail.size() >= 22 ? in.tail.size() - 21 : 0; i-- > 0;) {
            if (!has_at(in.tail, i, "PK\x05\x06"sv)) continue;
            const std::uint16_t comment = le16(&in.tail[i + 20]);
            if (i + 22 + comment != in.tail.size()) continue;
            const bool sfx = has_executable_stub(in.head);
            return Detection{Format::Zip, sfx ? 90 : 70, 0, sfx, sfx ? "self-extracting" : "with a prefix"};
        }
        return std::nullopt;
    }

    std::unique_ptr<ReaderImpl> open(const OpenRequest &req, Context &ctx) const override
    {
        return std::make_unique<zip::ZipReader>(req, ctx);
    }
    bool can_write() const override { return zip::writer_ready; }
    std::unique_ptr<WriterImpl> writer() const override { return zip::make_writer(); }
};

} // namespace

void register_zip_formats() { register_driver(std::make_unique<ZipDriver>()); }

} // namespace raye::archive::detail
