// SPDX-License-Identifier: GPL-3.0-or-later
// tar and the single-stream compressors. A .tar.gz is detected as Gzip; its
// reader looks inside and lists the tar entries when the stream holds a tar.
#include "../../core/driver.h"
#include "../formats.h"

#include "../../core/bytes.h"
#include "tario.h"

using namespace std::literals;

namespace raye::archive::detail {

namespace {

// Old (v7) tar has no magic: the header checksum is the only proof.
bool tar_checksum_ok(std::span<const std::uint8_t> h)
{
    if (h.size() < 512) return false;
    unsigned stored = 0;
    bool digit = false;
    for (int i = 148; i < 156; ++i) {
        const auto c = h[std::size_t(i)];
        if (c >= '0' && c <= '7') { stored = stored * 8 + unsigned(c - '0'); digit = true; }
        else if (c != ' ' && c != 0) return false;
    }
    if (!digit) return false;
    unsigned sum = 0;
    for (int i = 0; i < 512; ++i) sum += (i >= 148 && i < 156) ? ' ' : h[std::size_t(i)];
    return sum == stored && h[0] != 0;
}

class TarDriver final : public SimpleDriver {
public:
    TarDriver() : SimpleDriver(Format::Tar, {".tar"}) {}
    std::optional<Detection> probe(const ProbeInput &in) const override
    {
        if (has_at(in.head, 257, "ustar"sv) && tar_checksum_ok(in.head)) return Detection{Format::Tar, 95, 0, false, {}};
        if (tar_checksum_ok(in.head)) return Detection{Format::Tar, 60, 0, false, "v7"};
        return std::nullopt;
    }
    std::unique_ptr<ReaderImpl> open(const OpenRequest &req, Context &ctx) const override
    {
        return open_tar_family(req, format(), ctx);
    }
    bool can_write() const override { return true; }
    std::unique_ptr<WriterImpl> writer() const override { return std::make_unique<TarWriter>(format()); }
};

struct Magic { Format f; std::string_view sig; std::vector<std::string> ext; };

class StreamDriver final : public SimpleDriver {
public:
    StreamDriver(Format f, std::string_view sig, std::vector<std::string> ext) : SimpleDriver(f, std::move(ext)), sig_(sig) {}
    std::optional<Detection> probe(const ProbeInput &in) const override
    {
        if (format() == Format::Brotli) { // no magic at all
            for (auto &e : extensions())
                if (name_ends_with(in.name, e)) return Detection{format(), 20, 0, false, "by name"};
            return std::nullopt;
        }
        if (format() == Format::Lzma) return probe_lzma(in);
        if (!has_at(in.head, 0, sig_)) return std::nullopt;
        if (format() == Format::Bzip2 && !(in.head.size() > 3 && in.head[3] >= '1' && in.head[3] <= '9')) return std::nullopt;
        return Detection{format(), 90, 0, false, {}};
    }
    std::unique_ptr<ReaderImpl> open(const OpenRequest &req, Context &ctx) const override
    {
        return open_tar_family(req, format(), ctx);
    }
    bool can_write() const override { return format() != Format::Compress; }
    std::unique_ptr<WriterImpl> writer() const override { return std::make_unique<TarWriter>(format()); }

private:
    // .lzma: props byte (lc/lp/pb) < 225, dictionary a sane size, then a size or -1.
    std::optional<Detection> probe_lzma(const ProbeInput &in) const
    {
        if (in.head.size() < 13 || in.head[0] >= 225) return std::nullopt;
        const std::uint32_t dict = le32(&in.head[1]);
        const std::uint64_t usize = le64(&in.head[5]);
        const bool pow2ish = (dict & (dict - 1)) == 0 || (dict & (dict - 1) & (dict - 2)) == 0 || dict == 0xffffffffu;
        if (!pow2ish || dict < 4096) return std::nullopt;
        if (usize != UINT64_MAX && usize > (1ull << 48)) return std::nullopt;
        const bool named = name_ends_with(in.name, ".lzma") || name_ends_with(in.name, ".tlz");
        return Detection{format(), named ? 50 : 15, 0, false, {}};
    }
    std::string_view sig_;
};

} // namespace

void register_tar_formats()
{
    register_driver(std::make_unique<TarDriver>());
    register_driver(std::make_unique<StreamDriver>(Format::Gzip, "\x1f\x8b"sv, std::vector<std::string>{".gz", ".tgz"}));
    register_driver(std::make_unique<StreamDriver>(Format::Bzip2, "BZh"sv, std::vector<std::string>{".bz2", ".tbz2", ".tbz"}));
    register_driver(std::make_unique<StreamDriver>(Format::Xz, "\xfd" "7zXZ\x00"sv, std::vector<std::string>{".xz", ".txz"}));
    register_driver(std::make_unique<StreamDriver>(Format::Lzma, ""sv, std::vector<std::string>{".lzma", ".tlz"}));
    register_driver(std::make_unique<StreamDriver>(Format::Zstd, "\x28\xb5\x2f\xfd"sv, std::vector<std::string>{".zst", ".tzst"}));
    register_driver(std::make_unique<StreamDriver>(Format::Lz4, "\x04\x22\x4d\x18"sv, std::vector<std::string>{".lz4"}));
    register_driver(std::make_unique<StreamDriver>(Format::Lzip, "LZIP"sv, std::vector<std::string>{".lz"}));
    register_driver(std::make_unique<StreamDriver>(Format::Brotli, ""sv, std::vector<std::string>{".br"}));
    register_driver(std::make_unique<StreamDriver>(Format::Compress, "\x1f\x9d"sv, std::vector<std::string>{".Z", ".taz"}));
}

} // namespace raye::archive::detail
