// SPDX-License-Identifier: GPL-3.0-or-later
// ZIP reader only (force_format), plus the Deflate64 decoder on raw bytes.
#include "formats/zip/zip.h"

#include <raye/archive/archive.h>

using namespace raye::archive;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    try {
        OpenOptions oo;
        oo.password = "raye";
        oo.force_format = Format::Zip;
        auto a = Archive::open(memory_source(std::vector<std::uint8_t>(data, data + size), "fuzz.zip"), oo);
        ExtractOptions eo;
        eo.threads = 1;
        (void)a.test(eo);
    } catch (const Error &) {
    }
    try {
        auto d = detail::zip::make_deflate64_decoder();
        std::vector<std::uint8_t> out(4096);
        std::size_t pos = 0, total = 0;
        while (total < (8u << 20)) {
            auto s = d->step(std::span(data + pos, size - pos), out, true);
            pos += s.consumed;
            total += s.produced;
            if (s.done || (!s.consumed && !s.produced)) break;
        }
    } catch (const Error &) {
    }
    return 0;
}
