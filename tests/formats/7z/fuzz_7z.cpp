// SPDX-License-Identifier: GPL-3.0-or-later
// libFuzzer target for the 7z reader alone: detection is skipped, so every
// input goes straight to the header parser and the decoders.
#include <raye/archive/archive.h>

#include <cstddef>
#include <cstdint>

using namespace raye::archive;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    std::shared_ptr<Source> src = memory_source(std::vector<std::uint8_t>(data, data + size), "fuzz.7z");
    try {
        OpenOptions oo;
        oo.password = "raye";
        oo.force_format = Format::SevenZip;
        auto a = Archive::open(src, oo);
        ExtractOptions eo;
        eo.threads = 1;
        (void)a.test(eo);
    } catch (const Error &) {
    }
    return 0;
}
