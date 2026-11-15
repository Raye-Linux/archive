// SPDX-License-Identifier: GPL-3.0-or-later
// Detect, list, test and stream every entry of an archive held in memory.
#include <raye/archive/archive.h>

#include <cstddef>
#include <cstdint>

using namespace raye::archive;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    std::shared_ptr<Source> src = memory_source(std::vector<std::uint8_t>(data, data + size), "fuzz");
    try {
        OpenOptions oo;
        oo.password = "fuzz";
        auto a = Archive::open(src, oo);
        ExtractOptions eo;
        eo.threads = 1;
        eo.safety.max_total_size = 64 << 20;
        (void)a.test(eo);
        for (std::size_t i = 0; i < a.entries().size() && i < 16; ++i) {
            NullSink n;
            try { a.extract_to(i, n, eo); } catch (const Error &) {}
        }
    } catch (const Error &) {
    }
    return 0;
}
