// SPDX-License-Identifier: GPL-3.0-or-later
// libFuzzer target for the RAR reader. Seed it with the RAR fixtures.
#include <raye/archive/archive.h>

#include <cstddef>
#include <cstdint>

using namespace raye::archive;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    if (size < 8) return 0;
    try {
        // First byte picks the reader and whether a password is given (key
        // derivation is slow on purpose, so most inputs go without).
        OpenOptions oo;
        if (data[0] & 2) oo.password = "password";
        oo.force_format = (data[0] & 1) ? Format::Rar5 : Format::Rar;
        std::vector<std::uint8_t> v(data + 1, data + size);
        auto a = Archive::open(memory_source(std::move(v), "fuzz.rar"), oo);
        a.entries();
        ExtractOptions eo;
        eo.password = oo.password;
        eo.threads = 1;
        a.test(eo);
    } catch (const Error &) {
    }
    return 0;
}
