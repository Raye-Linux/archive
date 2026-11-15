// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "streams.h"

#include <raye/archive/io.h>

#include <cstdint>
#include <memory>

namespace raye::archive::detail::sevenz {

// An LZMA2 stream cut where the dictionary resets (what 7-Zip writes with
// several threads) is decoded on several threads, in order. Returns nullptr
// when the stream has no such cuts or its chunk headers do not add up; the
// caller then decodes it the usual way, which reports any damage.
std::unique_ptr<Pull> open_lzma2_parallel(const Source &src, std::uint64_t offset, std::uint64_t packed,
                                          std::uint8_t props, std::uint64_t unpacked, unsigned threads);

} // namespace raye::archive::detail::sevenz
