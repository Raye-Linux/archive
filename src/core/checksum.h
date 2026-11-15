// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace raye::archive::detail {

// CRC-32 (ZIP, 7z, gzip, RAR). Incremental: crc = crc32(crc, data, n), start at 0.
std::uint32_t crc32(std::uint32_t crc, const void *data, std::size_t n);
std::uint32_t crc32_combine(std::uint32_t a, std::uint32_t b, std::uint64_t len_b);
// CRC-32C (Castagnoli), same calling style. Hardware instruction when the CPU has it.
std::uint32_t crc32c(std::uint32_t crc, const void *data, std::size_t n);
// RAR 1.5-2.x 16-bit header checksum is crc32 & 0xffff; RAR 1.4 uses its own, write it in rar/.

// BLAKE2sp (RAR5 file hashes). Not written yet: the RAR agent owns
// src/core/blake2sp.cpp and must replace the stub there.
class Blake2sp {
public:
    Blake2sp();
    ~Blake2sp();
    void update(const void *data, std::size_t n);
    std::array<std::uint8_t, 32> final();

private:
    struct State;
    std::unique_ptr<State> s_;
};

} // namespace raye::archive::detail
