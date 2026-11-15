// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

namespace raye::archive {

// Stable codes: the interface maps them to its own English/French text.
enum class ErrorCode : std::uint16_t {
    Ok = 0,
    Io = 1,               // read/write failed at the OS level
    NotFound = 2,         // file or entry does not exist
    UnknownFormat = 3,    // content matches no known archive
    NotImplemented = 4,   // format known, reader/writer not written yet
    Corrupt = 5,          // headers or data make no sense
    Truncated = 6,        // archive ends early
    Checksum = 7,         // CRC/hash mismatch after decoding
    PasswordRequired = 8, // encrypted and no password given
    WrongPassword = 9,
    UnsupportedMethod = 10, // compression or encryption method we do not decode
    UnsafePath = 11,      // ../, absolute, reserved name, NUL in name
    LinkOutside = 12,     // symlink or hard link would point out of the destination
    Bomb = 13,            // ratio or size limit hit
    Cancelled = 14,
    Exists = 15,          // conflict resolved as "fail"
    NoSpace = 16,
    ReadOnlyFormat = 17,  // format can be read but not written (RAR)
    MissingVolume = 18,
    InvalidOption = 19,
    Internal = 20,
};

// Short English name of a code ("checksum mismatch").
const char *error_code_name(ErrorCode code) noexcept;

class Error : public std::runtime_error {
public:
    Error(ErrorCode code, const std::string &message, std::string path = {});

    ErrorCode code() const noexcept { return code_; }
    // Archive member or file the error is about, empty if none.
    const std::string &path() const noexcept { return path_; }
    // Message without the path prefix.
    const std::string &message() const noexcept { return message_; }

private:
    ErrorCode code_;
    std::string message_;
    std::string path_;
};

[[noreturn]] void fail(ErrorCode code, const std::string &message, const std::string &path = {});

} // namespace raye::archive
