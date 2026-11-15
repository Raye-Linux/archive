// SPDX-License-Identifier: GPL-3.0-or-later
#include <raye/archive/error.h>

namespace raye::archive {

const char *error_code_name(ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::Ok: return "ok";
    case ErrorCode::Io: return "input/output error";
    case ErrorCode::NotFound: return "not found";
    case ErrorCode::UnknownFormat: return "not an archive Raye knows";
    case ErrorCode::NotImplemented: return "not supported yet";
    case ErrorCode::Corrupt: return "archive is damaged";
    case ErrorCode::Truncated: return "archive is incomplete";
    case ErrorCode::Checksum: return "checksum mismatch";
    case ErrorCode::PasswordRequired: return "password required";
    case ErrorCode::WrongPassword: return "wrong password";
    case ErrorCode::UnsupportedMethod: return "unsupported method";
    case ErrorCode::UnsafePath: return "unsafe path";
    case ErrorCode::LinkOutside: return "link points outside the destination";
    case ErrorCode::Bomb: return "decompression bomb";
    case ErrorCode::Cancelled: return "cancelled";
    case ErrorCode::Exists: return "already exists";
    case ErrorCode::NoSpace: return "not enough space";
    case ErrorCode::ReadOnlyFormat: return "format is read-only";
    case ErrorCode::MissingVolume: return "missing volume";
    case ErrorCode::InvalidOption: return "invalid option";
    case ErrorCode::Internal: return "internal error";
    }
    return "error";
}

static std::string full(const std::string &msg, const std::string &path)
{
    return path.empty() ? msg : path + ": " + msg;
}

Error::Error(ErrorCode code, const std::string &message, std::string path)
    : std::runtime_error(full(message, path)), code_(code), message_(message), path_(std::move(path))
{
}

void fail(ErrorCode code, const std::string &message, const std::string &path)
{
    throw Error(code, message, path);
}

} // namespace raye::archive
