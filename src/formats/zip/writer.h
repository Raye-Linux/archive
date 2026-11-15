// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "zip.h"

namespace raye::archive::detail::zip {

inline constexpr bool writer_ready = true;
std::unique_ptr<WriterImpl> make_writer();

} // namespace raye::archive::detail::zip
