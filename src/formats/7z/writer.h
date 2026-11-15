// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "../../core/driver.h"

namespace raye::archive::detail::sevenz {

std::unique_ptr<WriterImpl> make_writer();

} // namespace raye::archive::detail::sevenz
