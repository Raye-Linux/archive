// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "../../core/driver.h"

#include <memory>

namespace raye::archive::detail {

std::unique_ptr<ReaderImpl> open_ar(const OpenRequest &req);
std::unique_ptr<ReaderImpl> open_cpio(const OpenRequest &req);
std::unique_ptr<ReaderImpl> open_rpm(const OpenRequest &req);
std::unique_ptr<ReaderImpl> open_iso(const OpenRequest &req);
std::unique_ptr<ReaderImpl> open_cab(const OpenRequest &req);

} // namespace raye::archive::detail
