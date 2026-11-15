// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "driver.h"

#include <string_view>
#include <vector>

namespace raye::archive::detail {

// Expands input items into files and folders to add, in a stable order
// (folder before its content, names sorted), excluded paths removed.
std::vector<PlanItem> walk_inputs(const std::vector<InputItem> &items, const WriteOptions &opts);

// Exclusion pattern match. A pattern without '/' matches any path component
// name ("*.tmp", ".git"); with '/' it matches the whole path, '*' crossing
// folders.
bool glob_match(std::string_view pattern, std::string_view path);

} // namespace raye::archive::detail
