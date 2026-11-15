// SPDX-License-Identifier: GPL-3.0-or-later
// Each format folder defines one of these in its register.cpp.
#pragma once

namespace raye::archive::detail {

void register_zip_formats();
void register_7z_formats();
void register_rar_formats();
void register_tar_formats();   // tar and the stream compressors (gz, bz2, xz, lzma, zst, lz4, lz, br, Z)
void register_other_formats(); // iso, udf, cab, cpio, ar/deb, rpm, arj, lzh

inline void register_all_formats()
{
    register_zip_formats();
    register_7z_formats();
    register_rar_formats();
    register_tar_formats();
    register_other_formats();
}

} // namespace raye::archive::detail
