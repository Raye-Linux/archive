#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Rebuilds tests/fixtures from a tiny fixed tree with free tools (zip, bsdtar,
# 7z, gzip, xz, zstd, lz4, lzip, bzip2) and fetches the libarchive RAR/7z
# samples listed in PROVENANCE.md. Writes MANIFEST: file, format, the tree
# hash of what bsdtar (the reference) extracts, and the password if any.
# Run it in the agents' chroot; the output is committed.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tests=$(dirname "$here")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export TZ=UTC LC_ALL=C.UTF-8

src="$work/basic"
mkdir -p "$src/docs/deep" "$src/empty"
printf 'Hello from Raye.\n' > "$src/hello.txt"
python3 -c 'import random; r=random.Random(7); open("'"$src"'/docs/random.bin","wb").write(r.randbytes(5000))'
for i in $(seq 1 200); do echo "line $i of the notes, the same words again and again"; done > "$src/docs/notes.txt"
printf 'unicode name\n' > "$src/docs/été 日本.txt"
printf 'deep\n' > "$src/docs/deep/file.txt"
ln -s ../hello.txt "$src/docs/link-to-hello"
find "$src" -exec touch -h -d '2026-11-01 12:00:00' {} +

cd "$work"
manifest="$here/MANIFEST.new"
echo "# file format tree-hash(bsdtar extraction) [password]   -- written by make-fixtures.sh" > "$manifest"

ref_hash() { # archive [password]
    local out="$work/ref.$$"
    rm -rf "$out"; mkdir "$out"
    if bsdtar ${2:+--passphrase "$2"} -xf "$1" -C "$out" 2>/dev/null; then
        python3 "$tests/tree_hash.py" "$out"
    else
        echo -
    fi
    rm -rf "$out"
}
add() { # file format [password]
    cp "$1" "$here/$(basename "$1")"
    echo "$(basename "$1") $2 $(ref_hash "$1" "${3:-}") ${3:-}" >> "$manifest"
}

zip -qry -X basic.zip basic && add basic.zip zip
zip -qry -X -P raye basic-zipcrypto.zip basic && add basic-zipcrypto.zip zip raye
7z a -bd -bso0 -tzip -mem=AES256 -praye basic-aes.zip basic && add basic-aes.zip zip raye
7z a -bd -bso0 -tzip -mm=Deflate64 basic-deflate64.zip basic && add basic-deflate64.zip zip
7z a -bd -bso0 -tzip -mm=LZMA basic-lzma.zip basic && add basic-lzma.zip zip
7z a -bd -bso0 -tzip -mm=BZip2 basic-bzip2.zip basic && add basic-bzip2.zip zip
7z a -bd -bso0 -t7z -m0=lzma2 -mx=5 basic.7z basic && add basic.7z 7z
7z a -bd -bso0 -t7z -m0=lzma -ms=off basic-lzma.7z basic && add basic-lzma.7z 7z
7z a -bd -bso0 -t7z -m0=ppmd basic-ppmd.7z basic && add basic-ppmd.7z 7z
7z a -bd -bso0 -t7z -m0=bzip2 basic-bzip2.7z basic && add basic-bzip2.7z 7z
7z a -bd -bso0 -t7z -m0=deflate basic-deflate.7z basic && add basic-deflate.7z 7z
7z a -bd -bso0 -t7z -mf=BCJ2 -m0=lzma basic-bcj2.7z basic && add basic-bcj2.7z 7z
7z a -bd -bso0 -t7z -praye -mhe=on basic-encrypted-names.7z basic && add basic-encrypted-names.7z 7z raye
7z a -bd -bso0 -t7z -praye basic-encrypted.7z basic && add basic-encrypted.7z 7z raye
bsdtar --format ustar -cf basic.tar basic && add basic.tar tar
bsdtar --format pax -cf basic-pax.tar basic && add basic-pax.tar tar
bsdtar --format gnutar -cf basic-gnu.tar basic && add basic-gnu.tar tar
bsdtar -czf basic.tar.gz basic && add basic.tar.gz gz
bsdtar -cjf basic.tar.bz2 basic && add basic.tar.bz2 bz2
bsdtar -cJf basic.tar.xz basic && add basic.tar.xz xz
bsdtar --zstd -cf basic.tar.zst basic && add basic.tar.zst zst
bsdtar --lz4 -cf basic.tar.lz4 basic && add basic.tar.lz4 lz4
bsdtar --lzip -cf basic.tar.lz basic && add basic.tar.lz lz
bsdtar --lzma -cf basic.tar.lzma basic && add basic.tar.lzma lzma
bsdtar -Zcf basic.tar.Z basic && add basic.tar.Z Z
bsdtar --format cpio -cf basic.cpio basic && add basic.cpio cpio
bsdtar --format newc -cf basic-newc.cpio basic && add basic-newc.cpio cpio
bsdtar --format iso9660 -cf basic.iso basic && add basic.iso iso
bsdtar --format ar -cf basic.a basic/hello.txt basic/docs/notes.txt && add basic.a ar
gzip -9nc basic/docs/notes.txt > notes.txt.gz && add notes.txt.gz gz
xz -c basic/docs/notes.txt > notes.txt.xz && add notes.txt.xz xz
brotli -c basic/docs/notes.txt > notes.txt.br && add notes.txt.br br

# libarchive's own test samples (BSD-2-Clause), uuencoded upstream.
base=https://raw.githubusercontent.com/libarchive/libarchive/v3.8.5/libarchive/test
while read -r name fmt pw; do
    [ -z "$name" ] && continue
    curl -fsS "$base/$name.uu" -o "$work/$name.uu" || { echo "missing upstream: $name" >&2; continue; }
    python3 - "$work/$name.uu" "$work/$name" <<'PY'
import binascii, sys
out = bytearray()
lines = open(sys.argv[1], "rb").read().splitlines()
started = False
for l in lines:
    if l.startswith(b"begin "): started = True; continue
    if l.strip() == b"end": break
    if started and l:
        try: out += binascii.a2b_uu(l)
        except binascii.Error:
            n = (l[0] - 32) & 63; out += binascii.a2b_uu(l[:1 + (n * 4 + 2) // 3])
open(sys.argv[2], "wb").write(out)
PY
    add "$work/$name" "$fmt" "$pw"
done <<'LIST'
test_read_format_rar.rar rar
test_read_format_rar_unicode.rar rar
test_read_format_rar_multi_lzss_blocks.rar rar
test_read_format_rar_compress_best.rar rar
test_read_format_rar_filter.rar rar
test_read_format_rar_ppmd_lzss_conversion.rar rar
test_read_format_rar_encryption_data.rar rar password
test_read_format_rar_sfx.exe rar
test_read_format_rar5_stored.rar rar5
test_read_format_rar5_compressed.rar rar5
test_read_format_rar5_solid.rar rar5
test_read_format_rar5_multiple_files.rar rar5
test_read_format_rar5_blake2.rar rar5
test_read_format_rar5_arm.rar rar5
test_read_format_rar5_win32.rar rar5
test_read_format_rar5_extra_field_version.rar rar5
test_read_format_7zip_ppmd.7z 7z
test_read_format_7zip_bcj2_lzma2_1.7z 7z
test_read_format_7zip_deflate.7z 7z
test_read_format_7zip_delta_lzma2.7z 7z
test_read_format_7zip_bcj_lzma2.7z 7z
test_read_format_7zip_sfx_pe.exe 7z
test_read_format_cab_1.cab cab
LIST

mv "$manifest" "$here/MANIFEST"
echo "fixtures: $(grep -vc '^#' "$here/MANIFEST")"
