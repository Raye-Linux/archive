#!/bin/sh
# Remakes the zip-* fixtures (needs zip, 7z, python3). Tree hashes for
# MANIFEST: python3 tests/tree_hash.py on d64, sp and src.
set -e
out=$(realpath "${1:-$(dirname "$0")/../../fixtures}")
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cd "$W"
mkdir -p src/d sp d64
python3 - <<'EOF'
import random
r = random.Random(7)
blk = "".join(r.choice("acgt") for _ in range(40000)).encode()
mid = "".join(r.choice("ACGT") for _ in range(30000)).encode()
# Repeats 40 000 bytes back and runs of 70 000: only Deflate64 reaches them.
open("d64/far.txt", "wb").write(blk + mid + blk * 3 + b"x" * 70000)
open("sp/rand.bin", "wb").write(bytes(r.getrandbits(8) for _ in range(70000)))
open("src/notes.txt", "w").write("".join("line %d of the notes\n" % i for i in range(3000)))
open("src/d/hello.txt", "w").write("hello\n")
EOF
touch -d "2026-11-01 12:00:00" src src/d src/d/* src/notes.txt sp sp/* d64 d64/*
(cd d64 && 7z a -bd -bso0 -tzip -mm=Deflate64 -mx=9 "$out/zip-deflate64-far.zip" far.txt)
(cd sp && zip -qr -X -s 64k "$W/zip-split.zip" . && cp "$W"/zip-split.z01 "$W"/zip-split.zip "$out/")
(cd src && zip -qr -X -fz "$out/zip-zip64.zip" .)
{ printf 'MZ\220\0\3\0\0\0'; head -c 4000 /dev/zero; cat "$out/zip-zip64.zip"; } > "$out/zip-prefixed.exe"
