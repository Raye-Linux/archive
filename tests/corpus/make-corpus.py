#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write the test corpus: the same bytes on every run (fixed seed).

  make-corpus.py [--small|--bench] OUT

--small (tests, a few MB), default (round trips, ~40 MB),
--bench (~600 MB, for bench/bench.py).
"""
import argparse
import os
import random
import shutil
import zlib

WORDS = ("the of and to in is was for on that with as by at from this archive file folder "
         "raye window start taskbar settings update store picture music video document "
         "compress extract password volume solid block dictionary thread").split()


def text(rng, size):
    out, n = [], 0
    while n < size:
        line = " ".join(rng.choice(WORDS) for _ in range(rng.randint(4, 14))).capitalize() + ".\n"
        out.append(line)
        n += len(line)
    return "".join(out)[:size].encode()


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--small", action="store_true")
    g.add_argument("--bench", action="store_true")
    a = ap.parse_args()
    scale = 0.05 if a.small else 15 if a.bench else 1
    rng = random.Random(20261111)
    if os.path.exists(a.out):
        shutil.rmtree(a.out)
    os.makedirs(a.out)
    mb = lambda n: max(1, int(n * scale * (1 << 20)))

    write(f"{a.out}/text/book.txt", text(rng, mb(8)))
    write(f"{a.out}/text/notes.md", text(rng, mb(0.3)))
    write(f"{a.out}/text/log/2026-11-11.log", b"".join(
        b"2026-11-11 %02d:%02d:%02d raye-update: checked %d packages\n" % (h % 24, h % 60, h * 7 % 60, h) for h in range(mb(2) // 50)))
    write(f"{a.out}/binary/random.bin", rng.randbytes(mb(4)))
    write(f"{a.out}/binary/zeros.bin", bytes(mb(6)))
    # Looks like code: a repeating structure with small changes (BCJ-friendly-ish).
    write(f"{a.out}/binary/program.bin", b"".join(
        bytes([0x48, 0x89, 0xe5, 0xe8]) + (i * 37).to_bytes(4, "little") + rng.randbytes(8) for i in range(mb(4) // 16)))
    write(f"{a.out}/packed/already.gz", zlib.compress(rng.randbytes(mb(2)), 6))
    many = 60 if a.small else 3000 if not a.bench else 20000
    for i in range(many):
        write(f"{a.out}/many/{i // 100:03d}/item-{i:05d}.txt", text(rng, rng.randint(0, 900)))
    for name in ("Résumé été.txt", "日本語のファイル.txt", "Ελληνικά.txt", "emoji 🎉 party.txt", "spaces  and\ttab.txt"):
        write(f"{a.out}/unicode/{name}", text(rng, 2000))
    write(f"{a.out}/empty-file", b"")
    os.makedirs(f"{a.out}/empty-folder/inside-empty")
    os.symlink("../text/book.txt", f"{a.out}/unicode/link-to-book")
    os.symlink("many", f"{a.out}/link-to-folder")
    os.chmod(f"{a.out}/text/notes.md", 0o600)
    os.chmod(f"{a.out}/binary/program.bin", 0o755)
    # Fixed times so archives built from the corpus are reproducible.
    for root, dirs, files in os.walk(a.out, topdown=False):
        for n in files + dirs:
            os.utime(os.path.join(root, n), (1762800000, 1762800000), follow_symlinks=False)
    os.utime(a.out, (1762800000, 1762800000))


if __name__ == "__main__":
    main()
