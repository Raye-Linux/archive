#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Print the tree hash of a folder (same rules as tests/tree.h)."""
import hashlib
import os
import sys


def tree_hash(root):
    # Bytes all the way: names in archives are not always valid UTF-8.
    root = os.fsencode(root)
    lines = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if os.path.islink(full):
                lines.append((rel, b"L " + rel + b" " + os.readlink(full)))
            elif os.path.isdir(full):
                lines.append((rel, b"D " + rel))
            else:
                with open(full, "rb") as f:
                    lines.append((rel, b"F " + rel + b" " + hashlib.sha256(f.read()).hexdigest().encode()))
    lines.sort()
    return hashlib.sha256(b"".join(l + b"\n" for _, l in lines)).hexdigest()


if __name__ == "__main__":
    print(tree_hash(sys.argv[1]))
