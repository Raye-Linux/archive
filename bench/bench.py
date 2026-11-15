#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure raye-archive against 7-Zip and unrar on a fixed corpus.

  bench.py --raye build/raye-archive [--corpus DIR] [--rar DIR] [--out results.md]

--rar DIR adds test and extract times of every .rar in DIR against unrar
(archives without a password; RAR is never written here).

For each case: wall time, CPU time, peak memory (ru_maxrss of the child),
output size and ratio. Other tools are used only if found in PATH (7zz or
7z, unrar) and only to measure; nothing here is shipped.
"""
import argparse
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))


# Each case runs under its own small Python parent, so the peak memory read
# back is that case's alone (ru_maxrss of children only ever grows).
_PEAK = ("import resource, subprocess, sys; "
         "r = subprocess.run(sys.argv[1:], stdout=subprocess.DEVNULL); "
         "sys.stderr.write('\\npeak %d\\n' % resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss); "
         "sys.exit(r.returncode)")


def run(cmd, cwd=None):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    t0 = time.monotonic()
    p = subprocess.run([sys.executable, "-c", _PEAK, *cmd], cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    wall = time.monotonic() - t0
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    err = p.stderr.decode(errors="replace")
    peak = 0
    for line in err.splitlines():
        if line.startswith("peak "):
            peak = int(line.split()[1]) // 1024
    return p.returncode, wall, cpu, peak, err[-300:]


def du(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            if not os.path.islink(fp):
                total += os.path.getsize(fp)
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raye", required=True)
    ap.add_argument("--corpus")
    ap.add_argument("--rar")
    ap.add_argument("--out")
    ap.add_argument("--threads", type=int, default=os.cpu_count())
    a = ap.parse_args()
    work = tempfile.mkdtemp(prefix="raye-bench-")
    corpus = a.corpus or os.path.join(work, "corpus")
    if not a.corpus:
        subprocess.check_call([sys.executable, os.path.join(HERE, "..", "tests", "corpus", "make-corpus.py"), corpus])
    raw = du(corpus)
    sevenz = shutil.which("7zz") or shutil.which("7z")
    t = str(a.threads)
    cases = []
    for fmt, lvl in (("7z", 5), ("7z", 9), ("zip", 5), ("tar.zst", 5), ("tar.xz", 6)):
        out = os.path.join(work, f"raye-{lvl}.{fmt}")
        cases.append(("raye", f"{fmt} -mx{lvl}", [a.raye, "a", "-mx", str(lvl), "-mt", t, out, corpus], out))
        if sevenz and fmt in ("7z", "zip"):
            out7 = os.path.join(work, f"7z-{lvl}.{fmt}")
            cases.append(("7-Zip", f"{fmt} -mx{lvl}", [sevenz, "a", "-bd", "-snl", f"-mx={lvl}", f"-mmt={t}", out7, corpus], out7))
    rows = []
    for tool, what, cmd, out in cases:
        rc, wall, cpu, rss, err = run(cmd)
        if rc != 0:
            rows.append((tool, "create " + what, "failed", err.strip().splitlines()[-1:] or [""], "", "", ""))
            continue
        size = du(out)
        rows.append((tool, "create " + what, f"{wall:.2f}", f"{cpu:.2f}", f"{rss}", f"{size}", f"{raw / max(size, 1):.2f}"))
        dest = os.path.join(work, "x-" + os.path.basename(out))
        os.makedirs(dest)
        xcmd = [a.raye, "x", "-y", "-o", dest, out] if tool == "raye" else [sevenz, "x", "-bd", "-y", "-snld", f"-o{dest}", out]
        rc, wall, cpu, rss, err = run(xcmd)
        rows.append((tool, "extract " + what, f"{wall:.2f}" if rc == 0 else "failed", f"{cpu:.2f}", f"{rss}", "", ""))
        shutil.rmtree(dest, ignore_errors=True)
        if tool == "7-Zip":
            # the same 7-Zip archive, opened by us
            os.makedirs(dest)
            rc, wall, cpu, rss, err = run([a.raye, "x", "-y", "-o", dest, out])
            rows.append(("raye", "extract 7-Zip's " + what, f"{wall:.2f}" if rc == 0 else "failed", f"{cpu:.2f}", f"{rss}", "", ""))
            shutil.rmtree(dest, ignore_errors=True)
    unrar = shutil.which("unrar")
    if a.rar:
        for name in sorted(os.listdir(a.rar)):
            if not name.endswith(".rar"):
                continue
            rar = os.path.join(a.rar, name)
            tools = [("raye", [a.raye, "t", rar], lambda d: [a.raye, "x", "-y", "-o", d, rar])]
            if unrar:
                tools.append(("unrar", [unrar, "t", "-idq", rar], lambda d: [unrar, "x", "-idq", "-o+", rar, d + "/"]))
            for tool, tcmd, xcmd in tools:
                rc, wall, cpu, rss, err = run(tcmd)
                rows.append((tool, "test " + name, f"{wall:.2f}" if rc == 0 else "failed", f"{cpu:.2f}", f"{rss}", "", ""))
                dest = os.path.join(work, f"x-{tool}-{name}")
                os.makedirs(dest)
                rc, wall, cpu, rss, err = run(xcmd(dest))
                rows.append((tool, "extract " + name, f"{wall:.2f}" if rc == 0 else "failed", f"{cpu:.2f}", f"{rss}", "", ""))
                shutil.rmtree(dest, ignore_errors=True)
    lines = [f"Corpus {raw} bytes, {a.threads} threads, {time.strftime('%Y-%m-%d %H:%M')}", "",
             "| tool | case | wall s | cpu s | peak MiB | bytes | ratio |", "|---|---|---|---|---|---|---|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    text = "\n".join(lines)
    print(text)
    if a.out:
        with open(a.out, "w") as f:
            f.write(text + "\n")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
