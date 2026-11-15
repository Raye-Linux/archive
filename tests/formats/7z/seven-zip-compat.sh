#!/bin/sh
# Archives made by 7-Zip must extract here, and ours must extract in 7-Zip.
# Needs 7z (package 7zip); without it the test is reported as skipped.
# usage: seven-zip-compat.sh RAYE-ARCHIVE CORPUS
set -u
R=$1
C=$2
command -v 7z >/dev/null 2>&1 || { echo "7z is not installed: skipped"; exit 77; }
W=$(mktemp -d)
trap 'chmod -R u+w "$W"; rm -r "$W"' EXIT
mkdir "$W/src"
cp -a "$C/." "$W/src/"
for b in /bin/ls /bin/sh; do [ -f "$b" ] && cp -L "$b" "$W/src/"; done
ln -s text/book.txt "$W/src/link-to-book"
bad=0

theirs() {
    name=$1; shift
    (cd "$W/src" && 7z a -bd -snl "$@" "$W/t.7z" . >/dev/null) || { echo "FAIL $name: 7z could not create"; bad=1; return; }
    a=$W/t.7z; [ -f "$W/t.7z.001" ] && a=$W/t.7z.001
    if "$R" x -y -praye -o "$W/o" "$a" >/dev/null && diff -r --no-dereference "$W/src" "$W/o" >/dev/null; then
        echo "ok   7-Zip $name"
    else
        echo "FAIL 7-Zip $name"; bad=1
    fi
    find "$W" -maxdepth 1 -name 't.7z*' -delete; rm -r "$W/o" 2>/dev/null
}

ours() {
    name=$1; shift
    (cd "$W/src" && "$R" a "$@" "$W/r.7z" * >/dev/null) || { echo "FAIL $name: could not create"; bad=1; return; }
    a=$W/r.7z; [ -f "$W/r.7z.001" ] && a=$W/r.7z.001
    if 7z x -snld -bd -y -praye -o"$W/o" "$a" >/dev/null && diff -r --no-dereference "$W/src" "$W/o" >/dev/null; then
        echo "ok   raye $name"
    else
        echo "FAIL raye $name"; bad=1
    fi
    find "$W" -maxdepth 1 -name 'r.7z*' -delete; rm -r "$W/o" 2>/dev/null
}

theirs mx1 -mx1
theirs mx9 -mx9
theirs not-solid -ms=off
theirs ppmd -m0=PPMd:mem=1m:o=16
theirs bzip2 -m0=BZip2
theirs deflate -m0=Deflate
theirs deflate64 -m0=Deflate64
theirs bcj2 -m0=BCJ2 -m1=LZMA2 -m2=LZMA -m3=LZMA -mb0:1 -mb0s1:2 -mb0s2:3
theirs arm64 -mf=ARM64
theirs delta -mf=Delta:4
theirs aes-names -praye -mhe=on
theirs volumes -v300k

ours mx0 -mx 0
ours mx1 -mx 1
ours mx5 -mx 5
ours mx9 -mx 9
ours not-solid -ms off
ours lzma -mm lzma
ours ppmd -mm ppmd
ours bzip2 -mm bzip2
ours deflate -mm deflate
ours aes -praye
ours aes-names -praye --encrypt-names
ours volumes -mx 1 -v 300k
exit $bad
