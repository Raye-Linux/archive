#!/bin/sh
# ZIP files go both ways between raye-archive and zip/unzip, bsdtar and 7z.
# usage: interop.sh RAYE-ARCHIVE CORPUS   (exit 77 = tools missing, skipped)
set -u
R=$(realpath "$1")
C=$(realpath "$2")
for t in zip unzip bsdtar 7z python3; do
    command -v $t >/dev/null || { echo "skip: $t not installed"; exit 77; }
done
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
here=$(realpath "$(dirname "$0")")
hash() { python3 "$here/../../tree_hash.py" "$1"; }
fails=0
bad() { echo "FAIL $*"; fails=$((fails + 1)); }

# The corpus has a tab in a name (unzip drops it) and a ../ link (7z skips
# it): compare on a copy without those two.
mkdir -p "$W/in"
cp -a "$C/." "$W/in/"
find "$W/in" -name '*	*' -exec rm -f {} +
find "$W/in" -type l -lname '../*' -exec rm -f {} +
want=$(hash "$W/in")

check() { # label dir
    got=$(hash "$2" 2>/dev/null || echo none)
    [ "$got" = "$want" ] || bad "$1"
}

cd "$W"
for m in store deflate bzip2 lzma zstd xz; do
    "$R" a -t zip -mm $m -mx 6 r-$m.zip in >/dev/null || bad "create $m"
    rm -rf o && mkdir o && bsdtar -xf r-$m.zip -C o && check "bsdtar reads $m" o/in
    rm -rf o
    if 7z x -bd -y -oo r-$m.zip >/dev/null 2>&1; then check "7z reads $m" o/in; else bad "7z reads $m"; fi
    case $m in store|deflate|bzip2)
        rm -rf o && mkdir o && unzip -q r-$m.zip -d o && check "unzip reads $m" o/in ;;
    esac
done

"$R" a -t zip -prayé r-aes.zip in >/dev/null || bad "create aes"
rm -rf o
if 7z x -bd -y -prayé -oo r-aes.zip >/dev/null 2>&1; then check "7z reads aes" o/in; else bad "7z reads aes"; fi
rm -rf o && mkdir o && bsdtar --passphrase rayé -xf r-aes.zip -C o && check "bsdtar reads aes" o/in

# Other tools write, we read.
zip -qry -X t-zip.zip in && rm -rf o && "$R" x -y -o o t-zip.zip >/dev/null && check "read zip" o/in
zip -qry -X -P pw t-zc.zip in && rm -rf o && "$R" x -y -ppw -o o t-zc.zip >/dev/null && check "read zip -P" o/in
zip -qry -X -s 100k t-split.zip in && rm -rf o && "$R" x -y -o o t-split.z01 >/dev/null && check "read zip -s" o/in
bsdtar --format zip -cf t-bsd.zip in && rm -rf o && "$R" x -y -o o t-bsd.zip >/dev/null && check "read bsdtar zip" o/in
for m in Deflate Deflate64 BZip2 LZMA; do
    7z a -snl -bd -bso0 -tzip -mm=$m t-7z-$m.zip in && rm -rf o && "$R" x -y -o o t-7z-$m.zip >/dev/null && check "read 7z $m" o/in
done
7z a -snl -bd -bso0 -tzip -mem=AES256 -ppw t-7z-aes.zip in && rm -rf o && "$R" x -y -ppw -o o t-7z-aes.zip >/dev/null && check "read 7z aes" o/in
7z a -snl -bd -bso0 -tzip -mm=Deflate -mx=9 -v300k t-7z-vol.zip in && rm -rf o && "$R" x -y -o o t-7z-vol.zip.002 >/dev/null && check "read 7z volumes" o/in

[ $fails = 0 ] && echo "all interop checks passed"
exit $([ $fails = 0 ] && echo 0 || echo 1)
