#!/bin/sh
# The command line tool answers, detects by content, and fails cleanly.
set -e
cli=$1
fixtures=$2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$cli" --version | grep -q '^raye-archive '
"$cli" --help | grep -q 'Commands:'

# A ZIP with no extension (the case Files refused) is still a ZIP.
cp "$fixtures/basic.zip" "$tmp/no-extension"
"$cli" i "$tmp/no-extension" | head -1 | grep -q '^zip '

# Unknown content: clear message, exit 1.
printf 'not an archive at all' > "$tmp/plain.txt"
if "$cli" l "$tmp/plain.txt" 2> "$tmp/err"; then exit 1; fi
grep -q 'not an archive' "$tmp/err"

# Bad option: exit 2.
set +e
"$cli" x --nope "$tmp/plain.txt" 2>/dev/null
[ $? -eq 2 ] || exit 1
# RAR is never created.
"$cli" a -t rar "$tmp/new.rar" "$tmp/plain.txt" 2> "$tmp/err"
[ $? -eq 1 ] && grep -q 'not be created\|but not created' "$tmp/err" || exit 1
echo ok
