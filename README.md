# Raye Archive

The archive engine of Raye Linux: a C++ library (`libraye-archive`) and a
command line tool (`raye-archive`) that open, test and extract almost any
archive, and create 7z, ZIP and tar archives.

Detection reads the content, not the file name, so an archive with no
extension or a self-extracting `.exe` still opens.

## Build

    cmake -S . -B build -G Ninja
    cmake --build build

## Test

    ctest --test-dir build --output-on-failure

`tests/` has the unit tests, the fixtures and a corpus; `fuzz/` has fuzz
targets and `bench/` a few benchmarks.

`raye-archive --help` lists what the tool does.

## License

GPL-3.0-or-later (`LICENSE`). A few imported files are BSD-2-Clause or
ISC; `debian/copyright` lists them.

## Links

- Website: https://rayelinux.com
- Discord: https://discord.gg/TrxhUkabyB (questions, bug reports, news)
