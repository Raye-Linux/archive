# libFuzzer targets: cmake -DRAYE_ARCHIVE_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++
# then ./fuzz_open -max_total_time=60 ../tests/fixtures
add_executable(fuzz_open fuzz_open.cpp)
target_compile_options(fuzz_open PRIVATE -fsanitize=fuzzer,address,undefined)
target_link_options(fuzz_open PRIVATE -fsanitize=fuzzer,address,undefined)
target_link_libraries(fuzz_open PRIVATE raye-archive)
