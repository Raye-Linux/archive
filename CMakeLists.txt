cmake_minimum_required(VERSION 3.20)
project(raye-archive VERSION 0.5 LANGUAGES CXX)

set(RAYE_ARCHIVE_VERSION_STRING "0.5~beta1")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)

option(BUILD_TESTING "Build the tests" ON)
option(RAYE_ARCHIVE_SANITIZE "Build with AddressSanitizer and UBSan" OFF)
option(RAYE_ARCHIVE_FUZZ "Build libFuzzer targets (clang only)" OFF)

if(RAYE_ARCHIVE_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

find_package(PkgConfig REQUIRED)
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)
pkg_check_modules(LZMA REQUIRED IMPORTED_TARGET liblzma)
pkg_check_modules(ZSTD REQUIRED IMPORTED_TARGET libzstd)
pkg_check_modules(LZ4 REQUIRED IMPORTED_TARGET liblz4)
pkg_check_modules(BROTLI REQUIRED IMPORTED_TARGET libbrotlienc libbrotlidec)

add_library(raye-archive SHARED
    src/core/archive.cpp
    src/core/blake2sp.cpp
    src/core/checksum.cpp
    src/core/codec.cpp
    src/core/context.cpp
    src/core/crypto.cpp
    src/core/error.cpp
    src/core/extract.cpp
    src/core/format.cpp
    src/core/io.cpp
    src/core/registry.cpp
    src/core/threadpool.cpp
    src/core/walk.cpp
)
# Each format lists its own files: nobody edits this file to add one.
foreach(fmt zip 7z rar tar other)
    add_subdirectory(src/formats/${fmt})
endforeach()

set_target_properties(raye-archive PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    OUTPUT_NAME raye-archive)
target_compile_definitions(raye-archive PRIVATE RAYE_ARCHIVE_VERSION="${RAYE_ARCHIVE_VERSION_STRING}")
# Symbols stay visible: the tests reach detail:: (codecs, extractor). Only
# include/raye is installed, so detail is not part of the public API.
target_include_directories(raye-archive
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(raye-archive PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(raye-archive PRIVATE
    ZLIB::ZLIB BZip2::BZip2 OpenSSL::Crypto Threads::Threads
    PkgConfig::LZMA PkgConfig::ZSTD PkgConfig::LZ4 PkgConfig::BROTLI)

add_executable(raye-archive-cli tools/raye-archive.cpp)
set_target_properties(raye-archive-cli PROPERTIES OUTPUT_NAME raye-archive)
target_link_libraries(raye-archive-cli PRIVATE raye-archive)

install(TARGETS raye-archive LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS raye-archive-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/raye DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
configure_file(raye-archive.pc.in raye-archive.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/raye-archive.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

if(RAYE_ARCHIVE_FUZZ)
    add_subdirectory(fuzz)
endif()
