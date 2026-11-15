# Raye archive tests. Label "raye": the package build runs ctest -L raye.
#
# raye_archive_add_test(NAME SOURCE [ARGS ...]) builds one test binary that
# can include core/*.h and tests/check.h. Format work adds its own tests in
# tests/formats/<format>/CMakeLists.txt, never here.
function(raye_archive_add_test name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE raye-archive)
    target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/tests)
    add_test(NAME ${name} COMMAND ${name} ${ARGN})
    set_tests_properties(${name} PROPERTIES LABELS raye TIMEOUT 300)
endfunction()

set(RAYE_ARCHIVE_FIXTURES ${CMAKE_CURRENT_SOURCE_DIR}/fixtures)
set(RAYE_ARCHIVE_CORPUS ${CMAKE_CURRENT_BINARY_DIR}/corpus)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME corpus_setup COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/corpus/make-corpus.py
         --small ${RAYE_ARCHIVE_CORPUS})
set_tests_properties(corpus_setup PROPERTIES FIXTURES_SETUP corpus LABELS raye)

raye_archive_add_test(test_core core/test_core.cpp)
raye_archive_add_test(test_extract core/test_extract.cpp)
raye_archive_add_test(test_fixtures core/test_fixtures.cpp ${RAYE_ARCHIVE_FIXTURES})
raye_archive_add_test(test_roundtrip core/test_roundtrip.cpp ${RAYE_ARCHIVE_CORPUS})
set_tests_properties(test_roundtrip PROPERTIES FIXTURES_REQUIRED corpus)
raye_archive_add_test(test_fuzz_smoke core/test_fuzz_smoke.cpp ${RAYE_ARCHIVE_FIXTURES})

add_test(NAME cli_smoke COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/cli-smoke.sh $<TARGET_FILE:raye-archive-cli>
         ${RAYE_ARCHIVE_FIXTURES})
set_tests_properties(cli_smoke PROPERTIES LABELS raye)

foreach(fmt zip 7z rar tar other)
    add_subdirectory(formats/${fmt})
endforeach()
