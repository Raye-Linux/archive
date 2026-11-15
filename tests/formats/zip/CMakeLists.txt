# Tests of the zip format: raye_archive_add_test(test_zip_<what> <file>.cpp [args])
raye_archive_add_test(test_zip_read test_zip_read.cpp ${RAYE_ARCHIVE_FIXTURES})
raye_archive_add_test(test_zip_write test_zip_write.cpp ${RAYE_ARCHIVE_CORPUS})
set_tests_properties(test_zip_write PROPERTIES FIXTURES_REQUIRED corpus)

if(RAYE_ARCHIVE_FUZZ)
    add_executable(fuzz_zip fuzz_zip.cpp)
    target_include_directories(fuzz_zip PRIVATE ${PROJECT_SOURCE_DIR}/src)
    target_compile_options(fuzz_zip PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_zip PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(fuzz_zip PRIVATE raye-archive)
endif()

add_test(NAME test_zip_interop COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/interop.sh $<TARGET_FILE:raye-archive-cli>
         ${RAYE_ARCHIVE_CORPUS})
set_tests_properties(test_zip_interop PROPERTIES LABELS raye SKIP_RETURN_CODE 77 FIXTURES_REQUIRED corpus TIMEOUT 300)
