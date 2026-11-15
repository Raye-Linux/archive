# Sources of the 7z format. Add new files here, never in the top CMakeLists.
target_sources(raye-archive PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/register.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/header.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/streams.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lzma2mt.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/filters.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ppmd.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/reader.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/writer.cpp
)
# The PPMd model reads one state through a context's fields, as the format expects.
set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/ppmd.cpp PROPERTIES COMPILE_OPTIONS -fno-strict-aliasing)
