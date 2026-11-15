# Sources of the zip format. Add new files here, never in the top CMakeLists.
target_sources(raye-archive PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/common.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/deflate64.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/reader.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/register.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/writer.cpp
)
