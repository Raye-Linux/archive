# Sources of the other format. Add new files here, never in the top CMakeLists.
target_sources(raye-archive PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/register.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/items.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/cpio.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/iso.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/cab.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lzx.cpp
)
