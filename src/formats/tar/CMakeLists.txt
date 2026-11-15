# Sources of the tar format. Add new files here, never in the top CMakeLists.
target_sources(raye-archive PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/register.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stream.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/bz2par.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lzw.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tar.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tario.cpp
)
