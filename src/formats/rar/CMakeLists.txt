# Sources of the rar format. Add new files here, never in the top CMakeLists.
target_sources(raye-archive PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/register.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/common.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/crypt.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/archive4.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/archive5.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/reader.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/unpack5.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/unpack3.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ppmd.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/unpack2.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/unpack1.cpp
)
