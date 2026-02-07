cmake_minimum_required(VERSION 3.15)
project(oggtag VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(oggtag STATIC
    src/oggtag.c
    src/vorbis_comment/vorbis_comment.c
    src/ogg/ogg_stream.c
    src/ogg/ogg_crc.c
    src/flac/flac_meta.c
    src/io/file_io.c
    src/util/buffer.c
    src/util/string_util.c
)

target_include_directories(oggtag
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(oggtag PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

# Apple platform settings
if(APPLE)
    set_target_properties(oggtag PROPERTIES
        XCODE_ATTRIBUTE_CLANG_ENABLE_MODULES YES
    )
    if(NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "macOS deployment target")
    endif()
    if(CMAKE_OSX_SYSROOT MATCHES "iphoneos")
        set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "iOS deployment target" FORCE)
    endif()
endif()

# Install
install(TARGETS oggtag
    EXPORT oggtag-targets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)
install(DIRECTORY include/oggtag DESTINATION include)
install(EXPORT oggtag-targets
    FILE oggtag-config.cmake
    NAMESPACE oggtag::
    DESTINATION lib/cmake/oggtag
)

# Tests
option(OGGTAG_BUILD_TESTS "Build tests" OFF)
if(OGGTAG_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
