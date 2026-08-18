cmake_minimum_required(VERSION 3.20)

project(
    WireAtlas
    VERSION 0.1.0
    DESCRIPTION "A defensive, offline classic-PCAP inspector"
    LANGUAGES CXX
)

include(CTest)
include(GNUInstallDirs)

set(CMAKE_CXX_EXTENSIONS OFF)

option(WIREATLAS_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(WIREATLAS_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(WIREATLAS_ENABLE_CLANG_TIDY "Run clang-tidy while compiling" OFF)
option(WIREATLAS_BUILD_FUZZER "Build the libFuzzer harness (Clang only)" OFF)

set(WIREATLAS_CORE_SOURCES
    src/byte_cursor.cpp
    src/packet_decoder.cpp
    src/pcap_reader.cpp
    src/report.cpp
)

function(wireatlas_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
        if(WIREATLAS_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wshadow
        )
        if(WIREATLAS_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

function(wireatlas_enable_sanitizers target)
    if(NOT WIREATLAS_ENABLE_SANITIZERS)
        return()
    endif()
    if(MSVC)
        message(FATAL_ERROR "WIREATLAS_ENABLE_SANITIZERS requires GCC or Clang")
    endif()
    target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
endfunction()

if(WIREATLAS_ENABLE_CLANG_TIDY)
    find_program(WIREATLAS_CLANG_TIDY clang-tidy REQUIRED)
    set(CMAKE_CXX_CLANG_TIDY "${WIREATLAS_CLANG_TIDY}")
endif()

add_library(wireatlas-core STATIC ${WIREATLAS_CORE_SOURCES})
add_library(WireAtlas::core ALIAS wireatlas-core)
set_target_properties(wireatlas-core PROPERTIES EXPORT_NAME core)
target_compile_features(wireatlas-core PUBLIC cxx_std_20)
target_include_directories(wireatlas-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
wireatlas_set_warnings(wireatlas-core)
wireatlas_enable_sanitizers(wireatlas-core)

add_executable(wireatlas src/main.cpp)
target_link_libraries(wireatlas PRIVATE WireAtlas::core)
wireatlas_set_warnings(wireatlas)
wireatlas_enable_sanitizers(wireatlas)

add_executable(wireatlas-sample tools/make_sample.cpp)
target_compile_features(wireatlas-sample PRIVATE cxx_std_20)
target_include_directories(wireatlas-sample PRIVATE include tools)
wireatlas_set_warnings(wireatlas-sample)
wireatlas_enable_sanitizers(wireatlas-sample)

if(BUILD_TESTING)
    add_executable(wireatlas-tests tests/tests.cpp)
    target_link_libraries(wireatlas-tests PRIVATE WireAtlas::core)
    target_include_directories(wireatlas-tests PRIVATE tools)
    wireatlas_set_warnings(wireatlas-tests)
    wireatlas_enable_sanitizers(wireatlas-tests)
    add_test(NAME wireatlas-tests COMMAND wireatlas-tests)
endif()

if(WIREATLAS_BUILD_FUZZER)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "WIREATLAS_BUILD_FUZZER requires Clang and libFuzzer")
    endif()
    add_executable(wireatlas-fuzz fuzz/fuzz_wireatlas.cpp ${WIREATLAS_CORE_SOURCES})
    target_compile_features(wireatlas-fuzz PRIVATE cxx_std_20)
    target_include_directories(wireatlas-fuzz PRIVATE include)
    target_compile_options(wireatlas-fuzz PRIVATE
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(wireatlas-fuzz PRIVATE
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer
    )
    wireatlas_set_warnings(wireatlas-fuzz)
endif()

install(TARGETS wireatlas wireatlas-core
    EXPORT WireAtlasTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT WireAtlasTargets
    FILE WireAtlasTargets.cmake
    NAMESPACE WireAtlas::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/WireAtlas
)
