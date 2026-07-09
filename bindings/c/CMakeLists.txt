cmake_minimum_required(VERSION 3.20)
project(basecrawl_c_sdk LANGUAGES C)

enable_testing()

find_library(
  BASECRAWL_FFI_LIBRARY
  NAMES basecrawl_ffi
  PATHS "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release"
  NO_DEFAULT_PATH
  REQUIRED
)

add_executable(basecrawl-c-example example.c)
target_include_directories(basecrawl-c-example PRIVATE include)
target_link_libraries(basecrawl-c-example PRIVATE "${BASECRAWL_FFI_LIBRARY}")
set_target_properties(
  basecrawl-c-example
  PROPERTIES
    BUILD_RPATH "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release"
)

add_test(
  NAME basecrawl-c-scrapeproof-shape
  COMMAND ${CMAKE_COMMAND}
    -DPROGRAM=$<TARGET_FILE:basecrawl-c-example>
    -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/assert_scrapeproof.cmake
)
