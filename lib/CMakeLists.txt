cmake_minimum_required(VERSION 2.8)

include_directories("${PROJECT_SOURCE_DIR}/include")
include_directories("${PROJECT_SOURCE_DIR}/kmod")
include_directories("${PROJECT_SOURCE_DIR}/common")

add_library(jtrace_lib jtrace_lib.c ${PROJECT_SOURCE_DIR}/common/jtrace_common.c )
