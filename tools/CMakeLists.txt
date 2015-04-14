cmake_minimum_required(VERSION 2.8)

include_directories("${PROJECT_SOURCE_DIR}/include")
include_directories("${PROJECT_SOURCE_DIR}/kmod")
include_directories("${PROJECT_SOURCE_DIR}/common")

add_executable(jtrace jtrace.c )
target_link_libraries( jtrace jtrace_lib )

add_executable(usertest usertest.c)
target_link_libraries( usertest jtrace_lib )
target_link_libraries( usertest pthread )
