cmake_minimum_required(VERSION 2.8)

message(STATUS "Configuring project jtrace")

project( mse )

function(gest_unit_test name)
    add_executable(${name} ${ARGN})
    add_dependencies(${name} googletest-pkg)
    add_test(${name} ${name})
    target_link_libraries(${name} ${CN_LIBS} ${MPOOL_LIBS} ${CORETEST_LIBS} ${GTEST_LIBS})
endfunction(gest_unit_test)

# Example: to copy a set of files from the current src dir to the
# corresponding build output dir:
#
#   copy_files(foobar
#    ${CMAKE_CURRENT_BINARY_DIR}
#     readme *.txt *.json *.sh doc/*.txt)
#
macro(copy_files TARGET_NAME DST_DIR)
  add_custom_target(${TARGET_NAME} ALL)
  foreach(PATTERN ${ARGN})
    file(GLOB COPY_FILES
      RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
      ${PATTERN})
    foreach(FILENAME ${COPY_FILES})
      set(SRC "${CMAKE_CURRENT_SOURCE_DIR}/${FILENAME}")
      set(DST "${DST_DIR}/${FILENAME}")
      add_custom_command(
        TARGET ${TARGET_NAME}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${SRC} ${DST})
    endforeach(FILENAME)
  endforeach(PATTERN)
endmacro(copy_files)



# increasing warning levels
set( CFLAGS_WARN_1 "-Wall -Werror")
set( CFLAGS_WARN_2 "${CFLAGS_WARN_1} -Wlogical-op -Wmissing-field-initializers  -Wuninitialized -Wmaybe-uninitialized")
set( CFLAGS_WARN_3 "${CFLAGS_WARN_2} -Wextra -Wno-conversion -Wno-sign-conversion -Wno-sign-compare -Wno-unused-parameter")
set( CFLAGS_WARN_4 "${CFLAGS_WARN_2} -Wextra -Wconversion    -Wsign-conversion    -Wsign-compare    -Wunused-parameter")
set( CFLAGS_WARN_MAX "${CFLAGS_WARN_4}")

SET( CMAKE_C_FLAGS "${CFLAGS_WARN_3}")

#
# Flags to enable the use of gprof
#
set( PROFILING false )

if( ${PROFILING} )
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg " )
  set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L /usr/local/lib -lprofiler" )
endif( ${PROFILING} )

set( C0_LIBS         c0 bonsai cheap threadpool)
set( MPOOL_LIBS      mpool_lib coreutils uuid)
set( CN_LIBS         cn kvblock mpool_lib coreutils mse_util cheap uuid threadpool bloom bloom_base ext_util m pthread)
set( CORETEST_LIBS   coretest coreutils mse_util)

set( MSE_UTIL_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/libutil/include)
set( MSE_SUB_REPOS ${PROJECT_SOURCE_DIR}/sub)


#

include_directories(${CMAKE_BINARY_DIR})


#
# All compiled binaries should depend upon nf_version.
#
macro(add_library _target)
    _add_library(${_target} ${ARGN})
    add_dependencies(${_target} nf_version)
endmacro()

macro(add_executable _target)
    _add_executable(${_target} ${ARGN})
    add_dependencies(${_target} nf_version)
endmacro()

set( FROBNICATE "check" )

#
# Rest of the project
#

message(STATUS "Configuring jtrace:library")
add_subdirectory( lib )

message(STATUS "Configuring jtrace:tools")
add_subdirectory( tools )

