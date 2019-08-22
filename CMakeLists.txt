cmake_minimum_required(VERSION 3.0)
project(tdb)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_STANDARD 11)
SET(CMAKE_C_STANDARD_REQUIRED ON)
SET(CMAKE_C_COMPILER gcc)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

SET(CMAKE_C_FLAGS "-g -march=native -Wall -Wpedantic -Werror -Wextra -Wfloat-equal -Wshadow -Werror=return-type -Werror=implicit-function-declaration -Werror=incompatible-pointer-types")

#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Werror -Wpedantic")
#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -Werror -Wpedantic")

include_directories(tdb ${CMAKE_SOURCE_DIR}/src/)
file(GLOB TDB_SOURCES "${CMAKE_SOURCE_DIR}/src/tdb/*.c")

include_directories(tdb ${CMAKE_SOURCE_DIR}/external/linenoise)
file(GLOB LINENOISE_SOURCES "${CMAKE_SOURCE_DIR}/external/linenoise/*.c")

include_directories(tdb ${CMAKE_SOURCE_DIR}/external/libdwarf/libdwarf)
file(GLOB LIBDWARF_LIBS "${CMAKE_SOURCE_DIR}/external/libdwarf/libdwarf/libdwarf*.o")

find_package(LibElf REQUIRED)
include_directories(${LIBELF_INCLUDE_DIRS})

find_package(ZLIB REQUIRED)
include_directories(${ZLIB_INCLUDE_DIRS})

include_directories(tdb ${LIBELF_INCLUDE_DIRS})

add_executable(tdb ${CMAKE_SOURCE_DIR}/src/main.c ${TDB_SOURCES} ${LINENOISE_SOURCES})
target_link_libraries(tdb ${LIBDWARF_LIBS} ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES})
