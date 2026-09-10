# Imports the library `zig build c` staged under zig-out/c. Nothing here builds
# the core: point GOSSVEIL_STAGE at another stage directory to use one.
cmake_minimum_required(VERSION 3.20)

set(GOSSVEIL_STAGE "${CMAKE_CURRENT_LIST_DIR}/../../zig-out/c" CACHE PATH "where zig build c staged the SDK")
set(GOSSVEIL_LIBRARY "${GOSSVEIL_STAGE}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}gossveil${CMAKE_SHARED_LIBRARY_SUFFIX}")

if(NOT EXISTS "${GOSSVEIL_LIBRARY}")
    message(FATAL_ERROR "no library at ${GOSSVEIL_LIBRARY}; run zig build c first")
endif()

add_library(gossveil SHARED IMPORTED GLOBAL)
set_target_properties(gossveil PROPERTIES
    IMPORTED_LOCATION "${GOSSVEIL_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${GOSSVEIL_STAGE}/include")
