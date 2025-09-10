cmake_minimum_required(VERSION 3.10.0)

project(libdavec VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force Position Independent Code for static libraries so they can be linked into shared libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_STATIC_LIBRARY_PREFIX "")

set(CMAKE_SHARED_LIBRARY_PREFIX "")

set(LIBDAVEC_SHARED ${BUILD_SHARED_LIBS})

include(GenerateExportHeader)

# Force libdave to always be static
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libdave/cpp)

set(BUILD_SHARED_LIBS ${LIBDAVEC_SHARED} CACHE BOOL "Build shared libraries" FORCE)

add_library(libdavec ${CMAKE_CURRENT_SOURCE_DIR}/src/libdavec.cpp)

generate_export_header(libdavec)

target_include_directories(libdavec PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(libdavec PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(libdavec PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out
)

target_link_libraries(libdavec PRIVATE libdave)
