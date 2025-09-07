cmake_minimum_required(VERSION 3.10.0)

project(libdavec VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force Position Independent Code for static libraries so they can be linked into shared libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_STATIC_LIBRARY_PREFIX "")

set(CMAKE_SHARED_LIBRARY_PREFIX "")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)

set(LIBDAVEC_SHARED ${BUILD_SHARED_LIBS})

# Force libdave to always be static
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libdave/cpp)

set(BUILD_SHARED_LIBS ${LIBDAVEC_SHARED} CACHE BOOL "Build shared libraries" FORCE)

add_library(libdavec ${CMAKE_CURRENT_SOURCE_DIR}/src/libdavec.cpp)

target_include_directories(libdavec PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(libdavec PRIVATE libdave)

if (WIN32 AND BUILD_SHARED_LIBS)
    set_target_properties(libdavec PROPERTIES LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/libdavec.def")
endif ()
