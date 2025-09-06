cmake_minimum_required(VERSION 3.10.0)
project(libdavec VERSION 0.1.0 LANGUAGES C CXX)

# Force Position Independent Code for static libraries so they can be linked into shared libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_STATIC_LIBRARY_PREFIX "")

set(CMAKE_SHARED_LIBRARY_PREFIX "")

set(LIBDAVEC_SHARED ${BUILD_SHARED_LIBS})

# Force libdave to always be static
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)

add_subdirectory(libdave/cpp)

set(BUILD_SHARED_LIBS ${LIBDAVEC_SHARED} CACHE BOOL "Build shared libraries" FORCE)

add_library(libdavec src/libdavec.cpp)

target_include_directories(libdavec PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(libdavec PRIVATE libdave)
