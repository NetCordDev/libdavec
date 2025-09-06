cmake_minimum_required(VERSION 3.10.0)

if (WIN32 AND NOT DEFINED VCPKG_TARGET_TRIPLET)
    set(VCPKG_TARGET_TRIPLET "${WIN_TRIPLET_ARCH}-windows-static-md")
endif()

project(libdavec VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
