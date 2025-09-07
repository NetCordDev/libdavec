SOURCE_DIR=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))

SSL=boringssl

ifeq ($(SSL),boringssl)
VCPKG_MANIFEST_DIR=$(SOURCE_DIR)libdave/cpp/vcpkg-alts/boringssl
else ifeq ($(SSL),openssl1.1)
VCPKG_MANIFEST_DIR=$(SOURCE_DIR)libdave/cpp/vcpkg-alts/openssl_1.1
else ifeq ($(SSL),openssl3)
VCPKG_MANIFEST_DIR=$(SOURCE_DIR)libdave/cpp/vcpkg-alts/openssl_3
else
$(error "Unknown SSL option: $(SSL). Valid options are: boringssl, openssl1.1, openssl3")
endif

WIN_TRIPLET=
ifeq ($(OS),Windows_NT)
	ifeq ($(PROCESSOR_ARCHITEW6432),)
	NATIVE_ARCH=$(PROCESSOR_ARCHITECTURE)
	else
	NATIVE_ARCH=$(PROCESSOR_ARCHITEW6432)
	endif

	ifeq ($(NATIVE_ARCH),x86)
	WIN_TRIPLET_ARCH=x86
	else ifeq ($(NATIVE_ARCH),ARM64)
	WIN_TRIPLET_ARCH=arm64
	else
	WIN_TRIPLET_ARCH=x64
	endif

	WIN_TRIPLET=$(WIN_TRIPLET_ARCH)-windows-static-md
endif

BUILD_DIR=build
TEST_DIR=build/test
CLANG_FORMAT=clang-format -i -style=file:.clang-format
TOOLCHAIN_FILE=$(SOURCE_DIR)libdave/cpp/vcpkg/scripts/buildsystems/vcpkg.cmake
SHARED=ON
CONFIG=Release

OPTIONAL_ARGUMENTS=
ifneq ($(CMAKE_CXX_COMPILER),)
OPTIONAL_ARGUMENTS += -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
endif
ifneq ($(CMAKE_C_COMPILER),)
OPTIONAL_ARGUMENTS += -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
endif
ifneq ($(VCPKG_TARGET_TRIPLET),)
OPTIONAL_ARGUMENTS += -DVCPKG_TARGET_TRIPLET=${VCPKG_TARGET_TRIPLET}
else ifneq ($(WIN_TRIPLET),)
OPTIONAL_ARGUMENTS += -DVCPKG_TARGET_TRIPLET=${WIN_TRIPLET}
endif

all: configure build

configure:
	cmake -B${BUILD_DIR} \
	${OPTIONAL_ARGUMENTS} \
	-DCMAKE_BUILD_TYPE=${CONFIG} \
	-DVCPKG_MANIFEST_DIR=${VCPKG_MANIFEST_DIR} \
	-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE} \
	-DBUILD_SHARED_LIBS=${SHARED} \
	-DWIN_TRIPLET_ARCH=${WIN_TRIPLET_ARCH} \
	-S${SOURCE_DIR}

build:
	cmake --build ${BUILD_DIR} --config ${CONFIG}

clean:
	cmake --build ${BUILD_DIR} --target clean

cclean:
	cmake -E rm -rf ${BUILD_DIR}

.PHONY: all configure build clean cclean
