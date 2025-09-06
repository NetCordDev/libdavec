SSL=boringssl

ifeq ($(SSL),boringssl)
VCPKG_MANIFEST_DIR=$(PWD)/libdave/cpp/vcpkg-alts/boringssl
else ifeq ($(SSL),openssl1.1)
VCPKG_MANIFEST_DIR=$(PWD)/libdave/cpp/vcpkg-alts/openssl_1.1
else ifeq ($(SSL),openssl3)
VCPKG_MANIFEST_DIR=$(PWD)/libdave/cpp/vcpkg-alts/openssl_3
else
$(error "Unknown SSL option: $(SSL). Valid options are: boringssl, openssl1.1, openssl3")
endif

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

BUILD_DIR=build
TEST_DIR=build/test
CLANG_FORMAT=clang-format -i -style=file:.clang-format
TOOLCHAIN_FILE=$(PWD)/libdave/cpp/vcpkg/scripts/buildsystems/vcpkg.cmake
SHARED=ON
CONFIG=Release

all:
	cmake -B${BUILD_DIR} \
	-DVCPKG_MANIFEST_DIR=${VCPKG_MANIFEST_DIR} \
	-DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE} \
	-DBUILD_SHARED_LIBS=${SHARED} \
	-DWIN_TRIPLET_ARCH=${WIN_TRIPLET_ARCH}
	cmake --build ${BUILD_DIR} --config ${CONFIG}

clean:
	cmake --build ${BUILD_DIR} --target clean

cclean:
	cmake -E rm -rf ${BUILD_DIR}
