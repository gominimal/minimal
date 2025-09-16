#!/bin/sh
set -ex

tar xf llvm-20.1.8.src.tar.xz
cd llvm-20.1.8.src

tar -xf ../cmake-20.1.8.src.tar.xz
tar -xf ../third-party-20.1.8.src.tar.xz
sed '/LLVM_COMMON_CMAKE_UTILS/s@../cmake@cmake-20.1.8.src@' \
	-i CMakeLists.txt
sed '/LLVM_THIRD_PARTY_DIR/s@../third-party@third-party-20.1.8.src@' \
	-i cmake/modules/HandleLLVMOptions.cmake

tar -xf ../clang-20.1.8.src.tar.xz -C tools
mv tools/clang-20.1.8.src tools/clang

tar -xf ../compiler-rt-20.1.8.src.tar.xz -C projects
mv projects/compiler-rt-20.1.8.src projects/compiler-rt

sed 's/utility/tool/' -i utils/FileCheck/CMakeLists.txt

mkdir -v build
cd build

export CC=clang 
export CXX=clang++ 

cmake \
	-D CLANG_CONFIG_FILE_SYSTEM_DIR=/etc/clang \
	-D CLANG_DEFAULT_PIE_ON_LINUX=ON \
	-D CMAKE_BUILD_TYPE=Release \
	-D CMAKE_INSTALL_PREFIX=/usr \
	-D CMAKE_SKIP_INSTALL_RPATH=ON \
	-D LLVM_BINUTILS_INCDIR=/usr/include \
	-D LLVM_BUILD_LLVM_DYLIB=ON \
	-D LLVM_ENABLE_FFI=ON \
	-D LLVM_ENABLE_RTTI=ON \
	-D LLVM_INCLUDE_BENCHMARKS=OFF \
	-D LLVM_LINK_LLVM_DYLIB=ON \
	-D LLVM_TARGETS_TO_BUILD="host" \
	-W no-dev -G Ninja ..

ninja
DESTDIR=$OUTPUT_DIR ninja install
