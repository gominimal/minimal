#!/bin/sh
set -e

tar xf llvm-20.1.8.src.tar.xz
cd llvm-20.1.8.src

tar -xf ../cmake-20.1.8.src.tar.xz                              &&
tar -xf ../third-party-20.1.8.src.tar.xz                        &&
sed '/LLVM_COMMON_CMAKE_UTILS/s@../cmake@cmake-20.1.8.src@'          \
    -i CMakeLists.txt                                                &&
sed '/LLVM_THIRD_PARTY_DIR/s@../third-party@third-party-20.1.8.src@' \
    -i cmake/modules/HandleLLVMOptions.cmake

# grep -rl '#!.*python' | xargs sed -i '1s/python$/python3/'

mkdir -v build &&
cd       build &&

CC=gcc CXX=g++                               \
cmake -D CMAKE_INSTALL_PREFIX=/usr           \
      -D CMAKE_SKIP_INSTALL_RPATH=ON         \
      -D LLVM_ENABLE_FFI=ON                  \
      -D CMAKE_BUILD_TYPE=Release            \
      -D LLVM_BUILD_LLVM_DYLIB=ON            \
      -D LLVM_LINK_LLVM_DYLIB=ON             \
      -D LLVM_ENABLE_RTTI=ON                 \
      -D LLVM_TARGETS_TO_BUILD="host;AMDGPU" \
      -D LLVM_BINUTILS_INCDIR=/usr/include   \
      -D LLVM_INCLUDE_BENCHMARKS=OFF         \
      -D CLANG_DEFAULT_PIE_ON_LINUX=ON       \
      -D CLANG_CONFIG_FILE_SYSTEM_DIR=/etc/clang \
      -W no-dev -G Ninja ..                  &&
ninja
