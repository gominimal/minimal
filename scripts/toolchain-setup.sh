#!/bin/bash
# Shared toolchain setup for all package builds
# This script should be sourced by package build scripts

# Toolchain setup
TOOLCHAIN_DIR="${TOOLCHAIN_DIR:-toolchains/x86_64-unknown-linux-gnu}"
export PATH="${TOOLCHAIN_DIR}/bin:${PATH}"

# Export cross-compilation toolchain variables
export CC="x86_64-unknown-linux-gnu-gcc"
export CXX="x86_64-unknown-linux-gnu-g++"
export AR="x86_64-unknown-linux-gnu-ar"
export RANLIB="x86_64-unknown-linux-gnu-ranlib"
export LD="x86_64-unknown-linux-gnu-ld"
export STRIP="x86_64-unknown-linux-gnu-strip"
export OBJCOPY="x86_64-unknown-linux-gnu-objcopy"
export OBJDUMP="x86_64-unknown-linux-gnu-objdump"
export NM="x86_64-unknown-linux-gnu-nm"

# Additional commonly used variables
export CROSS_COMPILE="x86_64-unknown-linux-gnu-"
export TARGET="x86_64-unknown-linux-gnu"