#!/bin/sh
set -ex

tar xf minpkgs-ca7133e671320bc33ccb07d2a682a5f2ec10586d.tar.gz
cd minpkgs-ca7133e671320bc33ccb07d2a682a5f2ec10586d

export CC=gcc
export LD=gcc
export RUSTFLAGS="-C linker=gcc"

cargo build --release

mkdir -p $OUTPUT_DIR/usr/bin
cp target/release/minimal $OUTPUT_DIR/usr/bin
