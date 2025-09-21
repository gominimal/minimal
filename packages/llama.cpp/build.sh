#!/bin/sh
set -e

tar xfo b6529.tar.gz
cd llama.cpp-b6529

cmake -B build
cmake --build build --config Release -j $(nproc)

mkdir -pv $OUTPUT_DIR/usr/{bin,lib}

install -vm755 build/bin/*.so $OUTPUT_DIR/usr/lib/
install -vm755 build/bin/llama-{cli,run,server} $OUTPUT_DIR/usr/bin/