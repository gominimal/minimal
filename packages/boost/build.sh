#!/bin/sh
set -e

tar xfo boost-1.89.0-b2-nodocs.tar.xz
cd boost-1.89.0

./bootstrap.sh --prefix=/usr --with-python=python3
./b2 stage -j$(nproc) threading=multi link=shared

pushd tools/build/test; python3 test_all.py; popd

./b2 --prefix=$OUTPUT_DIR/usr install threading=multi link=shared