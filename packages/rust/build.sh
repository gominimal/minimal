#!/bin/sh
set -ex

tar xf rustc-1.89.0-src.tar.xz
cd rustc-1.89.0-src

cp ../bootstrap.toml .

export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
export LIBSSH2_SYS_USE_PKG_CONFIG=1

./x.py build

DESTDIR=$OUTPUT_DIR ./x.py install
