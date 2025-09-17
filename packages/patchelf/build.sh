#!/bin/sh
set -e

tar xfo b49de1b3384e7928bf0df9a889fe5a4e7b3fbddf.tar.gz
cd patchelf-b49de1b3384e7928bf0df9a889fe5a4e7b3fbddf

mkdir build
cd build
cmake .. -GNinja -DCMAKE_INSTALL_PREFIX=/usr
ninja all

DESTDIR=$OUTPUT_DIR ninja install
