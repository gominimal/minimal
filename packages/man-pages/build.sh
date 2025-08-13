#!/bin/bash

set -e

tar xf man-pages-6.15.tar.xz
cd man-pages-6.15

rm -v man3/crypt*

make -R GIT=false prefix="$OUTPUT_DIR" install

echo "Man-pages installation complete"
