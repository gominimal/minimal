#!/bin/sh
set -e

tar xf meson-1.9.0.tar.gz
cd meson-1.9.0

pip3 wheel -w dist --no-cache-dir --no-build-isolation --no-deps $PWD

pip3 install --root $OUTPUT_DIR --no-index --find-links dist meson
