#!/bin/sh
set -e

tar xf setuptools-80.9.0.tar.gz
cd setuptools-80.9.0

pip3 wheel -w dist --no-cache-dir --no-build-isolation --no-deps $PWD
pip3 install --root $OUTPUT_DIR --no-index --find-links dist setuptools
