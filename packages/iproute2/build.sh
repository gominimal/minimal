#!/bin/sh
set -e

tar xfo iproute2-6.13.0.tar.xz
cd iproute2-6.13.0

make NETNS_RUN_DIR=/run/netns -j$(nproc)
make SBINDIR=/usr/sbin DESTDIR=$OUTPUT_DIR install
