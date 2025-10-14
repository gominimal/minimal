#!/bin/sh
set -ex

mkdir -p $OUTPUT_DIR/etc/ssl/certs
cat > $OUTPUT_DIR/etc/resolv.conf << "EOF"
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

cat > $OUTPUT_DIR/etc/hosts << "EOF"
127.0.0.1   localhost
::1         localhost
EOF
