#!/bin/sh
set -ex

tar -xzf ssl-certs-complete.tar.gz

# Copy the complete certs directory structure to output
mkdir -p "$OUTPUT_DIR/etc/ssl"
cp -r certs "$OUTPUT_DIR/etc/ssl/"

# Create symbolic links for certificate hashes (common practice)
cd "$OUTPUT_DIR/etc/ssl/certs"
for cert in *.crt; do
    # Get certificate hash and create symlink
    hash=$(openssl x509 -hash -noout -in "$cert" 2>/dev/null || echo "skip")
    if [ "$hash" != "skip" ]; then
        ln -sf "$cert" "${hash}.0"
    fi
done
