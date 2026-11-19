#!/bin/sh
# Build esapi-bench as a static musl binary on Alpine (aarch64), against
# tpm2-tss 4.1.3 built from source with --enable-nodl and the device TCTI
# only. Run in alpine:3.22 with the crate at /src and an output dir at /out:
#   docker run --rm -v $PWD/esapi-bench:/src:ro -v $PWD/out:/out \
#     -v $PWD/static-musl-build.sh:/s.sh:ro alpine:3.22 sh /s.sh
set -eu
apk add -q rust cargo pkgconf clang-dev openssl-dev openssl-libs-static json-c-dev curl-dev util-linux-dev build-base autoconf automake libtool autoconf-archive linux-headers swtpm file git >/dev/null
cd /tmp && wget -q https://github.com/tpm2-software/tpm2-tss/releases/download/4.1.3/tpm2-tss-4.1.3.tar.gz && tar xzf tpm2-tss-4.1.3.tar.gz && cd tpm2-tss-4.1.3
./configure -q --prefix=/opt/tss --enable-nodl --enable-static --disable-shared --disable-fapi --disable-policy --disable-doxygen-doc --disable-tcti-cmd --disable-tcti-swtpm --disable-tcti-mssim --disable-tcti-pcap --disable-tcti-spi-helper --disable-tcti-spi-ltt2go --disable-tcti-spidev --disable-tcti-i2c-helper --disable-tcti-i2c-ftdi --disable-tcti-libtpms --with-crypto=ossl >/tmp/conf.log 2>&1 || { tail -20 /tmp/conf.log; exit 1; }
make -s -j"$(nproc)" >/tmp/make.log 2>&1 || { grep -m5 -i error /tmp/make.log; exit 1; }
make -s install >/dev/null 2>&1
for a in /opt/tss/lib/*.a; do printf '%s ' "${a##*/}"; done; echo
cp -r /src /b && cd /b && rm -rf target
echo "== static build against tpm2-tss --enable-nodl"
PKG_CONFIG_PATH=/opt/tss/lib/pkgconfig PKG_CONFIG_ALL_STATIC=1 RUSTFLAGS="-C target-feature=+crt-static -L /opt/tss/lib -C link-arg=-Wl,--start-group -C link-arg=-ltss2-esys -C link-arg=-ltss2-tctildr -C link-arg=-ltss2-sys -C link-arg=-ltss2-mu -C link-arg=-ltss2-rc -C link-arg=-ltss2-tcti-device -C link-arg=-lcrypto -C link-arg=-Wl,--end-group" cargo build --release -q --target aarch64-alpine-linux-musl >/tmp/cargo.log 2>&1 || {
    grep -E "^error|undefined|multiple|ld:" /tmp/cargo.log | grep -v "^error: could not" | head -12
    echo "error: the static build failed" >&2
    exit 1
}
B=target/aarch64-alpine-linux-musl/release/esapi-bench
[ -f "$B" ] || { echo "error: the build made no binary" >&2; exit 1; }
file "$B" | sed 's/BuildID.*//'; wc -c <"$B"
cp "$B" /out/esapi-bench-static-device
