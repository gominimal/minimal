let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let file = import "../file/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let lz4 = import "../lz4/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
    name = "zstd",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/zstd-1.5.6.tar.gz", 
            sha256 = "8c29e06cf42aacc1eafc4077ae2ec6c6fcb96a626157e0593d5e82a34fd403c1"
        } | Source,
        bash,
        binutils,
        coreutils,
        diffutils,
        file,
        gcc,
        glibc,
        grep,
        gzip,
        linux_headers,
        lz4,
        make,
        sed,
        tar,
        xz,
        zlib,
    ],
    cmd = "./build.source.sh",
    outputs = {
        zstd_bin = { glob = "usr/bin/zstd" } | OutputLib,
        zstdcat = { glob = "usr/bin/zstdcat" } | OutputLib,
        zstdgrep = { glob = "usr/bin/zstdgrep" } | OutputLib,
        zstdless = { glob = "usr/bin/zstdless" } | OutputLib,
        zstdmt = { glob = "usr/bin/zstdmt" } | OutputLib,
        unzstd = { glob = "usr/bin/unzstd" } | OutputLib,
        libzstd = { glob = "usr/lib/libzstd.so*" } | OutputLib,
        libzstd_a = { glob = "usr/lib/libzstd.a" } | OutputLib,
        headers = { glob = "usr/include/*.h" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/libzstd.pc" } | OutputLib,
    },
} | BuildSpec
