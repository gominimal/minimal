let {BuildSpec, HostPath, OutputLib, Local, Source, Prebuilt, ..} = import "minimal.ncl" in
let binutils = import "../binutils/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "zlib",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/zlib-1.3.1.tar.gz", 
            sha256 = "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
        } | Source,
        binutils,
        bash,
        coreutils,
        gcc,
        glibc,
        gzip,
        linux_headers,
        make,
        sed,
        tar,
        mpc,
        mpfr,
        gmp,
        zstd,
    ],
    cmd = "./build.source.sh",
    outputs = {
        libz = { glob = "usr/lib/libz.so*" } | OutputLib,
        zconf_h = { glob = "usr/include/zconf.h" } | OutputLib,
        zlib_h = { glob = "usr/include/zlib.h" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/zlib.pc" } | OutputLib,
    },
} | BuildSpec
