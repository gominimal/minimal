let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let make = import "../make/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let sed = import "../sed/build.ncl" in
let grep = import "../grep/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "expat",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "expat-2.7.1.tar.xz"} | Local,
        bash,
        coreutils,
        make,
        glibc,
        gcc,
        binutils,
        linux_headers,
        sed,
        grep,
        gawk,
        tar,
        xz,
        mpc,
        mpfr,
        gmp,
        zstd,
    ],
    cmd = "./build.sh",
    outputs = {
        xmlwf = { glob = "usr/bin/xmlwf" } | OutputLib,
        library = { glob = "usr/lib/libexpat.so*" } | OutputLib,
        headers = { glob = "usr/include/expat*.h" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/expat.pc" } | OutputLib,
    },
} | BuildSpec
