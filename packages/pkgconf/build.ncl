let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
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
    name = "pkgconf",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/pkgconf-2.5.1.tar.xz",
            sha256 = "cd05c9589b9f86ecf044c10a2269822bc9eb001eced2582cfffd658b0a50c243"
        } | Source,
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
        pkgconf = { glob = "usr/bin/pkgconf" } | OutputLib,
        library = { glob = "usr/lib/libpkgconf.so*" } | OutputLib,
        headers = { glob = "usr/include/pkgconf/libpkgconf/*.h" } | OutputLib,
        man_pages = { glob = "usr/share/man/man1/*.1" } | OutputLib,
    },
} | BuildSpec
