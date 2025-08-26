let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let make = import "../make/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let grep = import "../grep/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "readline",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/readline-8.3.tar.gz",
            sha256 = "fe5383204467828cd495ee8d1d3c037a7eba1389c22bc6a041f627976f9061cc"
        } | Source,
        bash,
        coreutils,
        make,
        ncurses,
        grep,
        sed,
        tar,
        gzip,
        glibc,
        gcc,
        binutils,
        linux_headers,
        gawk,
        mpc,
        mpfr,
        gmp,
        zstd,
    ],
    cmd = "./build.sh",
    outputs = {
        libreadline = { glob = "usr/lib/libreadline.so*" } | OutputLib,
        libhistory = { glob = "usr/lib/libhistory.so*" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
        
        headers = { glob = "usr/include/readline/*.h" } | OutputLib,
    },
} | BuildSpec
