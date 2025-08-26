let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let make = import "../make/build.ncl" in
let tar = import "../tar/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let sed = import "../sed/build.ncl" in
let grep = import "../grep/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
let gawk = import "../gawk/build.ncl" in
{
    name = "libffi",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/libffi-3.5.2.tar.gz",
            sha256 = "f3a3082a23b37c293a4fcd1053147b371f2ff91fa7ea1b2a52e335676bac82dc"
        } | Source,
        bash,
        coreutils,
        make,
        tar,
        gzip,
        sed,
        grep,
        glibc,
        gcc,
        binutils,
        linux_headers,
        mpc,
        mpfr,
        gmp,
        zstd,
        gawk,
    ],
    cmd = "./build.sh",
    outputs = {
        lib = { glob = "usr/lib/*" } | OutputLib,
        include = { glob = "usr/include/*" } | OutputLib,
    },
} | BuildSpec
