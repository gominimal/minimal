let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let binutils = import "../binutils/build.ncl" in 
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in 
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in 
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in 
let sed = import "../sed/build.ncl" in 
let tar = import "../tar/build.ncl" in 
let xz = import "../xz/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "findutils",
    inputs = [
        {
            url = "gs://minimal-staging-archives/findutils-4.10.0.tar.xz",
            sha256 = "1387e0b67ff247d2abde998f90dfbf70c1491391a59ddfecb8ae698789f0a4f5"
        } | Source,
        {file = "build.sh"} | Local,
        binutils,
        bash,
        coreutils,
        gawk,
        gcc,
        glibc,
        grep,
        linux_headers,
        make,
        sed,
        tar,
        xz,
        mpc,
        mpfr,
        gmp,
        zstd,
    ],
    cmd = "./build.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" },
        usr_libexec = { glob = "usr/libexec/**/*" },
        usr_share = { glob = "usr/share/**/*" },
    },
} | BuildSpec
