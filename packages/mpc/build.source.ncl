let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let binutils = import "../binutils/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make = import "../make/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "mpc",
    inputs = [
        {file = "build.source.sh"} | Local,
        {file = "mpc-1.3.1.tar.gz"} | Local,
        binutils,
        bash,
        coreutils,
        gcc,
        glibc,
        gmp,
        grep,
        linux_headers,
        m4,
        make,
        mpfr,
        sed,
        tar,
        xz,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
    },
} | BuildSpec
