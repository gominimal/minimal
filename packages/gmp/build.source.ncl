let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let binutils = import "../binutils/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let grep = import "../grep/build.ncl" in
let m4 = import "../m4/build.ncl" in
{
    name = "gmp",
    inputs = [
        {file = "build.source.sh"} | Local,
        {file = "gmp-6.3.0.tar.xz"} | Local,
        binutils,
        bash,
        coreutils,
        gcc,
        glibc,
        linux_headers,
        make,
        sed,
        tar,
        xz,
        grep,
        m4,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
    },
} | BuildSpec
