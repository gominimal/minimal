let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let binutils = import "../binutils/build.ncl" in
let bison = import "../bison/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
# let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in 
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make = import "../make/build.ncl" in
let python = import "../python/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "glibc",
    inputs = [
        {file = "build.source.sh"} | Local,
        {file = "glibc-2.42.tar.xz"} | Local,
        binutils,
        bison,
        bash,
        coreutils,
        # gawk,
        gcc,
        glibc,
        grep,
        gzip,
        linux_headers,
        m4,
        make,
        python,
        sed,
        tar,
        xz,
    ],
    cmd = "./build.source.sh",
    outputs = {
        etc = { glob = "etc/**/*" } | OutputLib,
        lib64 = { glob = "lib64/**/*" } | OutputLib,
        sbin = { glob = "sbin/**/*" } | OutputLib,
        usr = { glob = "usr/**/*" } | OutputLib,
        var = { glob = "var/**/*" } | OutputLib,
    },
} | BuildSpec
