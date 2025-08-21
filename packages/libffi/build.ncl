let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
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
{
    name = "libffi",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "libffi-3.5.2.tar.gz"} | Local,
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
    ],
    cmd = "./build.sh",
    outputs = {
        lib = { glob = "usr/lib/*" } | OutputLib,
        include = { glob = "usr/include/*" } | OutputLib,
    },
} | BuildSpec
