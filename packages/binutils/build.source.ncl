let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
    name = "binutils",
    inputs = [
        {file = "binutils-2.45.tar.xz"} | Local,
        {file = "build.source.sh"} | Local,
        bash,
        binutils,
        coreutils,
        gcc,
        glibc,
        grep,
        linux_headers,
        make,
        sed,
        zlib,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec
