let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let readline = import "../readline/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
{
    name = "bash",
    inputs = [
        {file = "build.source.sh"} | Local,
        {file = "bash-5.3.tar.gz"} | Local,
        bash,
        binutils,
        coreutils,
        gawk,
        gcc,
        glibc,
        grep,
        gzip,
        linux_headers,
        make,
        readline,
        sed,
        tar,
    ],
    cmd = "./build.source.sh",
    outputs = {
        bin_sh  = { glob = "bin/sh" },
        usr_bin = { glob = "usr/bin/**/*" },
        usr_lib = { glob = "usr/lib/**/*" },
        usr_share = { glob = "usr/share/**/*" },
        usr_include = { glob = "usr/include/**/*" },
    },
} | BuildSpec
