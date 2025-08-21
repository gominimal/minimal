let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let make = import "../make/build.ncl" in
let grep = import "../grep/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let gawk = import "../gawk/build.ncl" in
{
    name = "m4",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "m4-1.4.20.tar.xz"} | Local,
        bash,
        coreutils,
        make,
        grep,
        sed,
        tar,
        xz,
        glibc,
        gcc,
        binutils,
        linux_headers,
        gawk,
    ],
    cmd = "./build.sh",
    outputs = {
        m4_bin = { glob = "usr/bin/m4" } | OutputLib,
        m4_man = { glob = "usr/share/man/man1/m4.1" } | OutputLib,
        m4_info = { glob = "usr/share/info/m4.info*" } | OutputLib,
    },
} | BuildSpec
