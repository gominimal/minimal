let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
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
{
    name = "readline",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "readline-8.3.tar.gz"} | Local,
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
    ],
    cmd = "./build.sh",
    outputs = {
        libreadline = { glob = "usr/lib/libreadline.so*" } | OutputLib,
        libhistory = { glob = "usr/lib/libhistory.so*" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
        
        headers = { glob = "usr/include/readline/*.h" } | OutputLib,
    },
} | BuildSpec
