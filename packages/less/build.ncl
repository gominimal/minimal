let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
{
    name = "less",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/less-679.tar.gz",
            sha256 = "9b68820c34fa8a0af6b0e01b74f0298bcdd40a0489c61649b47058908a153d78"
        } | Source,
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
        ncurses,
        sed,
        tar,
    ],
    cmd = "./build.sh",
    outputs = {
        bin = { glob = "usr/bin/*" } | OutputLib,
        man = { glob = "usr/share/man/**/*" } | OutputLib,
    },
} | BuildSpec