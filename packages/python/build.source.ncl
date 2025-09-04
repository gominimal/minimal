let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let make = import "../make/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let sed = import "../sed/build.ncl" in
let grep = import "../grep/build.ncl" in
let libffi = import "../libffi/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let pkgconf = import "../pkgconf/build.ncl" in
let gawk = import "../gawk/build.ncl" in
{
    name = "python",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/Python-3.13.7.tar.xz",
            sha256 = "5462f9099dfd30e238def83c71d91897d8caa5ff6ebc7a50f14d4802cdaaa79a"
        } | Source,
        bash,
        coreutils,
        make,
        tar,
        xz,
        sed,
        grep,
        libffi,
        binutils,
        gcc,
        glibc,
        linux_headers,
        ncurses,
        pkgconf,
        gawk,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
    },
} | BuildSpec
