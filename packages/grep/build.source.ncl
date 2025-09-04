let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let make = import "../make/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let sed = import "../sed/build.ncl" in
let grep = import "../grep/build.ncl" in
let gawk = import "../gawk/build.ncl" in
{
    name = "grep",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/grep-3.12.tar.xz",
            sha256 = "2649b27c0e90e632eadcd757be06c6e9a4f48d941de51e7c0f83ff76408a07b9"
        } | Source,
        bash,
        binutils,
        coreutils,
        gcc,
        glibc,
        linux_headers,
        make,
        tar,
        xz,
        sed,
        grep,
        gawk,
    ],
    cmd = "./build.source.sh",
    outputs = {
        grep_bin = { glob = "usr/bin/grep" } | OutputLib,
        egrep_bin = { glob = "usr/bin/egrep" } | OutputLib,
        fgrep_bin = { glob = "usr/bin/fgrep" } | OutputLib,
    },
} | BuildSpec
