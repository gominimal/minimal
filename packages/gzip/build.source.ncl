let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "gzip",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/gzip-1.14.tar.xz",
            sha256 = "01a7b881bd220bfdf615f97b8718f80bdfd3f6add385b993dcf6efd14e8c0ac6"
        } | Source,
        bash,
        coreutils,
        diffutils,
        gawk,
        grep,
        make,
        sed,
        tar,
        toolchain,
        xz,
    ],
    cmd = "./build.source.sh",
    outputs = {
        binaries = { glob = "usr/bin/*" } | OutputLib,
        info = { glob = "usr/share/info/*.info" } | OutputLib,
        man = { glob = "usr/share/man/man1/*.1" } | OutputLib,
    },
} | BuildSpec
