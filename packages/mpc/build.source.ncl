let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "mpc",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/mpc-1.3.1.tar.gz",
            sha256 = "ab642492f5cf882b74aa0cb730cd410a81edcdbec895183ce930e706c1c759b8"
        } | Source,
        bash,
        coreutils,
        diffutils,
        gawk,
        grep,
        gzip,
        make,
        sed,
        tar,
        toolchain,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
    },
} | BuildSpec
