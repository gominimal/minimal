let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let readline = import "../readline/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "bash",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/bash-5.3.tar.gz",
            sha256 = "0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba"
        } | Source,
        bash,
        coreutils,
        diffutils,
        gawk,
        grep,
        gzip,
        make,
        readline,
        sed,
        tar,
        toolchain,
    ],
    cmd = "./build.source.sh",
    outputs = {
        bin = { glob = "bin/**/*" },
        usr_bin = { glob = "usr/bin/**/*" },
        usr_lib = { glob = "usr/lib/**/*" },
        usr_share = { glob = "usr/share/**/*" },
        usr_include = { glob = "usr/include/**/*" },
    },
} | BuildSpec
