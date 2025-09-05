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
    name = "findutils",
    inputs = [
        {
            url = "gs://minimal-staging-archives/findutils-4.10.0.tar.xz",
            sha256 = "1387e0b67ff247d2abde998f90dfbf70c1491391a59ddfecb8ae698789f0a4f5"
        } | Source,
        {file = "build.source.sh"} | Local,
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
        usr_bin = { glob = "usr/bin/**/*" },
        usr_libexec = { glob = "usr/libexec/**/*" },
        usr_share = { glob = "usr/share/**/*" },
    },
} | BuildSpec
