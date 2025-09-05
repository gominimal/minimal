let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let file = import "../file/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "gmp",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/gmp-6.3.0.tar.xz",
            sha256 = "a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898"
        } | Source,
        bash,
        coreutils,
        diffutils,
        file,
        gawk,
        grep,
        m4,
        make,
        sed,
        tar,
        toolchain,
        xz,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
    },
} | BuildSpec
