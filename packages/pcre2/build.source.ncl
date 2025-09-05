let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let bzip2 = import "../bzip2/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let zlib = import "../zlib/build.ncl" in
{
    name = "pcre2",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/pcre2-10.46.tar.bz2",
            sha256 = "15fbc5aba6beee0b17aecb04602ae39432393aba1ebd8e39b7cabf7db883299f"
        } | Source,
        bash,
        binutils,
        bzip2,
        coreutils,
        diffutils,
        gawk,
        gcc,
        glibc,
        grep,
        linux_headers,
        make,
        sed,
        tar,
        zlib,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
    },
} | BuildSpec
