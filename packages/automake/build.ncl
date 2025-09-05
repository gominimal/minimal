let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let autoconf = import "../autoconf/build.ncl" in
let bash = import "../bash/build.ncl" in
let bzip2 = import "../bzip2/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let findutils = import "../findutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let xz = import "../xz/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "automake",
    inputs = [
        {
            url = "gs://minimal-staging-archives/automake-1.17.tar.xz",
            sha256 = "8920c1fc411e13b90bf704ef9db6f29d540e76d232cb3b2c9f4dc4cc599bd990"
        } | Source,
        {file = "build.sh"} | Local,
        autoconf,
        bash,
        bzip2,
        coreutils,
        diffutils,
        findutils,
        gawk,
        grep,
        gzip,
        m4,
        make,
        perl,
        sed,
        tar,
        toolchain,
        xz,
        zstd,
    ],
    cmd = "./build.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec
