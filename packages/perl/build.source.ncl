let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let binutils = import "../binutils/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
# let bzip2 = import "../bzip2/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
# let zlib = import "../zlib/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "perl",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/perl-5.42.0.tar.xz",
            sha256 = "73cf6cc1ea2b2b1c110a18c14bbbc73a362073003893ffcedc26d22ebdbdd0c3"
        } | Source,
        binutils,
        bash,
        coreutils,
    #     bzip2,
        gawk,
        gcc,
        glibc,
        grep,
        linux_headers,
        make,
        sed,
        tar,
        xz,
    #     zlib,
        mpc,
        mpfr,
        gmp,
        zstd,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec
