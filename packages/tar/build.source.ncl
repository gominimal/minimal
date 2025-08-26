let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let acl = import "../make/build.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let gawk = import "../gawk/build.ncl" in
{
    name = "tar",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/tar-1.35.tar.xz",
            sha256 = "4d62ff37342ec7aed748535323930c7cf94acf71c3591882b26a7ea50f3edc16"
        } | Source,
        acl,
        bash,
        binutils,
        coreutils,
        gcc,
        glibc,
        grep,
        linux_headers,
        make,
        sed,
        tar,
        xz,
        mpc,
        mpfr,
        gmp,
        zstd,
        gawk,
    ],
    cmd = "./build.source.sh",
    outputs = {
        tar = { glob = "usr/bin/tar" } | OutputLib,
        rmt = { glob = "usr/libexec/rmt" } | OutputLib,
        info = { glob = "usr/share/info/tar.info*" } | OutputLib,
        locale_files = { glob = "usr/share/locale/**/*" } | OutputLib,
    },
} | BuildSpec
