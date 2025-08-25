let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let binutils = import "../binutils/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "diffutils",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "diffutils-3.12.tar.xz"} | Local,
        binutils,
        bash,
        coreutils,
        gawk,
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
    ],
    cmd = "./build.sh",
    outputs = {
        cmp = { glob = "usr/bin/cmp" } | OutputLib,
        diff = { glob = "usr/bin/diff" } | OutputLib,
        diff3 = { glob = "usr/bin/diff3" } | OutputLib,
        sdiff = { glob = "usr/bin/sdiff" } | OutputLib,

        info = { glob = "usr/share/info/*.info*" } | OutputLib,
        man = { glob = "usr/share/man/man1/*.1" } | OutputLib,
        locales = { glob = "usr/share/locale/**/*" } | OutputLib,
    },
} | BuildSpec
