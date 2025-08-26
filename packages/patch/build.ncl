let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
# TODO depend on attr once runtime deps are functional
# otherwise every usage of patch requires importing attr
# let attr = import "../attr/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let bash = import "../bash/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "patch",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/patch-2.8.tar.xz",
            sha256 = "intentionally_bad_value"
        } | Source,
        bash,
        coreutils,
        gawk,
        grep,
        make,
        sed,
        tar,
        xz,
        glibc,
        gcc,
        binutils,
        linux_headers,
        mpc,
        mpfr,
        gmp,
        zstd,
    ],
    cmd = "./build.sh",
    outputs = {
        patch = { glob = "usr/bin/patch" } | OutputLib,
        man = { glob = "usr/share/man/man1/patch.1" } | OutputLib,
    },
} | BuildSpec
