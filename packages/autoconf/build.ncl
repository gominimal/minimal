let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make = import "../make/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let perl = import "../perl/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "autoconf",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/autoconf-2.72.tar.xz",
            sha256 = "ba885c1319578d6c94d46e9b0dceb4014caafe2490e437a0dbca3f270a223f5a"
        } | Source,
        bash,
        binutils,
        coreutils,
        gawk,
        gcc,
        glibc,
        gmp,
        grep,
        linux_headers,
        m4,
        make,
        mpc,
        mpfr,
        perl,
        sed,
        tar,
        xz,
    ],
    cmd = "./build.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec
