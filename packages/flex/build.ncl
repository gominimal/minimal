let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let make = import "../make/build.ncl" in
let m4 = import "../m4/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let binutils = import "../binutils/build.ncl" in 
let linux_headers = import "../linux_headers/build.ncl" in
let sed = import "../sed/build.ncl" in
let grep = import "../grep/build.ncl" in
let m4 = import "../m4/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let tar = import "../tar/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "flex",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/flex-2.6.4.tar.gz",
            sha256 = "e87aae032bf07c26f85ac0ed3250998c37621d95f8bd748b31f15b33c45ee995"
        } | Source,
        binutils,
        bash,
        coreutils,
        gcc,
        glibc,
        linux_headers,
        m4,
        make,
        sed,
        grep,
        m4,
        gawk,
        tar,
        gzip,
        mpc,
        mpfr,
        gmp,
        zstd,
    ],
    cmd = "./build.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec
