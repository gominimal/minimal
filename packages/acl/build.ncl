let {BuildSpec, HostPath, OutputLib, Local, Source, Prebuilt, ..} = import "minimal.ncl" in
let attr = import "../attr/build.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "acl",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/acl-2.3.2.tar.xz",
            sha256 = "97203a72cae99ab89a067fe2210c1cbf052bc492b479eca7d226d9830883b0bd"
        } | Source,
        attr,
        bash,
        binutils,
        coreutils,
        gawk,
        gcc,
        glibc,
        gmp,
        grep,
        linux_headers,
        make,
        mpc,
        mpfr,
        sed,
        tar,
        xz,
        zstd,
    ],
    cmd = "./build.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec
