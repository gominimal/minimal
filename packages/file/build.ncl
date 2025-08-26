let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let make = import "../make/build.ncl" in
let grep = import "../grep/build.ncl" in
let tar = import "../tar/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let sed = import "../sed/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "file",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/file-5.46.tar.gz",
            sha256 = "c9cc77c7c560c543135edc555af609d5619dbef011997e988ce40a3d75d86088"
        } | Source,
        bash,
        coreutils,
        make,
        grep,
        tar,
        gzip,
        sed,
        gcc,
        glibc,
        binutils,
        linux_headers,
        gawk,
        mpc,
        mpfr,
        gmp,
        zstd,
    ],
    cmd = "./build.sh",
    outputs = {
        file_bin = { glob = "usr/bin/file" } | OutputLib,
        libmagic = { glob = "usr/lib/libmagic.so*" } | OutputLib,
        headers = { glob = "usr/include/magic.h" } | OutputLib,
        magic_data = { glob = "usr/share/misc/magic*" } | OutputLib,
    },
} | BuildSpec
