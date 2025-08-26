let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "make",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/make-4.4.1.tar.gz",
            sha256 = "dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3"
        } | Source,
        bash,
        binutils,
        coreutils,
        gawk,
        gcc,
        glibc,
        gmp,
        grep,
        gzip,
        linux_headers,
        make,
        mpc,
        mpfr,
        sed,
        tar,
        zstd,
    ],
    cmd = "./build.source.sh",
    outputs = {
        make_bin = { glob = "usr/bin/make" } | OutputLib,
        headers = { glob = "usr/include/*.h" } | OutputLib,
        info_pages = { glob = "usr/share/info/*.info*" } | OutputLib,
        man_pages = { glob = "usr/share/man/man1/*.1" } | OutputLib,
        locale_files = { glob = "usr/share/locale/*/LC_MESSAGES/*.mo" } | OutputLib,
    },
} | BuildSpec
