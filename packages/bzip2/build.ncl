let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
    name = "bzip2",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "bzip2-1.0.8.tar.gz"} | Local,
        bash,
        coreutils,
        diffutils,
        make,
        sed,
        tar,
        gzip,
        gcc,
        glibc,
        binutils,
        linux_headers,
        mpc,
        mpfr,
        gmp,
        zstd,
    ],
    cmd = "./build.sh",
    outputs = {
        bunzip2 = { glob = "usr/bin/bunzip2" } | OutputLib,
        bzcat = { glob = "usr/bin/bzcat" } | OutputLib,
        bzcmp = { glob = "usr/bin/bzcmp" } | OutputLib,
        bzdiff = { glob = "usr/bin/bzdiff" } | OutputLib,
        bzegrep = { glob = "usr/bin/bzegrep" } | OutputLib,
        bzfgrep = { glob = "usr/bin/bzfgrep" } | OutputLib,
        bzgrep = { glob = "usr/bin/bzgrep" } | OutputLib,
        bzip2 = { glob = "usr/bin/bzip2" } | OutputLib,
        bzip2recover = { glob = "usr/bin/bzip2recover" } | OutputLib,
        bzless = { glob = "usr/bin/bzless" } | OutputLib,
        bzmore = { glob = "usr/bin/bzmore" } | OutputLib,
        
        libbz2 = { glob = "usr/lib/libbz2.so*" } | OutputLib,
        
        headers = { glob = "usr/include/bzlib.h" } | OutputLib,
    },
} | BuildSpec
