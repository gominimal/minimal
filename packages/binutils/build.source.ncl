let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "build.ncl" in
let bzip2 = import "../bzip2/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let dejagnu = import "../dejagnu/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let expect = import "../expect/build.ncl" in
let file = import "../file/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let xz = import "../xz/build.ncl" in
let zlib = import "../zlib/build.ncl" in
let pkgconf = import "../pkgconf/build.ncl" in
{
    name = "binutils",
    inputs = [
        {
            url = "gs://minimal-staging-archives/binutils-2.45.tar.xz",
            sha256 = "c50c0e7f9cb188980e2cc97e4537626b1672441815587f1eab69d2a1bfbef5d2"
        } | Source,
        {file = "build.source.sh"} | Local,
        bash,
        binutils,
        bzip2,
        coreutils,
        dejagnu,
        diffutils,
        expect,
        file,
        gawk,
        gcc,
        glibc,
        grep,
        linux_headers,
        make,
        sed,
        tar,
        xz,
        zlib,
        pkgconf,
    ],
    cmd = "./build.source.sh",
    outputs = {
        etc = { glob = "etc/*" } | OutputLib,
        usr_bin = { glob = "usr/bin/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/*" } | OutputLib,
        usr_lib_ldscripts = { glob = "usr/lib/ldscripts/*" } | OutputLib,
        usr_lib_gprofng = { glob = "usr/lib/gprofng/*" } | OutputLib,
        usr_lib_bfdplugins = { glob = "usr/lib/bfd-plugins/*" } | OutputLib,
        usr_include = { glob = "usr/include/*" } | OutputLib,
    },
} | BuildSpec
