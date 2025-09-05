let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
{
    name = "gdbm",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/gdbm-1.26.tar.gz",
            sha256 = "6a24504a14de4a744103dcb936be976df6fbe88ccff26065e54c1c47946f4a5e"
        } | Source,
        bash,
        binutils,
        coreutils,
        diffutils,
        gawk,
        gcc,
        glibc,
        grep,
        gzip,
        linux_headers,
        make,
        sed,
        tar,
    ],
    cmd = "./build.sh",
    outputs = {
        bin = { glob = "usr/bin/*" } | OutputLib,
        lib = { glob = "usr/lib/*" } | OutputLib,
        include = { glob = "usr/include/**/*" } | OutputLib,
        man = { glob = "usr/share/man/**/*" } | OutputLib,
        info = { glob = "usr/share/info/*" } | OutputLib,
    },
} | BuildSpec