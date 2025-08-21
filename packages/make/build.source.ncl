let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let make = import "../make/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let sed = import "../sed/build.ncl" in
let grep = import "../grep/build.ncl" in
{
    name = "make",
    inputs = [
        {file = "build.source.sh"} | Local,
        {file = "make-4.4.1.tar.gz"} | Local,
        bash,
        coreutils,
        make,
        glibc,
        gcc,
        binutils,
        linux_headers,
        sed,
        grep,
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
