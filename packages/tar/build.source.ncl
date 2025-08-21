let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let acl = import "../make/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let make = import "../make/build.ncl" in
let grep = import "../grep/build.ncl" in
let sed = import "../sed/build.ncl" in
# let tar = import "build.ncl" in
# let xz = import "../xz/build.ncl" in
# TODO removed perl dep to break dependency cycle
# let perl = import "../perl/build.ncl" in
# let texinfo = import "../texinfo/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let binutils = import "../binutils/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
{
    name = "tar",
    inputs = [
        {file = "build.source.sh"} | Local,
        {file = "tar-1.35.tar.xz"} | Local,
        acl,
        bash,
        coreutils,
        make,
        grep,
        sed,
        # tar,
        # xz,
        glibc,
        gcc,
        binutils,
        linux_headers,
    ],
    cmd = "./build.source.sh",
    outputs = {
        tar = { glob = "usr/bin/tar" } | OutputLib,
        rmt = { glob = "usr/libexec/rmt" } | OutputLib,
        info = { glob = "usr/share/info/tar.info*" } | OutputLib,
        locale_files = { glob = "usr/share/locale/**/*" } | OutputLib,
    },
} | BuildSpec
