let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
# let acl = import "../acl/build.ncl" in # dangerous unless acl is a prebuilt
# let attr = import "../attr/build.ncl" in # TODO required for attr
let binutils = import "../binutils/build.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let grep = import "../grep/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "build.ncl" in
{
    name = "sed",
    inputs = [
        {file = "build.source.sh"} | Local,
        {file = "sed-4.9.tar.xz"} | Local,
        # acl,
        # attr,
        binutils,
        bash,
        coreutils,
        gawk,
        gcc,
        glibc,
        grep,
        linux_headers,
        make,
        sed,
    ],
    cmd = "./build.source.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec
