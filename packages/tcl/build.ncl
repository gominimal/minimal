let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "tcl",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/tcl8.6.16-src.tar.gz", 
            sha256 = "91cb8fa61771c63c262efb553059b7c7ad6757afa5857af6265e4b0bdc2a14a5"
        } | Source,
        bash,
        coreutils,
        gawk,
        grep,
        gzip,
        make,
        sed,
        tar,
        toolchain,
    ],
    cmd = "./build.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec
