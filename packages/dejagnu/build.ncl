let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let tcl = import "../tcl/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "expect",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/dejagnu-1.6.3.tar.gz",
            sha256 = "87daefacd7958b4a69f88c6856dbd1634261963c414079d0c371f589cd66a2e3"
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
        usr_bin = { glob  = "usr/bin/*" } | OutputLib,
        usr_include = { glob = "usr/include/*" } | OutputLib,
        usr_share_dejagnu = { glob = "usr/share/dejagnu/**/*" } | OutputLib,
    },
} | BuildSpec
