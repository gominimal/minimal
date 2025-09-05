let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "expat",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/expat-2.7.1.tar.xz",
            sha256 = "354552544b8f99012e5062f7d570ec77f14b412a3ff5c7d8d0dae62c0d217c30"
        } | Source,
        bash,
        coreutils,
        gawk,
        grep,
        make,
        sed,
        tar,
        toolchain,
        xz,
    ],
    cmd = "./build.sh",
    outputs = {
        xmlwf = { glob = "usr/bin/xmlwf" } | OutputLib,
        library = { glob = "usr/lib/libexpat.so*" } | OutputLib,
        headers = { glob = "usr/include/expat*.h" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/expat.pc" } | OutputLib,
    },
} | BuildSpec
