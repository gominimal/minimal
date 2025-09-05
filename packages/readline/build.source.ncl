let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "readline",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/readline-8.3.tar.gz",
            sha256 = "fe5383204467828cd495ee8d1d3c037a7eba1389c22bc6a041f627976f9061cc"
        } | Source,
        bash,
        coreutils,
        gawk,
        grep,
        gzip,
        make,
        ncurses,
        sed,
        tar,
        toolchain,
    ],
    cmd = "./build.source.sh",
    outputs = {
        libreadline = { glob = "usr/lib/libreadline.so*" } | OutputLib,
        libhistory = { glob = "usr/lib/libhistory.so*" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
        
        headers = { glob = "usr/include/readline/*.h" } | OutputLib,
    },
} | BuildSpec
