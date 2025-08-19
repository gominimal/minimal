let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../sed/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../coreutils/build.ncl" in
let tar = import "../tar/build.ncl" in
let tcl = import "../tcl/build.ncl" in
{
    name = "expect",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "expect5.45.4.tar.gz"} | Local,
        bash,
        coreutils,
        grep,
        gzip,
        make,
        sed,
        tar,
        tcl,
    ],
    cmd = "./build.sh",
    outputs = {
        library = { glob = "usr/lib/libexpect*.so*" } | OutputLib,
        expect_library = { glob = "usr/lib/expect*/*" } | OutputLib,
        binary = { glob = "usr/bin/expect" } | OutputLib,
        manpages = { glob = "usr/share/man/man*/*" } | OutputLib,
    },
} | BuildSpec
