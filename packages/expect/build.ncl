let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_patch = import "../host_patch/build.ncl" in
let tcl = import "../tcl/build.ncl" in
{
    name = "expect",
    inputs = [
        host_bash,
        host_patch,
        tcl,
    ],
    cmd = "./build.sh",
    outputs = {
        expect_bin = { glob = "bin/expect" } | OutputLib,
        expect_lib = { glob = "lib/expect*" } | OutputLib,
        libexpect = { glob = "lib/libexpect*.so*" } | OutputLib,
        expect_man = { glob = "share/man/man1/expect.1" } | OutputLib,
        expect_man3 = { glob = "share/man/man3/libexpect.3" } | OutputLib,
    },
} | BuildSpec
