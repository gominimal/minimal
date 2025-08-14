let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_patch = import "../host_patch/build.ncl" in
{
    name = "bzip2",
    inputs = [
        {path = "/usr/bin/sh"} | HostPath,
        host_coreutils,
        host_bash,
        host_patch,
    ],
    cmd = "./build.sh",
    outputs = {
        bzip2_bin = { glob = "bin/bzip2" } | OutputLib,
        bzcat = { glob = "bin/bzcat" } | OutputLib,
        bunzip2 = { glob = "bin/bunzip2" } | OutputLib,
        bzip2recover = { glob = "bin/bzip2recover" } | OutputLib,
        bzdiff = { glob = "bin/bzdiff" } | OutputLib,
        bzgrep = { glob = "bin/bzgrep" } | OutputLib,
        bzmore = { glob = "bin/bzmore" } | OutputLib,
        bzless = { glob = "bin/bzless" } | OutputLib,
        libbz2 = { glob = "lib/libbz2.so*" } | OutputLib,
        headers = { glob = "include/*.h" } | OutputLib,
    },
} | BuildSpec
