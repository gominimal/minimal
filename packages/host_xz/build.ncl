let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
let host_gawk = import "../host_gawk/build.ncl" in
let host_grep = import "../host_grep/build.ncl" in
let host_make = import "../host_make/build.ncl" in
{
    name = "host_xz",
    inputs = [
        {path = "/usr/bin/xz"} | HostPath,
        host_bash,
        host_coreutils,
        host_gawk,
        host_grep,
        host_make,
    ],
    cmd = "./build.sh",
    outputs = {
        gzip = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
