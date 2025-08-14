let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
{
    name = "host_make",
    inputs = [
        {path = "/usr/bin/make"} | HostPath,
        host_bash,
        host_coreutils,
    ],
    cmd = "./build.sh",
    outputs = {
        make = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
