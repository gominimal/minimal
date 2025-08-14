let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
{
    name = "host_gawk",
    inputs = [
        {path = "/usr/bin/gawk"} | HostPath,
        host_bash,
        host_coreutils,
    ],
    cmd = "./build.sh",
    outputs = {
        patch = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
