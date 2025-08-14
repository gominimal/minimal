let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
{
    name = "host_xz",
    inputs = [
        {path = "/usr/bin/xz"} | HostPath,
        host_bash,
        host_coreutils,
    ],
    cmd = "./build.sh",
    outputs = {
        gzip = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
