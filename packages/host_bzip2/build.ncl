let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
{
    name = "host_bzip2",
    inputs = [
        {path = "/usr/bin/bzip2"} | HostPath,
        host_bash,
        host_coreutils,
    ],
    cmd = "./build.sh",
    outputs = {
        gzip = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
