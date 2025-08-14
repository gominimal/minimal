let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
let host_bash = import "../host_bash/build.ncl" in
{
    name = "host_tar",
    inputs = [
        {path = "/usr/bin/tar"} | HostPath,
        host_coreutils,
        host_bash,
    ],
    cmd = "./build.sh",
    outputs = {
        tar = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
