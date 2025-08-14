let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
{
    name = "host_tar",
    inputs = [
        host_bash,
    ],
    cmd = "./build.sh",
    outputs = {
        tar = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
