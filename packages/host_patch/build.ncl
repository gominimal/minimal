let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
{
    name = "host_patch",
    inputs = [
        {path = "/usr/bin/patch"} | HostPath,
        host_bash,
    ],
    cmd = "./build.sh",
    outputs = {
        patch = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
