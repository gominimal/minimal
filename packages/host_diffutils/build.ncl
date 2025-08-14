let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
{
    name = "host_diffutils",
    inputs = [
        {path = "/usr/bin/diff"} | HostPath,
        host_bash,
    ],
    cmd = "./build.sh",
    outputs = {
        patch = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
