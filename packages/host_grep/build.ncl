let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
{
    name = "host_grep",
    inputs = [
        {path = "/usr/bin/grep"} | HostPath,
        {path = "/usr/bin/egrep"} | HostPath,
        host_bash,

    ],
    cmd = "./build.sh",
    outputs = {
        patch = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
