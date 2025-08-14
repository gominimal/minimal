let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
{
    name = "host_sed",
    inputs = [
        host_sed,
    ],
    cmd = "./build.sh",
    outputs = {
        sed = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
