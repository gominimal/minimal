let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
let host_coreutils = import "../host_coreutils/build.ncl" in
{
    name = "host_python",
    inputs = [
        {path = "/usr/bin/python3"} | HostPath,
        {path = "/usr/lib/python3.13"} | HostPath,
        host_bash,
        host_coreutils,
    ],
    cmd = "./build.sh",
    outputs = {
        python3 = { glob = "bin/*" } | OutputLib,
        python3_libs = { glob = "lib/**/*" } | OutputLib,
    },
} | BuildSpec
