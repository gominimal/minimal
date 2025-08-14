let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
{
    name = "grep",
    inputs = [
        host_bash,
    ],
    cmd = "./build.sh",
    outputs = {
        grep_bin = { glob = "bin/grep" } | OutputLib,
        egrep_bin = { glob = "bin/egrep" } | OutputLib,
        fgrep_bin = { glob = "bin/fgrep" } | OutputLib,
    },
} | BuildSpec
