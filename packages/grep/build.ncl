let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "grep",
    inputs = [
        {path = "/usr"} | HostPath,
    ],
    cmd = "/.build.sh",
    outputs = {
        grep_bin = { glob = "bin/grep" } | OutputLib,
        egrep_bin = { glob = "bin/egrep" } | OutputLib,
        fgrep_bin = { glob = "bin/fgrep" } | OutputLib,
    },
} | BuildSpec
