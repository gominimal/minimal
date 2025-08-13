let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "grep",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/xz"} | HostPath,
        {path = "/usr/bin/sed"} | HostPath,
        {path = "/usr/bin/make"} | HostPath,
    ],
    cmd = "build.sh",
    outputs = {
        grep_bin = { glob = "bin/grep" } | OutputLib,
        egrep_bin = { glob = "bin/egrep" } | OutputLib,
        fgrep_bin = { glob = "bin/fgrep" } | OutputLib,
    },
} | BuildSpec