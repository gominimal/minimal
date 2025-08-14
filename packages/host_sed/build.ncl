let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "host_sed",
    inputs = [
        {path = "/usr/bin/sed"} | HostPath,
        {path = "/bin/sh"} | HostPath,
        {path = "/usr/bin/mkdir"} | HostPath,
        {path = "/usr/bin/cp"} | HostPath,
        {path = "/usr/bin/echo"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        sed = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec