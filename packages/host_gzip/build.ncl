let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "host_gzip",
    inputs = [
        {path = "/usr/bin/gzip"} | HostPath,
        {path = "/bin/sh"} | HostPath,
        {path = "/usr/bin/mkdir"} | HostPath,
        {path = "/usr/bin/cp"} | HostPath,
        {path = "/usr/bin/echo"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        gzip = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec