let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "host_make",
    inputs = [
        {path = "/usr/bin/make"} | HostPath,
        {path = "/bin/sh"} | HostPath,
        {path = "/usr/bin/mkdir"} | HostPath,
        {path = "/usr/bin/cp"} | HostPath,
        {path = "/usr/bin/echo"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        make = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
