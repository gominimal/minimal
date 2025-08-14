let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "host_patch",
    inputs = [
        {path = "/usr/bin/patch"} | HostPath,
        {path = "/bin/sh"} | HostPath,
        {path = "/usr/bin/mkdir"} | HostPath,
        {path = "/usr/bin/cp"} | HostPath,
        {path = "/usr/bin/echo"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        patch = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
