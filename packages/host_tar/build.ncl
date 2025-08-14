let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "host_tar",
    inputs = [
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/bin/sh"} | HostPath,
        {path = "/usr/bin/mkdir"} | HostPath,
        {path = "/usr/bin/cp"} | HostPath,
        {path = "/usr/bin/echo"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        tar = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec