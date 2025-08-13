let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "iana-etc",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/mkdir"} | HostPath,
        {path = "/usr/bin/cp"} | HostPath,
    ],
    cmd = "build.sh",
    outputs = {
        protocols = { glob = "etc/protocols" } | OutputLib,
        services = { glob = "etc/services" } | OutputLib,
    },
} | BuildSpec