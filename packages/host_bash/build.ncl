let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in{
    name = "host_bash",
    inputs = [
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/mkdir"} | HostPath,
        {path = "/usr/bin/cp"} | HostPath,
        {path = "/usr/bin/ln"} | HostPath,
        {path = "/usr/bin/echo"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        bash = { glob = "bin/*" } | OutputLib,
    },
} | BuildSpec
