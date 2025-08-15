let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in{
    name = "host_bash",
    inputs = [
        {file = "build.sh"} | Local,
        # {path = "/usr/lib/x86_64-linux-gnu"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/mkdir"} | HostPath,
        {path = "/usr/bin/cp"} | HostPath,
        {path = "/usr/bin/ln"} | HostPath,
        {path = "/usr/bin/echo"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        bash = { glob = "bin/*" } | OutputLib,
        # libtinfo_hack1 = { glob = "lib/x86_64-linux-gnu/libtinfo.so.6" } | OutputLib,
        # libtinfo_hack2 = { glob = "lib/x86_64-linux-gnu/libtinfo.so.6.4" } | OutputLib,
    },
} | BuildSpec
