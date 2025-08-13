let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "m4",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/make"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/xz"} | HostPath,
    ],
    cmd = "build.sh",
    outputs = {
        m4_bin = { glob = "bin/m4" } | OutputLib,
        m4_man = { glob = "share/man/man1/m4.1" } | OutputLib,
        m4_info = { glob = "share/info/m4.info*" } | OutputLib,
    },
} | BuildSpec
