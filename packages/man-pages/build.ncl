let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "man-pages",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/xz"} | HostPath,
        {path = "/usr/bin/make"} | HostPath,
        {path = "/usr/bin/rm"} | HostPath,
    ],
    cmd = "build.sh",
    outputs = {
        man_pages = { glob = "share/man/**/*" } | OutputLib,
    },
} | BuildSpec