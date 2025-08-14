let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "man-pages",
    inputs = [
        {path = "/usr"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        man_pages = { glob = "share/man/**/*" } | OutputLib,
    },
} | BuildSpec
