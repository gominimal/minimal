let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
{
    name = "man-pages",
    inputs = [
        host_bash,
    ],
    cmd = "./build.sh",
    outputs = {
        man_pages = { glob = "share/man/**/*" } | OutputLib,
    },
} | BuildSpec
