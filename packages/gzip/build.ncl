let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
{
    name = "gzip",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "gzip-1.14.tar.xz"} | Local,
        busybox_static,
        make,
    ],
    cmd = "./build.sh",
    outputs = {
        binaries = { glob = "bin/*" } | OutputLib,
        info = { glob = "share/info/*.info" } | OutputLib,
        man = { glob = "share/man/man1/*.1" } | OutputLib,
    },
} | BuildSpec