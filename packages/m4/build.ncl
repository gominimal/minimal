let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
{
    name = "m4",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "m4-1.4.19.tar.xz"} | Local,
        busybox_static,
        make,
    ],
    cmd = "./build.sh",
    outputs = {
        m4_bin = { glob = "bin/m4" } | OutputLib,
        m4_man = { glob = "share/man/man1/m4.1" } | OutputLib,
        m4_info = { glob = "share/info/m4.info*" } | OutputLib,
    },
} | BuildSpec
