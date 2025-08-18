let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
{
    name = "sed",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "sed-4.9.tar.xz"} | Local,
        busybox_static,
        make,
    ],
    cmd = "./build.sh",
    outputs = {
        sed_bin = { glob = "bin/sed" } | OutputLib,
        man_pages = { glob = "share/man/man1/*.1" } | OutputLib,
        info_pages = { glob = "share/info/*.info*" } | OutputLib,
    },
} | BuildSpec