let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
{
    name = "diffutils",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "diffutils-3.12.tar.xz"} | Local,
        busybox_static,
        make,
    ],
    cmd = "./build.sh",
    outputs = {
        cmp = { glob = "bin/cmp" } | OutputLib,
        diff = { glob = "bin/diff" } | OutputLib,
        diff3 = { glob = "bin/diff3" } | OutputLib,
        sdiff = { glob = "bin/sdiff" } | OutputLib,
        info = { glob = "share/info/*.info*" } | OutputLib,
        man = { glob = "share/man/man1/*.1" } | OutputLib,
    },
} | BuildSpec