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
        cmp = { glob = "usr/bin/cmp" } | OutputLib,
        diff = { glob = "usr/bin/diff" } | OutputLib,
        diff3 = { glob = "usr/bin/diff3" } | OutputLib,
        sdiff = { glob = "usr/bin/sdiff" } | OutputLib,

        info = { glob = "usr/share/info/*.info*" } | OutputLib,
        man = { glob = "usr/share/man/man1/*.1" } | OutputLib,
        locales = { glob = "usr/share/locale/**/*" } | OutputLib,
    },
} | BuildSpec
