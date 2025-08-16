let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make_static = import "../make_static/build.ncl" in
{
    name = "file",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "file-5.46.tar.gz"} | Local,
        busybox_static,
        make_static
    ],
    cmd = "./build.sh",
    outputs = {
        file_bin = { glob = "usr/bin/file" } | OutputLib,
        libmagic = { glob = "usr/lib/libmagic.so*" } | OutputLib,
        headers = { glob = "usr/include/magic.h" } | OutputLib,
        magic_data = { glob = "usr/share/misc/magic*" } | OutputLib,
    },
} | BuildSpec
