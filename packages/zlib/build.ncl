let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make_static = import "../make_static/build.ncl" in
{
    name = "zlib",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "zlib-1.3.1.tar.gz"} | Local,
        busybox_static,
        make_static,
    ],
    cmd = "./build.sh",
    outputs = {
        libz = { glob = "lib/libz.so*" } | OutputLib,
        libz_static = { glob = "lib/libz.a" } | OutputLib,
        headers = { glob = "include/*.h" } | OutputLib,
        pkgconfig = { glob = "lib/pkgconfig/zlib.pc" } | OutputLib,
    },
} | BuildSpec
