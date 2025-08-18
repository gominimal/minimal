let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make_static = import "../make_static/build.ncl" in
{
    name = "lz4",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "lz4-1.10.0.tar.gz"} | Local,
        busybox_static,
        make_static,
    ],
    cmd = "./build.sh",
    outputs = {
        lz4_bin = { glob = "bin/lz4" } | OutputLib,
        lz4c_bin = { glob = "bin/lz4c" } | OutputLib,
        lz4cat_bin = { glob = "bin/lz4cat" } | OutputLib,
        unlz4_bin = { glob = "bin/unlz4" } | OutputLib,
        liblz4 = { glob = "lib/liblz4.so*" } | OutputLib,
        headers = { glob = "include/*.h" } | OutputLib,
    },
} | BuildSpec