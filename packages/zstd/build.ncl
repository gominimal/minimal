let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make_static = import "../make_static/build.ncl" in
{
    name = "zstd",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "zstd-1.5.6.tar.gz"} | Local,
        busybox_static,
        make_static,
    ],
    cmd = "./build.sh",
    outputs = {
        zstd_bin = { glob = "bin/zstd" } | OutputLib,
        zstdcat = { glob = "bin/zstdcat" } | OutputLib,
        zstdgrep = { glob = "bin/zstdgrep" } | OutputLib,
        zstdless = { glob = "bin/zstdless" } | OutputLib,
        zstdmt = { glob = "bin/zstdmt" } | OutputLib,
        unzstd = { glob = "bin/unzstd" } | OutputLib,
        libzstd = { glob = "lib/libzstd.so*" } | OutputLib,
        headers = { glob = "include/*.h" } | OutputLib,
    },
} | BuildSpec
