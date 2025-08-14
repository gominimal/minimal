let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
{
    name = "zstd",
    inputs = [
        host_bash,
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
