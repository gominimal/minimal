let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "zstd",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/make"} | HostPath,
    ],
    cmd = "build.sh",
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