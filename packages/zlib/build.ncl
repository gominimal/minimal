let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "zlib",
    inputs = [
        {path = "/usr"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        libz = { glob = "lib/libz.so*" } | OutputLib,
        libz_static = { glob = "lib/libz.a" } | OutputLib,
        headers = { glob = "include/*.h" } | OutputLib,
        pkgconfig = { glob = "lib/pkgconfig/zlib.pc" } | OutputLib,
    },
} | BuildSpec
