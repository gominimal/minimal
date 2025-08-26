let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
{
    name = "gmp",
    inputs = [
        {package = "gmp"} | Prebuilt,
    ],
    cmd = "",
    outputs = {
        include = { glob = "usr/include/*.h" } | OutputLib,
        lib = { glob = "usr/lib/libgmp*.so*" } | OutputLib,
        lib_la = { glob = "usr/lib/*.la" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
        info = { glob = "usr/share/info/*" } | OutputLib,
    },
} | BuildSpec
