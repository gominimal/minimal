let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
{
    name = "mpfr",
    inputs = [
        {package = "mpfr"} | Prebuilt,
    ],
    cmd = "",
    outputs = {
        include = { glob = "usr/include/*.h" } | OutputLib,
        lib = { glob = "usr/lib/libmpfr*.so*" } | OutputLib,
        lib_la = { glob = "usr/lib/*.la" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
        doc = { glob = "usr/share/doc/mpfr-4.2.2/**/*" } | OutputLib,
        info = { glob = "usr/share/info/*" } | OutputLib,
    },
} | BuildSpec
