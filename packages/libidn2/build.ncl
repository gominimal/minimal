let {BuildSpec, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let libunistring = import "../libunistring/build.ncl" in
{
    name = "libidn2",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/libidn2-2.3.8.tar.gz",
            sha256 = "f557911bf6171621e1f72ff35f5b1825bb35b52ed45325dcdee931e5d3c0787a"
        } | Source,
        base,
        toolchain,
        libunistring,
    ],
    cmd = "./build.sh",
    outputs = {
        bin = { glob = "usr/bin/idn2" } | OutputLib,
        lib = { glob = "usr/lib/libidn2*" } | OutputLib,
        include = { glob = "usr/include/*" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/libidn2.pc" } | OutputLib,
        man = { glob = "usr/share/man/man*/*" } | OutputLib,
    },
} | BuildSpec
