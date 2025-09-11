let {BuildSpec, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "gdbm",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/gdbm-1.26.tar.gz",
            sha256 = "6a24504a14de4a744103dcb936be976df6fbe88ccff26065e54c1c47946f4a5e"
        } | Source,
        base,
        toolchain,
    ],
    cmd = "./build.source.sh",
    outputs = {
        bin = { glob = "usr/bin/*" } | OutputLib,
        lib = { glob = "usr/lib/*" } | OutputLib,
        include = { glob = "usr/include/**/*" } | OutputLib,
        man = { glob = "usr/share/man/**/*" } | OutputLib,
        info = { glob = "usr/share/info/*" } | OutputLib,
    },
} | BuildSpec
