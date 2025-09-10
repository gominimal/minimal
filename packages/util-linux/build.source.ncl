let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "util-linux",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/util-linux-2.41.1.tar.xz",
            sha256 = "be9ad9a276f4305ab7dd2f5225c8be1ff54352f565ff4dede9628c1aaa7dec57"
        } | Source,
        base,
        toolchain,
    ],
    cmd = "./build.source.sh",
    outputs = {
        bin = { glob = "usr/bin/*" } | OutputLib,
        sbin = { glob = "usr/sbin/*" } | OutputLib,
        lib = { glob = "usr/lib/*" } | OutputLib,
        include = { glob = "usr/include/*" } | OutputLib,
        man = { glob = "usr/share/man/**/*" } | OutputLib,
        doc = { glob = "usr/share/doc/**/*" } | OutputLib,
        share = { glob = "usr/share/bash-completion/**/*" } | OutputLib,
    },
} | BuildSpec