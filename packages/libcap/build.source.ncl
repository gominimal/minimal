let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let grep = import "../grep/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let xz = import "../xz/build.ncl" in
{
    name = "libcap",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/libcap-2.76.tar.xz",
            sha256 = "629da4ab29900d0f7fcc36227073743119925fd711c99a1689bbf5c9b40c8e6f"
        } | Source,
        bash,
        coreutils,
        diffutils,
        grep,
        make,
        sed,
        tar,
        toolchain,
        xz,
    ],
    cmd = "./build.source.sh",
    outputs = {
        sbin = { glob = "usr/sbin/*" } | OutputLib,
        lib = { glob = "usr/lib/*" } | OutputLib,
        include = { glob = "usr/include/**/*" } | OutputLib,
        man = { glob = "usr/share/man/**/*" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*" } | OutputLib,
    },
} | BuildSpec
