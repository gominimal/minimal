let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "lz4",
    inputs = [
        {file = "build.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/lz4-1.10.0.tar.gz",
            sha256 = "537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b"
        } | Source,
        bash,
        coreutils,
        diffutils,
        grep,
        gzip,
        make,
        sed,
        tar,
        toolchain,
    ],
    cmd = "./build.sh",
    outputs = {
        lz4_bin = { glob = "usr/bin/lz4" } | OutputLib,
        lz4c_bin = { glob = "usr/bin/lz4c" } | OutputLib,
        lz4cat_bin = { glob = "usr/bin/lz4cat" } | OutputLib,
        unlz4_bin = { glob = "usr/bin/unlz4" } | OutputLib,
        liblz4 = { glob = "usr/lib/liblz4.so*" } | OutputLib,
        headers = { glob = "usr/include/*.h" } | OutputLib,
    },
} | BuildSpec
