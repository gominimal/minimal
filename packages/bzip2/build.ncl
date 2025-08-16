let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let host_make = import "../host_make/build.ncl" in
{
    name = "bzip2",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "bzip2-1.0.8-install_docs-1.patch"} | Local,
        {file = "bzip2-1.0.8.tar.gz"} | Local,
        busybox_static,
        host_make,
    ],
    cmd = "./build.sh",
    outputs = {
        bzip2_bin = { glob = "bin/bzip2" } | OutputLib,
        bzcat = { glob = "bin/bzcat" } | OutputLib,
        bunzip2 = { glob = "bin/bunzip2" } | OutputLib,
        bzip2recover = { glob = "bin/bzip2recover" } | OutputLib,
        bzdiff = { glob = "bin/bzdiff" } | OutputLib,
        bzgrep = { glob = "bin/bzgrep" } | OutputLib,
        bzmore = { glob = "bin/bzmore" } | OutputLib,
        bzless = { glob = "bin/bzless" } | OutputLib,
        libbz2 = { glob = "lib/libbz2.so*" } | OutputLib,
        headers = { glob = "include/*.h" } | OutputLib,
    },
} | BuildSpec
