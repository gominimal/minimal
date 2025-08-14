let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
let host_bash = import "../host_bash/build.ncl" in
{
    name = "file",
    inputs = [
        host_bash,
    ],
    cmd = "./build.sh",
    outputs = {
        file_bin = { glob = "bin/file" } | OutputLib,
        libmagic = { glob = "lib/libmagic.so*" } | OutputLib,
        headers = { glob = "include/magic.h" } | OutputLib,
        magic_data = { glob = "share/misc/magic*" } | OutputLib,
    },
} | BuildSpec
