let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "file",
    inputs = [
        {path = "/usr"} | HostPath,
    ],
    cmd = "./build.sh",
    outputs = {
        file_bin = { glob = "bin/file" } | OutputLib,
        libmagic = { glob = "lib/libmagic.so*" } | OutputLib,
        headers = { glob = "include/magic.h" } | OutputLib,
        magic_data = { glob = "share/misc/magic*" } | OutputLib,
    },
} | BuildSpec
