let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "file",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/make"} | HostPath,
    ],
    cmd = "build.sh",
    outputs = {
        file_bin = { glob = "bin/file" } | OutputLib,
        libmagic = { glob = "lib/libmagic.so*" } | OutputLib,
        headers = { glob = "include/magic.h" } | OutputLib,
        magic_data = { glob = "share/misc/magic*" } | OutputLib,
    },
} | BuildSpec