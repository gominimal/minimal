let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "bzip2",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/patch"} | HostPath,
        {path = "/usr/bin/sed"} | HostPath,
        {path = "/usr/bin/make"} | HostPath,
        {path = "/usr/bin/cp"} | HostPath,
        {path = "/usr/bin/ln"} | HostPath,
        {path = "/usr/bin/rm"} | HostPath,
    ],
    cmd = "build.sh",
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
