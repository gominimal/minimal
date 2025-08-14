let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "bzip2",
    inputs = [
        {path = "/usr"} | HostPath,
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
