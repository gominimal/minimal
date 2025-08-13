let {BuildSpec, HostPath, OutputLib, ..} = import "minimal.ncl" in
{
    name = "expect",
    inputs = [
        {path = "/bin"} | HostPath,
        {path = "/usr/bin/bash"} | HostPath,
        {path = "/usr/bin/make"} | HostPath,
        {path = "/usr/bin/tar"} | HostPath,
        {path = "/usr/bin/gzip"} | HostPath,
        {path = "/usr/bin/ln"} | HostPath,
        {path = "/usr/bin/sed"} | HostPath,
        {path = "/usr/bin/patch"} | HostPath,
    ],
    cmd = "build.sh",
    outputs = {
        expect_bin = { glob = "bin/expect" } | OutputLib,
        expect_lib = { glob = "lib/expect*" } | OutputLib,
        libexpect = { glob = "lib/libexpect*.so*" } | OutputLib,
        expect_man = { glob = "share/man/man1/expect.1" } | OutputLib,
        expect_man3 = { glob = "share/man/man3/libexpect.3" } | OutputLib,
    },
} | BuildSpec
