let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
{
    name = "sed",
    inputs = [
        {package = "sed"} | Prebuilt,
    ],
    cmd = "",
    outputs = {
        sed_bin = { glob = "usr/bin/sed" } | OutputLib,
    },
} | BuildSpec
