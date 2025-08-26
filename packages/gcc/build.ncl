let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
{
    name = "gcc",
    inputs = [
        {package = "gcc"} | Prebuilt,
    ],
    cmd = "",
    outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
    },
} | BuildSpec
