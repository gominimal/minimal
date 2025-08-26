let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
{
    name = "m4",
    inputs = [
        {package = "m4"} | Prebuilt,
    ],
    cmd = "",
    outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
    },
} | BuildSpec
