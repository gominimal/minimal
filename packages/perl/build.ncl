let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
{
    name = "perl",
    inputs = [
        {package = "perl"} | Prebuilt,
    ],
    cmd = "",
    outputs = {
        usr = { glob = "usr/**/*" } | OutputLib,
    },
} | BuildSpec
