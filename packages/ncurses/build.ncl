let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
let attr = import "../attr/build.ncl" in
{
    name = "ncurses",
    inputs = [
        {package = "ncurses"} | Prebuilt,
    ],
    runtime_deps = [
        attr,
    ],
    cmd = "",
    outputs = {},
} | BuildSpec
