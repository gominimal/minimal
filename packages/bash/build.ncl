let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
let glibc = import "../glibc/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let readline = import "../readline/build.ncl" in
{
    name = "bash",
    inputs = [
        {package = "bash"} | Prebuilt,
    ],
    runtime_deps = [
        glibc,
        ncurses,
        readline,
    ],
    cmd = "",
    outputs = {},
} | BuildSpec
