let {BuildSpec, Local, ..} = import "minimal.ncl" in
{
    name = "single buildspec",
    inputs = [
        {file = "local_input.txt"} | Local,
    ],
    cmd = "",
} | BuildSpec