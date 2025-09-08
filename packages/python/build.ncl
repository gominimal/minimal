let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "python",
  inputs = [
    { package = "python" } | Prebuilt,
  ],
  cmd = "",
  outputs = {},
} | BuildSpec
