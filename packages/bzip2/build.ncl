let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "bzip2",
  inputs = [
    { package = "bzip2" } | Prebuilt,
  ],
  cmd = "",
  outputs = {},
} | BuildSpec
