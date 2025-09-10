let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "util-linux",
  inputs = [
    { package = "util-linux" } | Prebuilt,
  ],
  runtime_deps = [],
  cmd = "",
  outputs = {},
} | BuildSpec