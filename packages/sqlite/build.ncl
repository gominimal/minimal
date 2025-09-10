let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "sqlite",
  inputs = [
    { package = "sqlite" } | Prebuilt,
  ],
  runtime_deps = [],
  cmd = "",
  outputs = {},
} | BuildSpec