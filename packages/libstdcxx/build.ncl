let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "libstdcxx",
  inputs = [
    { package = "libstdcxx" } | Prebuilt,
  ],
  runtime_deps = [],
  cmd = "",
  outputs = {},
} | BuildSpec
