let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "libgcc",
  inputs = [
    { package = "libgcc" } | Prebuilt,
  ],
  runtime_deps = [],
  cmd = "",
  outputs = {},
} | BuildSpec
