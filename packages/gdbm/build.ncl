let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "gdbm",
  inputs = [
    { package = "gdbm" } | Prebuilt,
  ],
  runtime_deps = [],
  cmd = "",
  outputs = {},
} | BuildSpec