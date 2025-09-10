let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "openssl",
  inputs = [
    { package = "openssl" } | Prebuilt,
  ],
  cmd = "",
  outputs = {},
} | BuildSpec
