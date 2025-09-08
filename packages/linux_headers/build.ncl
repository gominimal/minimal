let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "linux_headers",
  inputs = [
    { package = "linux_headers" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
  },
} | BuildSpec
