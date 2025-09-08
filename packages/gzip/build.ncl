let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "gzip",
  inputs = [
    { package = "gzip" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    binaries = { glob = "usr/bin/*" } | OutputLib,
  },
} | BuildSpec
