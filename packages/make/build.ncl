let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "make",
  inputs = [
    { package = "make" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    make = { glob = "usr/bin/make" } | OutputLib,
  },
} | BuildSpec
