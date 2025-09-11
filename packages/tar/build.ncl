let { BuildSpec, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "tar",
  inputs = [
    { package = "tar" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    tar = { glob = "usr/bin/tar" } | OutputLib,
  },
} | BuildSpec
