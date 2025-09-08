let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "xz",
  inputs = [
    { package = "xz" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
  },
} | BuildSpec
