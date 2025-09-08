let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "binutils",
  inputs = [
    { package = "binutils" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
  },
} | BuildSpec
