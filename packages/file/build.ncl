let { BuildSpec, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "file",
  inputs = [
    { package = "file" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
  }
} | BuildSpec
