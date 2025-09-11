let { BuildSpec, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "mpc",
  inputs = [
    { package = "mpc" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    usr_include = { glob = "usr/include/*.h" } | OutputLib,
    lib = { glob = "usr/lib/libmpc*.so*" } | OutputLib,
    lib_la = { glob = "usr/lib/*.la" } | OutputLib,
    info = { glob = "usr/share/info/*" } | OutputLib,
  },
} | BuildSpec
