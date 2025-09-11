let { BuildSpec, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
{
  name = "glibc",
  inputs = [
    { package = "glibc" } | Prebuilt,
  ],
  cmd = "",
  outputs = {
    etc = { glob = "etc/**/*" } | OutputLib,
    lib64 = { glob = "lib64/**/*" } | OutputLib,
    sbin = { glob = "sbin/**/*" } | OutputLib,
    usr = { glob = "usr/**/*" } | OutputLib,
    var = { glob = "var/**/*" } | OutputLib,
  },
} | BuildSpec
