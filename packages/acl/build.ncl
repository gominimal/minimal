let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
let attr = import "../attr/build.ncl" in
{
  name = "acl",
  inputs = [
    { package = "acl" } | Prebuilt,
  ],
  runtime_deps = [
    attr,
  ],
  cmd = "",
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },
} | BuildSpec
