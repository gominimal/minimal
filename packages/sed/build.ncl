let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
let acl = import "../acl/build.ncl" in
let attr = import "../attr/build.ncl" in # TODO
{
  name = "sed",
  inputs = [
    { package = "sed" } | Prebuilt,
  ],
  runtime_deps = [
    acl,
    attr,
  ],
  cmd = "",
  outputs = {
    sed_bin = { glob = "usr/bin/sed" } | OutputLib,
  },
} | BuildSpec
