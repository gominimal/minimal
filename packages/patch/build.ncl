let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let attr = import "../attr/build.ncl" in
let base = import "../base/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "patch",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/patch-2.8.tar.xz",
      sha256 = "f87cee69eec2b4fcbf60a396b030ad6aa3415f192aa5f7ee84cad5e11f7f5ae3"
    } | Source,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [
    attr,
  ],

  cmd = "./build.sh",
  outputs = {
    patch = { glob = "usr/bin/patch" } | OutputLib,
    man = { glob = "usr/share/man/man1/patch.1" } | OutputLib,
  },
} | BuildSpec
