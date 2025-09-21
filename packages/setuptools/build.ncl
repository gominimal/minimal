let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let python = import "../python/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "setuptools",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/setuptools-80.9.0.tar.gz",
      sha256 = "f36b47402ecde768dbfafc46e8e4207b4360c654f1f3bb84475f0a28628fb19c"
    } | Source,
    base,
    python,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    site_packages = { glob = "usr/lib/python3.13/site-packages/**/*" } | OutputLib,
  },
} | BuildSpec
