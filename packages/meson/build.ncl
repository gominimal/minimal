let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let python = import "../python/build.ncl" in
let setuptools = import "../setuptools/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "meson",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/meson-1.9.0.tar.gz",
      sha256 = "cd27277649b5ed50d19875031de516e270b22e890d9db65ed9af57d18ebc498d"
    } | Source,
    base,
    setuptools,
    toolchain,
  ],
  runtime_deps = [python],
  cmd = "./build.sh",
  outputs = {
    meson = { glob = "usr/bin/meson" } | OutputLib,
    site_packages = { glob = "usr/lib/python3.13/site-packages/**/*" } | OutputLib,
  },
} | BuildSpec
