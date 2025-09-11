let { BuildSpec, HostPath, OutputBin, Local, Prebuilt, .. } = import "minimal.ncl" in
let libacl = import "../acl/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let xz = import "../xz/build.ncl" in
{
  name = "tar",
  inputs = [
    { package = "tar" } | Prebuilt,
  ],
  runtime_deps = [
    libacl,
    gzip,
    xz,
  ],
  cmd = "",
  outputs = {
    tar = { path = "usr/bin/tar" } | OutputBin,
  },
} | BuildSpec
