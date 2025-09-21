let { BuildSpec, .. } = import "minimal.ncl" in
let binutils = import "../binutils/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
{
  name = "toolchain",
  inputs = [],
  runtime_deps = [
    binutils,
    gcc,
    glibc,
    linux_headers,
  ],
  cmd = "",
  outputs = {},
} | BuildSpec
