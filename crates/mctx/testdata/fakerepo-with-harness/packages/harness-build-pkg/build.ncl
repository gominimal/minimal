let { BuildSpec, .. } = import "minimal.ncl" in
{
  name = "harness-build-pkg",
  build_deps = [],
  runtime_deps = [],
  outputs = {},
} | BuildSpec
