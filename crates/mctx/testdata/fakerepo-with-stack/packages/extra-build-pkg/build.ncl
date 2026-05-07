let { BuildSpec, .. } = import "minimal.ncl" in
{
  name = "extra-build-pkg",
  build_deps = [],
  runtime_deps = [],
  outputs = {},
} | BuildSpec
