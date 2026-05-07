let { BuildSpec, .. } = import "minimal.ncl" in
{
  name = "stack-build-pkg",
  build_deps = [],
  runtime_deps = [],
  outputs = {},
} | BuildSpec
