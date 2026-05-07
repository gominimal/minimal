let { BuildSpec, .. } = import "minimal.ncl" in
{
  name = "stack-runtime-pkg",
  build_deps = [],
  runtime_deps = [],
  outputs = {},
} | BuildSpec
