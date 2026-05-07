let { BuildSpec, .. } = import "minimal.ncl" in
{
  name = "extra-runtime-pkg",
  build_deps = [],
  runtime_deps = [],
  outputs = {},
} | BuildSpec
