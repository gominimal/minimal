let { BuildSpec, .. } = import "minimal.ncl" in
{
  name = "extra-build-pkg",
  inputs = [],
  runtime_deps = [],
  outputs = {},
} | BuildSpec
