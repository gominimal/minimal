let { BuildSpec, .. } = import "minimal.ncl" in
{
  name = "harness-build-pkg",
  inputs = [],
  runtime_deps = [],
  outputs = {},
} | BuildSpec
