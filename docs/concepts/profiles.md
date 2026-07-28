---
description: Profiles declare reusable customizations (packages, env vars, and filesystem mappings) that can be applied to tasks.
---

# Minimal Profiles

In Minimal, profiles are used to declare customizations such as additional packages, environment variables, or filesystem mappings. These customizations
can then be easily applied to an environment, such as a [task](../reference/tasks.md).

## Defining a profile

Like packages, profiles are defined in a configuration file located at `profiles/<profile name>/profile.ncl`, either in your
codebase or any layer above it in the [software supply chain](./software-supply-chain.md). The `profiles/` directory is
always adjacent to the [`minimal.toml`](../reference/minimal-dot-toml.md) file at the base of the layer, but can be omitted if
the repository does not define any profiles.

Like packages, profiles are defined using [Nickel](https://nickel-lang.org/):

```ncl
let { profile, .. } = import "minimal.ncl" in
profile {
  name = "my-terraform-debug",

  env_vars.TF_LOG = "trace",
  packages = [
    # Make terraform package always present
    "terraform",
  ],
}
```

## Using a profile

### In all tasks

Setting `defaults.profile` within a codebase [`minimal.toml`](../reference/minimal-dot-toml.md) will apply the profile to all tasks which do not have a profile explicitly set.

```toml
[defaults]
profile = "my-profile" # my-profile is set on all tasks
```

### On specific tasks

Profiles can be applied individually on tasks as well:

```toml
[tasks.shell]
profile = "my-profile"
```

Tasks which explicitly set a profile do not inherit any profile defined in `[defaults]`. Thus, a task can be configured to not use the default profile by setting `profile = ""`.
