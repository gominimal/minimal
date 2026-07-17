---
layout: home

hero:
  name: Minimal
  text: Hermetic environments for devs and agents
  tagline: Declarative builds, sandboxed sessions, and task running — reproducible by default.
  actions:
    - theme: brand
      text: CLI reference
      link: /reference/cli
    - theme: alt
      text: Architecture
      link: /architecture

features:
  - title: Declarative builds
    details: Packages are declared in Nickel, hashed like derivations, and cached content-addressed by Blake3.
  - title: Sandboxed sessions
    details: Dev and agent sessions run in Linux namespaces with a composed, read-only rootfs.
  - title: Task running
    details: Tasks from minimal.toml execute in clean-room sandboxes with only their declared dependencies.
---

<!-- TODO(launch): the hero text and tagline above are placeholders; final
     wording is a launch decision. -->

## Looking for user guides?

This site is the engineering documentation for the
[gominimal/minimal](https://github.com/gominimal/minimal) repository:
CLI and file-format reference, architecture notes, and contributor
conventions. Tutorials, install guides, and concept articles live at
[docs.minimal.dev](https://docs.minimal.dev).
