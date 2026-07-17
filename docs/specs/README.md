# Specs

Design specifications for larger units of work. Each spec lives in a numbered
directory, `NN-spec-<kebab-title>/`, containing the spec itself and, where one
was written, an `architecture.md` companion describing the chosen approach.
Companion files carry the same status as their spec.

These documents are working design artifacts, not user documentation: they are
excluded from the docs site but remain publicly visible in the repository.

## Status vocabulary

- **planned** — accepted design; implementation has not landed.
- **shipped** — the described feature is implemented in-tree. The spec is a
  historical design record; the code is the source of truth where they drift.
- **superseded** — replaced by a later spec (named in the `supersedes` chain).

## Index

| # | Title | Status | Summary |
|---|---|---|---|
| [01](01-spec-minvmd-host-daemon/01-spec-minvmd-host-daemon.md) | minvmd macOS VM provider host daemon | shipped | Host daemon that boots a Linux microVM via libkrun, supervises its lifecycle, and bridges a host UDS to the in-VM `minimald` over vsock. |
| [02](02-spec-minvmd-linux-kvm/02-spec-minvmd-linux-kvm.md) | minvmd Linux KVM backend | shipped | Extends minvmd beyond macOS/HVF: native Linux boots via libkrun's KVM backend, with a dedicated CI lane. |
| [03](03-spec-networking/03-spec-networking.md) | minimald networking | shipped | Session network modes (no-net, host-net, own-IP), DNS, egress/ingress policy, and the WireGuard mesh across the five deployment models, built on one gvproxy switch per host. |
| [04](04-spec-ot-render-decoupling/04-spec-ot-render-decoupling.md) | ot render decoupling | shipped | Splits `ot` into a render-free state core, a snapshot/version observation layer, and per-context drivers (indicatif shim locally, a scoped per-SSH-channel renderer in the daemon). |
| [05](05-spec-minvmd-gvproxy-pidfd/05-spec-minvmd-gvproxy-pidfd.md) | minvmd gvproxy pidfd signalling | shipped | Signals the gvproxy switch child via pidfd instead of raw PID, closing the recycled-PID window after an independent crash. |
| [06](06-spec-ssh-host-key-in-beacon/06-spec-ssh-host-key-in-beacon.md) | SSH host key in ready beacon | shipped | The guest's boot beacon carries `minimald`'s SSH host public key, so the host learns it without reading guest tmpfs state. |
| [07](07-spec-installer/07-spec-installer.md) | POSIX-sh fallback installer | shipped | A single POSIX-sh `curl \| sh` installer that fetches the release binaries (`min` and friends) for hosts without a package manager. |
| [08](08-spec-vm-ext4-volume/08-spec-vm-ext4-volume.md) | Per-VM writable ext4 volume | shipped | Gives each VM a writable ext4 volume for cache, sandbox staging, and session state, replacing the size-limited per-boot tmpfs. |
| [09](09-spec-minvmd-resource-monitoring/09-spec-minvmd-resource-monitoring.md) | minvmd resource monitoring | shipped | Live VM resource observation, per-VM resource configuration in `minvmd.toml`, and utilisation warnings, replacing static boot-time values. |

Spec 03 additionally carries
[networking-with-diagrams.md](03-spec-networking/networking-with-diagrams.md),
the implementation analysis that selected the networking building blocks (no
frontmatter; part of spec 03's record).
