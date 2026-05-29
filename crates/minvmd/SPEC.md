# minvmd + pkgs-sourced VM image — landed shape

Scope: how `minvmd` and the VM image fit together once both land in `minimal`,
with the image produced by the package registry rather than a fetched URL.

## Components

| Piece | Where | Role |
|---|---|---|
| `minvmd` | `crates/minvmd` (macOS) | Host broker: `up`/`down`/`status`/`debug-shell`. Drives `krunkit`, bridges host UDS ↔ guest vsock. |
| `alpine-virtio-linux` | pkgs package | Builds `vm-image.raw` (EFI GPT: ESP + ext4 root) + `manifest.json` from `virtio-linux` (kernel) + Alpine rootfs. |
| `minimald` | `crates/minimald` (Linux, in-VM) | Session orchestrator; terminates the `minimald-v1-*` SSH RPC. |

## Image provisioning (the change vs today)

- The image is a **`minimal` package output**, not a `MINVMD_IMAGE_URL` download. `minvmd` and `minimal` ship in the same repo, so `minvmd` resolves the `alpine-virtio-linux` package through the package manager.
- `minvmd up` ensures the `alpine-virtio-linux` output is materialized (built or pulled from the binary cache), then stages into `~/.minimal/vm/`:
  - `rootfs.raw` ← the package's `vm-image.raw` (read-only boot disk)
  - `state.qcow2` ← created locally (writable overlay)
  - `efivars.fd` ← created on first boot
- The package `manifest.json` carries the kernel/rootfs/image sha256s; `minvmd` verifies against it. A `MINVMD_IMAGE_*` env override stays for dev/CI.
- This retires minvmd's current "single fetched artifact + env digest" contract (R2.x).

## Boot + lifecycle (validated against krunkit 1.2.1)

`minvmd` spawns `krunkit` with:

```
--cpus N --memory N
--bootloader efi,variable-store=<vm>/efivars.fd,create
--device virtio-blk,path=<vm>/rootfs.raw,format=raw
--device virtio-blk,path=<vm>/state.qcow2,format=qcow2
--device virtio-vsock,port=1024,socketURL=<vm>/control.sock,connect
--device virtio-vsock,port=1025,socketURL=<vm>/root-debug.sock,connect
--device virtio-serial,logFilePath=<vm>/serial.log
--restful-uri unix://<vm>/krunkit.sock
```

- Boot path: OVMF → `vmlinuz-efi` on the ESP → ext4 root (`/dev/vda2`) → init. The kernel cmdline is supplied by `virtio-linux` (baked `CONFIG_CMDLINE_FORCE`) — **open decision**, see below.
- `status` ← REST `GET /vm/state` (`VirtualMachineStateRunning|Stopped`); `down` ← REST `{"state":"Stop"}` then SIGTERM reap.
- vsock is `connect` (host→guest): `minimald` / the debug shell *listen* inside the guest; `minvmd` dials in. The broker byte-pumps opaquely on port 1024; `minimald` parses the RPC.

## Integration with existing crates

- Paths use `sessions::paths::HostAbsPath` at the `minvmd` boundary; the guest is the `Daemon` realm (future `Translator` seam).
- Errors via a local `UserFacing` (no repo-wide equivalent exists yet).
- macOS-only crate; non-macOS builds a no-op shim so the workspace builds on Linux.

## Deferred / open

- **Kernel cmdline delivery**: bake into `virtio-linux` (validated, recommended) vs a bootloader/UKI package. Blocks a bootable image.
- **Production `KrunkitRunner`** + CLI wiring: `up`/`down`/`status` are stubbed; no real krunkit subprocess is launched yet.
- **Rootfs dedupe**: `alpine-virtio-linux` re-assembles the Alpine rootfs because build_deps merge into one root and musl collides with the glibc image tools. Cleaner once `alpine-minirootfs` emits a namespaced `rootfs.tar`.
- **Real init**: `minimald` replaces the boot-verification `stub-init` as guest pid-1.
