#!/bin/bash
# Assemble the minvmd guest rootfs as an ext4 image.
#
# The minimal build sandbox hardlinks this package's build_deps and their
# runtime closure (socat, bash, coreutils, e2fsprogs + glibc/readline/ncurses/
# openssl) into the sandbox root at standard paths. We snapshot that userland
# into a staging tree, drop in the bring-up init + contract manifest, and pack
# it with mke2fs. minvmd loads the result via krun_add_disk2 with a
# `root=/dev/vda rootfstype=ext4` cmdline (block root has no /init.krun, so the
# kernel runs init=/sbin/microvm-init directly; devtmpfs auto-mounts /dev,
# giving the stub /dev/vsock).
set -euo pipefail

STAGE="$(pwd)/stage"
rm -rf "$STAGE"
mkdir -p "$STAGE"

# Snapshot the runtime userland composed into this build sandbox.
for d in usr bin sbin lib lib64 etc; do
  if [ -e "/$d" ]; then
    cp -a "/$d" "$STAGE/"
  fi
done

mkdir -p "$STAGE/bin" "$STAGE/sbin" "$STAGE/etc/microvm"

# Kernel mountpoints. devtmpfs auto-mounts on /dev at boot (CONFIG_DEVTMPFS_MOUNT)
# — without the directory it fails with "devtmpfs: error mounting -2" and the
# guest has no /dev/vsock node. /proc and /sys are needed by minimald (Stage 2).
mkdir -p "$STAGE/dev" "$STAGE/proc" "$STAGE/sys" "$STAGE/run" "$STAGE/tmp"
chmod 1777 "$STAGE/tmp"

# Mountpoint for the writable state disk (/dev/vdb). It must exist in the
# read-only root image — the guest cannot mkdir it at boot (EROFS).
mkdir -p "$STAGE/var/lib/minimal"

# Guarantee /bin/sh for the init script's shebang.
if [ ! -e "$STAGE/bin/sh" ]; then
  if [ -e "$STAGE/bin/bash" ]; then
    ln -sf bash "$STAGE/bin/sh"
  elif [ -e "$STAGE/usr/bin/bash" ]; then
    ln -sf ../usr/bin/bash "$STAGE/bin/sh"
  fi
fi

# Bring-up workload: write the READY marker on vsock 7350 (guest connects out to
# host CID 2; R2.4), then serve the echo bridge on vsock 2222 (R3). Retry the
# marker briefly in case the vsock device is not live the instant init starts.
cat > "$STAGE/sbin/microvm-init" <<'STUB'
#!/bin/sh
i=0
while [ "$i" -lt 50 ]; do
    printf 'READY\n' | socat -t2 - VSOCK-CONNECT:2:7350 && break
    i=$((i + 1))
    sleep 0.1
done
exec socat VSOCK-LISTEN:2222,fork EXEC:cat
STUB
chmod +x "$STAGE/sbin/microvm-init"

# Guest rootfs contract (machine-readable record of the boot contract).
cat > "$STAGE/etc/microvm/manifest" <<'MANIFEST'
# minvmd guest rootfs contract
# format=krun_add_disk2-ext4
# exec_target_production=/sbin/minimald   (Stage 2; absent here)
# exec_target_bringup=/sbin/microvm-init
# vsock_port_ready=7350    guest CONNECTs out (host listen=false); writes "READY\n" once
# vsock_port_bridge=2222   guest LISTENs (host listen=true); echoes per connection
# net=none   init=kernel-cmdline (no /init.krun on a block-device root)
MANIFEST

# Prune build-time-only bulk the guest never needs: headers, static libs,
# docs/man, and especially glibc's locale archive (the bulk of the closure).
# The bring-up workload is sh + socat; the C locale fallback is sufficient.
( cd "$STAGE" && \
  rm -rf usr/include usr/share/man usr/share/doc usr/share/info \
         usr/share/locale usr/share/i18n usr/lib/locale usr/lib/pkgconfig \
         usr/share/aclocal usr/share/gtk-doc usr/share/bash-completion \
         usr/share/gdb && \
  find . \( -name '*.a' -o -name '*.la' -o -name '*.o' \) -delete 2>/dev/null || true )

# Fail loudly (not silently with an empty output) if the image tool is absent.
command -v mke2fs >/dev/null || {
  echo "ERROR: mke2fs not found on PATH ($PATH) — is e2fsprogs in build_deps?" >&2
  exit 1
}

# Pack the staging tree into a raw ext4 image (mke2fs -d copies the tree).
# Size = tree + 10% + 8 MiB headroom, in 1 KiB blocks. The headroom must cover
# ext4 metadata (inode tables) that `du` does not account for, or `mke2fs -d`
# can fail to fit the tree.
OUT="$OUTPUT_DIR/usr/share/minvmd-rootfs"
mkdir -p "$OUT"
KB="$(du -sk "$STAGE" | cut -f1)"
BLOCKS=$(( KB + KB / 10 + 8192 ))
# No journal (`-O ^has_journal`): the root mounts read-only, so the journal is
# pure overhead and its ~4 MiB+ reservation can overflow a tight image.
mke2fs -q -t ext4 -O ^has_journal -d "$STAGE" -b 1024 -F "$OUT/rootfs.img" "$BLOCKS"

# Assert the output exists so a silent mke2fs failure surfaces here rather than
# downstream as a missing materialize output.
[ -s "$OUT/rootfs.img" ] || {
  echo "ERROR: mke2fs did not produce $OUT/rootfs.img" >&2
  ls -la "$OUT" >&2 || true
  exit 1
}
echo "built rootfs.img: $(wc -c < "$OUT/rootfs.img") bytes"
