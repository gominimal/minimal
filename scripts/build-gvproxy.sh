#!/usr/bin/env bash
# Build the gvproxy switch (containers/gvisor-tap-vsock) from source, at the
# commit pinned in vendor/gvproxy/gvproxy.lock plus every patch in
# vendor/gvproxy/patches/, with the Go toolchain the lock pins.
#
# Why a source build: the upstream release's unexpose closes a forward's
# listener and leaves the connections it accepted open, so a withdrawn port
# keeps serving the connections already through it. The carried patch closes
# them. See docs/specs/03-spec-networking/architecture.md (gvproxy-source-build).
#
# Reproducible on purpose: CGO_ENABLED=0, -mod=vendor, -trimpath,
# -buildvcs=false and fixed ldflags, so every host builds the same bytes for an
# asset and scripts/fetch-gvproxy.sh can check the result against the lock.
#
# Usage:
#   scripts/build-gvproxy.sh <dest-path> <asset>   build one asset
#   scripts/build-gvproxy.sh --test <name>         run one Go test on the patched tree
#
# Assets: gvproxy-linux-amd64, gvproxy-linux-arm64, gvproxy-darwin (darwin-arm64).
#
# Environment (for tests and CI caches):
#   GVPROXY_LOCK      the lock file   (default vendor/gvproxy/gvproxy.lock)
#   GVPROXY_PATCHES   the patch dir   (default vendor/gvproxy/patches)
#   GVPROXY_GO_CACHE  where a fetched Go toolchain is kept
#                     (default ${XDG_CACHE_HOME:-$HOME/.cache}/minimal/go)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="${GVPROXY_LOCK:-$ROOT/vendor/gvproxy/gvproxy.lock}"
PATCHES="${GVPROXY_PATCHES:-$ROOT/vendor/gvproxy/patches}"
REPO=https://github.com/containers/gvisor-tap-vsock
MODULE=github.com/containers/gvisor-tap-vsock

die() { echo "build-gvproxy: $*" >&2; exit 1; }

usage() {
  echo "usage: build-gvproxy.sh <dest-path> <asset>" >&2
  echo "       build-gvproxy.sh --test <name>" >&2
  exit 2
}

test_name=""
dest=""
asset=""
case "${1:-}" in
  --test) [ $# -eq 2 ] || usage; test_name="$2" ;;
  ""|-*) usage ;;
  *) [ $# -eq 2 ] || usage; dest="$1"; asset="$2" ;;
esac

[ -f "$LOCK" ] || die "no lock file at $LOCK"
lock_value() { sed -n "s/^$1=//p" "$LOCK"; }
VERSION="$(lock_value version)"
COMMIT="$(lock_value commit)"
GO_VERSION="$(lock_value go)"
if [ -z "$VERSION" ] || [ -z "$COMMIT" ] || [ -z "$GO_VERSION" ]; then
  die "malformed $LOCK: need version=, commit= and go= lines"
fi

if [ -n "$asset" ]; then
  case "$asset" in
    gvproxy-linux-amd64) goos=linux;  goarch=amd64 ;;
    gvproxy-linux-arm64) goos=linux;  goarch=arm64 ;;
    gvproxy-darwin)      goos=darwin; goarch=arm64 ;;
    *) die "unknown asset ${asset}: expected gvproxy-linux-amd64, gvproxy-linux-arm64 or gvproxy-darwin" ;;
  esac
fi

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Every patch must carry the digest the lock records for it, before anything
# is fetched: a patch edited without the lock, or the lock without the patch,
# stops the build here.
patches=()
if [ -d "$PATCHES" ]; then
  for patch in "$PATCHES"/*.patch; do
    [ -e "$patch" ] || continue
    name="$(basename "$patch")"
    want="$(lock_value "patch.${name}")"
    [ -n "$want" ] || die "patch ${name} has no patch.${name}= line in $LOCK"
    got="$(sha256_of "$patch")"
    if [ "$got" != "$want" ]; then
      echo "build-gvproxy: patch ${name} does not match its SHA-256 in $LOCK" >&2
      echo "  got:  ${got}" >&2
      echo "  want: ${want}" >&2
      exit 1
    fi
    patches+=("$patch")
  done
fi
# A patch the lock names must be present, or the build is not the pinned one.
while IFS= read -r name; do
  [ -n "$name" ] || continue
  [ -f "$PATCHES/$name" ] || die "patch ${name} is in $LOCK but not in $PATCHES"
done < <(sed -n 's/^patch\.\([^=]*\)=.*/\1/p' "$LOCK")

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The Go toolchain: the one on PATH when it is the pinned version, else the
# pinned release archive, verified against the lock's digest for this host.
go_bin=""
if command -v go >/dev/null 2>&1 && [ "$(GOTOOLCHAIN=local go env GOVERSION 2>/dev/null)" = "go${GO_VERSION}" ]; then
  go_bin="$(command -v go)"
else
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  host=linux-amd64 ;;
    Linux-aarch64) host=linux-arm64 ;;
    Darwin-arm64)  host=darwin-arm64 ;;
    *) die "no pinned Go toolchain for $(uname -s)-$(uname -m)" ;;
  esac
  go_sha="$(lock_value "go-${host}")"
  [ -n "$go_sha" ] || die "no go-${host}= line in $LOCK"
  go_cache="${GVPROXY_GO_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/minimal/go}"
  go_root="${go_cache}/go${GO_VERSION}.${host}"
  if [ ! -x "${go_root}/bin/go" ]; then
    url="https://go.dev/dl/go${GO_VERSION}.${host}.tar.gz"
    echo "build-gvproxy: downloading ${url}"
    archive="${WORK}/go.tar.gz"
    curl -fsSL "$url" -o "$archive"
    got="$(sha256_of "$archive")"
    if [ "$got" != "$go_sha" ]; then
      echo "build-gvproxy: SHA-256 mismatch for go${GO_VERSION}.${host}.tar.gz" >&2
      echo "  got:  ${got}" >&2
      echo "  want: ${go_sha}" >&2
      exit 1
    fi
    mkdir -p "$go_cache"
    unpack="$(mktemp -d "${go_cache}/unpack.XXXXXX")"
    tar -xzf "$archive" -C "$unpack"
    # Renamed into place, so a concurrent build never sees half a toolchain.
    mv "$unpack/go" "$go_root" 2>/dev/null || [ -x "${go_root}/bin/go" ] \
      || die "could not install the Go toolchain at ${go_root}"
    rm -rf "$unpack"
  fi
  go_bin="${go_root}/bin/go"
fi

# Fetch the pinned commit directly (not the tag): a moved or deleted tag can
# never change what we build.
SRC="${WORK}/src"
echo "build-gvproxy: fetching ${REPO} @ ${COMMIT} (${VERSION})"
git init -q "$SRC"
git -C "$SRC" remote add origin "$REPO"
git -C "$SRC" fetch -q --depth 1 origin "$COMMIT"
git -C "$SRC" checkout -q FETCH_HEAD
actual="$(git -C "$SRC" rev-parse HEAD)"
[ "$actual" = "$COMMIT" ] || die "fetched HEAD ${actual} is not the pinned commit ${COMMIT}"

# Apply the carried patches in sorted order (the glob sorts). `git apply`
# exits non-zero on any rejected hunk and leaves the tree untouched, so a stale
# patch stops the build instead of producing an unpatched switch.
for patch in "${patches[@]+"${patches[@]}"}"; do
  name="$(basename "$patch")"
  echo "build-gvproxy: applying ${name}"
  if ! git -C "$SRC" apply --verbose "$patch"; then
    die "patch ${name} does not apply to gvisor-tap-vsock ${COMMIT} (${VERSION}); rebase it or drop it"
  fi
done

# A pinned, offline, local toolchain: no automatic toolchain switch, no module
# downloads, and no settings from the caller's environment.
export GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off GOWORK=off CGO_ENABLED=0

if [ -n "$test_name" ]; then
  # The packages whose tests define the name, so one test compiles one package.
  pkgs=()
  while IFS= read -r file; do
    pkgs+=("./$(dirname "$file")")
  done < <(cd "$SRC" && grep -rl --include='*_test.go' "^func ${test_name}(" pkg cmd 2>/dev/null | sort -u)
  [ "${#pkgs[@]}" -gt 0 ] || die "no Go test named ${test_name} in the patched tree"
  echo "build-gvproxy: go test -run '^${test_name}\$' ${pkgs[*]}"
  (cd "$SRC" && "$go_bin" test -count=1 -v -run "^${test_name}\$" "${pkgs[@]}")
  exit $?
fi

ldflags="-s -w -buildid= -X ${MODULE}/pkg/types.gitVersion=${VERSION}-minimal"
echo "build-gvproxy: building ${asset} (${goos}/${goarch}) with go${GO_VERSION}"
(cd "$SRC" && GOOS="$goos" GOARCH="$goarch" "$go_bin" build \
  -mod=vendor -trimpath -buildvcs=false -ldflags "$ldflags" \
  -o "${WORK}/${asset}" ./cmd/gvproxy)

mkdir -p "$(dirname "$dest")"
tmp="${dest}.build.$$"
cp "${WORK}/${asset}" "$tmp"
chmod +x "$tmp"
mv -f "$tmp" "$dest"
echo "build-gvproxy: ${asset} ${VERSION} at ${dest} ($(sha256_of "$dest"))"
