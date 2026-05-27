# justfile — repo-wide task runner. Lives at the workspace root.
#
# Recipes are grouped by crate where they're crate-specific.

# Build a release `minvmd` binary and code-sign it with the hypervisor
# entitlement. Re-run any time the entitlements file or binary changes.
# Ad-hoc signing (`-s -`) requires no Apple Developer membership; the binary
# only runs on the host that signed it, which is correct for dev builds.
codesign-minvmd:
    cargo build -p minvmd --release
    codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - target/release/minvmd
