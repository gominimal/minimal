<!-- PR title: use a Conventional Commit subject — `type(scope): summary`,
     imperative, lower-case, no trailing period. Add `!` before the colon for
     a breaking change. The `pr-title` check lints it. A squash merge uses it
     as the commit subject, and the release version is read from that subject.
     See docs/commit-conventions.md. -->

## Summary

<!-- What changes, and why. Link related issues (`Refs: #123` / `Closes: #123`). -->

## Testing

<!-- What you ran (`cargo test`, `cargo clippy`, harness/e2e scripts, manual
     steps) — paste the relevant output as evidence. -->

## Checklist

- [ ] Docs updated if behavior changed
- [ ] `BREAKING CHANGE:` footer present if this is a breaking change
