---
title: CI proposals (needs-human)
description: Drafted-but-not-applied CI changes that require a code-owner review to land, with apply instructions and the follow-up checklist.
---

> This is internal documentation. It is not published to the docs site.

# CI proposals (needs-human)

Everything in this directory is a **draft**. Nothing here is wired into CI,
and nothing here may be applied by an agent.

## Why these are proposals and not PR-ready edits

The workflow layer is frozen: `.github/` is CODEOWNER-gated (the repo-wide
`* @gominimal/minimalists` rule in `.github/CODEOWNERS` plus required
code-owner review), and the CI contract in
[CONTRIBUTING.md](../../../CONTRIBUTING.md) forbids editing
`.github/workflows/` — coverage is extended through convention-discovered
tests, `scripts/`, and the `justfile` instead. The design rationale is
[docs/ci-strategy.md](../../ci-strategy.md) (§10, "Extending CI without
editing workflows"). New lanes and workflow edits are exactly the cases the
freeze exists for, so they are drafted here and a human code owner applies
them.

## The artifacts

| File | What it is |
|---|---|
| [`docs-site.yml`](docs-site.yml) | Complete draft of the docs-site CI lane, on the repo's lane pattern (always-triggered, in-workflow `changes` path filter, `if: always()` aggregator `docs-site-success`). Builds the VitePress site, blocks site-absolute links under `docs/reference/`, offline-checks internal links (lychee), uploads the rendered site; weekly online link sweep (advisory); Pages deploy job drafted but disabled (`if: false`). |
| [`ci-yml-docs-filter.patch`](ci-yml-docs-filter.patch) | Unified diff against `.github/workflows/ci.yml` adding `!package.json`, `!package-lock.json`, `!.nvmrc`, `!NOTICE` to the `code` negation filter and widening `!LICENSE` to `!LICENSE*`, so docs-site-only PRs skip the Rust lanes. |
| [`promote-yml-webapp-repoint.patch`](promote-yml-webapp-repoint.patch) | Unified diff against `.github/workflows/promote.yml` retargeting the post-promotion `reference-docs-promoted` dispatch from the deprecated gominimal/docs repo to gominimal/webapp (app-token scope, API call, comments). |
| [`webapp-reference-sync.yml`](webapp-reference-sync.yml) | Draft workflow **for the gominimal/webapp repo**: consumes the `reference-docs-promoted` dispatch, mirrors the `docs/reference/manifest.json`-listed pages at the promoted SHA into webapp, opens/updates a sync PR; plus a weekly advisory drift check against `main`. |

## Apply instructions (code owner)

All of this should go through a normal PR that a member of
`@gominimal/minimalists` reviews (code-owner review is required on
`.github/**` regardless).

1. **docs-site lane** — copy the draft into place and commit:

   ```sh
   cp docs/internal/proposals/docs-site.yml .github/workflows/docs-site.yml
   ```

   Prerequisite: the VitePress scaffold (`package.json`,
   `package-lock.json`, `.nvmrc`, a `docs:build` script emitting
   `docs/.vitepress/dist`) must be on `main` first.

2. **ci.yml filter update** — verify, then apply:

   ```sh
   git apply --check docs/internal/proposals/ci-yml-docs-filter.patch
   git apply docs/internal/proposals/ci-yml-docs-filter.patch
   ```

3. **promote.yml repoint** — verify, then apply:

   ```sh
   git apply --check docs/internal/proposals/promote-yml-webapp-repoint.patch
   git apply docs/internal/proposals/promote-yml-webapp-repoint.patch
   ```

4. Open the PR; once applied, delete the applied artifacts from this
   directory (or replace them with a pointer to the landing PR) so drafts
   and reality cannot drift.

`webapp-reference-sync.yml` does **not** land in this repo — it goes to
gominimal/webapp as `.github/workflows/reference-sync.yml` via a PR in that
repository.

## Follow-up checklist

- [ ] **Branch protection**: decide when `docs-site-success` becomes a
      required check on `main`. That is a ruleset edit AND a change to
      `release.yml`'s `verify-ci` expectations (its `required=` list of
      lane aggregators would need `docs-site-success` appended) — do both
      together or neither.
- [ ] **webapp PR**: land `webapp-reference-sync.yml` in gominimal/webapp.
      Depends on the reference manifest (`docs/reference/manifest.json`)
      landing here first; the draft documents the assumed manifest shape.
- [ ] **App installation**: install the gominimal-aw-bot App on
      gominimal/webapp before applying the promote.yml repoint, or the
      token mint fails at promotion time.
- [ ] **Pages deploy at launch**: flip `docs-deploy`'s `if: false` to the
      push-to-main condition documented inline, and set the repository's
      Pages source to "GitHub Actions".
      <!-- TODO(launch): confirm the final docs hosting story — GitHub
      Pages from this repo vs. serving exclusively from gominimal/webapp —
      before enabling the deploy job. -->
- [ ] **gen-cli-docs**: once the `cargo xtask gen-cli-docs` check exists,
      un-comment its step in the docs-site lane.
