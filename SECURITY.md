# Security Policy

## Reporting a vulnerability

<!-- TODO(launch): confirm reporting channel (advisories-only vs a security@ address) before open-sourcing -->
Please report vulnerabilities through **GitHub private vulnerability
reporting**: open the repository's **Security** tab and click
**"Report a vulnerability"**. This creates a private advisory that only
the maintainers can see.

Please do **not** report security issues via public GitHub issues,
discussions, or pull requests — that discloses the problem to everyone
before a fix exists.

When reporting, include what you can of: the affected component and
version (`min version` / `mip --version`), reproduction steps or a
proof of concept, and your assessment of the impact.

## Response expectations

We are a small team. We aim to acknowledge new reports within **5
business days** and to keep you informed as we triage, fix, and
disclose. Please give us a reasonable window to ship a fix before any
public disclosure; we will credit reporters in the advisory unless you
prefer otherwise.

## Supported versions

Support follows the release channels used by the installer:

| Channel | Supported |
|---|---|
| `stable` | Yes — security fixes land in the current stable release. |
| `unstable` | Latest version only; update to the newest release. No backports. |
| `nightly` | Latest version only; update to the newest release. No backports. |

If you are on `unstable` or `nightly`, reproduce against the most
recent version before reporting — the issue may already be fixed.

## Scope

In scope:

- The released binaries: `min`, `mip`, `minimald`, and `minvmd`.
- The installer (the `curl | sh` install flow and the artifacts it
  downloads and verifies).
- The isolation boundaries: escapes from the build/task sandbox
  (Linux namespaces) or from the microVM used on macOS, and anything
  that lets a build or task read or modify host state it should not.
- The cache integrity model (content addressing, artifact
  verification).

Out of scope:

- Vulnerabilities in third-party packages that minimal builds or
  installs for you — report those upstream.
- Issues that require an already-compromised host or root access on
  the machine running minimal.
- Denial of service of your own local builds (e.g. a package
  definition that consumes excessive resources on your machine).
