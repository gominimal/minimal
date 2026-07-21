# Security Policy

Thanks for helping keep Minimal and its users safe.

## Reporting a vulnerability

Please report vulnerabilities by email to **security@minimal.dev**. We
will acknowledge the report and coordinate a fix and disclosure with you
privately.

Please do **not** report security issues via public GitHub issues,
discussions, or pull requests — that discloses the problem to everyone
before a fix exists.

When reporting, include what you can of: the affected component and
version (`min --version` / `mip --version`), reproduction steps or a
proof of concept, and your assessment of the impact. If you'd like to
encrypt your report, say so in your first email and we'll coordinate a
key exchange.

## No bug bounty

Minimal does not operate a paid bug bounty program. We genuinely
appreciate good-faith reports and are glad to credit researchers in the
disclosure, but we do not offer monetary rewards.

We reserve the right to disregard low-effort, unsolicited "beg bounty"
reports — for example, automated scanner output, missing security
headers, or theoretical findings with no demonstrated impact on the
components in scope below. For background on why, see [Troy Hunt on beg
bounties](https://www.troyhunt.com/beg-bounties/).

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

## Safe harbor

We will not pursue or support legal action against researchers who:

- Make a good-faith effort to comply with this policy.
- Avoid privacy violations, destruction of data, and interruption or
  degradation of others' use of minimal.
- Give us reasonable time to investigate and address a reported issue
  before any public disclosure.
