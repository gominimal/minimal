# Untrusted loadouts

This suite tests how `min` gates the loadouts in
`<config>/minimal/loadouts-untrusted/`. The user policy gates those loadouts
as it gates a project. The loadouts in `loadouts/` skip the `allow` step of
the policy.

```sh
just interactive-test untrusted-loadouts
SKIP_BUILD=1 just interactive-test untrusted-loadouts   # use the last build
```

## Requirements

- macOS on Apple Silicon, with the [VM prerequisites](../../AGENTS.md#system-dependencies).
- `zig`, `cargo-zigbuild` and the `aarch64-unknown-linux-musl` Rust target.
  The suite builds the guest `minimald` with `just initramfs-nodocker`, so it
  does not use Docker or rustup.
- `python3`, to give `min dash` a pseudo-terminal in the dashboard scenario.
- The checkout must be below `$HOME`, because some policy rules are `~/`
  paths into the copied fixtures.

## Isolation

The suite does not touch your config, your daemon or your sessions:

- **Config:** The suite copies `fixtures/config/` to
  `.scratch/interactive-tests/untrusted-loadouts/config/minimal/` and gives
  that location as `--config-dir`. All policy rules go into the
  `user_policy.toml` there.
- **Daemon:** `--minimal-dir ~/.local/state/minimal-interactive-tests` starts
  a different VM. Your installed stack continues to run next to it.
- **Project:** an empty temporary directory, activated with `--sync none`.
  So `min` does not ask to create a `minimal.toml` or to upload the
  directory. Loadout patches and hook scripts get to the session through a
  different upload.

Between scenarios, the suite destroys all sessions in its state directory and
deletes its `user_policy.toml`. At exit, also after Ctrl-C, it stops its
daemon. Then it deletes its copy of the fixtures and the temporary project.
If a VM continues to run after that, `just reap` stops it.

## Environment variables

| Variable | Effect |
|---|---|
| `SKIP_BUILD=1` | Do not build. Use the last build. |
| `INTERACTIVE=0` | Skip the interactive steps. When stdin is a terminal, the default is to run them. |
| `KEEP_DAEMON=1` | Do not stop the daemon of the suite at exit. |
| `LIST_ONLY=1` | Run only the listing checks, which do not start a daemon. |
| `STATE=<dir>` | The state directory of the daemon. Keep it short: a socket path below it must not be longer than about 104 bytes. |

## Automatic scenarios

These scenarios run with `--no-prompt`. Where a person can approve at a
prompt, the suite approves with an `allow` rule. For each refusal, the suite
also makes sure that no session stays.

| Scenario | Loadout | Expected |
|---|---|---|
| Listing | all | The suite tags each `ut-*` row `(untrusted)`. For `fixtures/list-test/`, see [Listing fixture](#listing-fixture). |
| Trusted hook | `t-hook` | The hook runs with no prompt and logs `kind=loadout`. |
| Trusted inherit | `t-inherit` | `UT_TEST_TOKEN` gets into the session with no prompt. |
| Untrusted literal | `ut-literal` | Refused with a `[vars]` snippet, unlike a project's literal. A `[vars] allow` rule lets it pass. |
| Untrusted inherit | `ut-inherit` | Refused with a `[vars]` snippet. A `[vars] allow` rule lets it pass. |
| Untrusted patch | `ut-patch` | Refused with a `[patches]` snippet. A `[patches] allow` rule lets it pass. |
| Untrusted hooks | `ut-hook` | Refused with a `[hooks]` snippet. With `--no-hooks`, it passes and the hooks do not run. With a `[hooks] allow` rule on its directory, the two hooks run and log `kind=loadout-untrusted`. |
| Missing script | `ut-missing-script` | If the policy allows the hook, hook staging fails. If the policy ignores the hook, activation passes. |
| `HOME` attack | `ut-home-attack` | The loadout sets `HOME = "/nonexistent"`. A `~/` deny rule continues to match its patch source, because `~/` expands only from trusted vars. |
| Var attack | `ut-var-attack` | The loadout sets `UT_TRUST_ROOT` to its own directory. The `[hooks] allow = ["$UT_TRUST_ROOT"]` rule fails as an unresolved variable and does not match. |
| Mixed | `t-hook` with `ut-hook` | Each hook logs its own kind. |
| Hooks deny | `ut-hook` | A `[hooks] deny` rule on its directory fails the activation. An `ignore` rule activates without running the hooks. |
| Dashboard | `ut-inherit` as a default loadout | `min dash` refuses before the dashboard opens, and its message names `min dash`, not `--no-prompt`. |

The two attack scenarios also allow the var they set (`HOME`, `UT_TRUST_ROOT`).
Without that, the var gate refuses the literal first, and the scenario never
reaches the rule that it tests.

The `HOME` attack also has an allow rule for the patch, with its absolute
path. If the `~/` deny rule did not match, the allow rule can let the patch
through, so the scenario passes only when the deny rule works.

### Listing fixture

`min loadout list --dir fixtures/list-test` must:

- Exit with a non-zero status and report `3 loadouts failed to load`.
- Show a warning about `missing`.
- Put a star on `alpha` and on `beta (untrusted)`.

## Interactive steps

After the automatic scenarios, the suite shows you the real prompts. Before
each step, a box tells you what appears and which option to select. It also
tells you what the suite checks after the step. Each prompt shows a menu, in
which you push the arrow keys to move and Enter to select. The cursor starts on "Allow once". Do not select a
"permanent" option.

| Loadout | You do | You answer |
|---|---|---|
| `ut-inherit` | Enter on **Allow once** | One menu, with `UT_TEST_TOKEN` in it |
| `ut-inherit` | Down to **Abort activation**, Enter | Nothing: the suite makes sure that no session exists |
| `ut-patch` | Enter on **Allow once** | One menu, with `greeting.txt` in it |
| `ut-hook` | Enter on **Allow once** | One hook menu only, although the loadout has two hooks |
| `ut-literal` | Enter on **Allow once** | One menu, which shows the value `"hello-from-ut-literal"` |
| `ut-home-attack` | Nothing | It fails with a denial and does not show a menu |

## Fixture traps

The fixtures prevent these mistakes, each of which can make a scenario pass
for the wrong reason:

- **Top-level keys come first.** If `patches = [...]` comes after a `[vars]`
  header, TOML puts it in `vars.patches`. The patch then becomes a var, and
  no error shows.
- **Inherited vars have no `default`.** If the host does not set the var, an
  inherited var with a default uses the default. From an untrusted loadout the
  policy still gates it, but the prompt shows the default instead of asking to
  read your environment. The suite sets `UT_TEST_TOKEN` itself.
- **`default_loadouts` goes under `[loadouts]`** in `config.toml`. At the top
  level, `min` ignores it.
- **`ut-var-attack.toml` has a placeholder.** The suite replaces
  `@LOADOUTS_UNTRUSTED@` with the absolute path of the copied directory.
