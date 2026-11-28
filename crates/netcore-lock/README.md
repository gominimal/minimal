# netcore-lock

The gates that keep `crates/netcore`'s claims fixed. A proof checker says a proof matches its statement. It does not say the statement is the one that was reviewed. These scripts hold every statement the crate makes, apart from how it is proved, so a change to what is claimed shows as a diff in a file that is read on purpose. They hold the negative controls that show each proof can fail, too.

| File | What it is |
|---|---|
| `statements.py` | The text lock's extractor and gate: `--check`, `--write`, `--counts` |
| `STATEMENTS.lock` | The text lock: every specification, contract, lemma statement, Kani harness, cited unit check, registry row and control, extracted from the source |
| `view.py` | The second lock: the verifier's own account of the crate (the `crate.vir` that `verus --log vir` writes), digested per function, compared with the text lock's items |
| `VIEW.lock` | The second lock, as written from that account |
| `statements_selftest.py` | Attacks both locks must catch, honest edits they must pass, and the known gaps they let through, each run on a copy |
| `controls.toml` | The negative controls: for each, the edit to the crate, what it breaks, where the verifier must reject it, and the run that showed it |
| `controls.py`, `scan.py` | The controls' tool: `--check` (every live control applies to the crate exactly once), `--cut` (one changed copy per control), `--judge` (reads the verifier's output for each copy), `--confirm`, `--lists` |
| `coverage-by-statement.py` | For every statement in the lock, how many controls the runs rejected inside it |
| `headers/`, `results/` | The paragraph at the top of each generated list, and the runs the lists cite |

## How to run

```
python3 statements.py --check                  # the gate: exit 1 on any difference, with the diff
python3 statements.py --write                  # after reading the diff
python3 view.py --check --vir CRATE.VIR        # the second lock, against a dump of the same source
python3 statements_selftest.py --vir CRATE.VIR # every attack, honest edit and gap, on copies
python3 controls.py --check                    # every live control applies to the crate (Python 3.11 or later)
```

The crate defaults to `../netcore`. The CI script whose pinned count the lock holds defaults to `../../scripts/verus.sh`; `--verus-script PATH` names another. Each script restarts itself in Python's isolated mode before its first import, so no file beside it and no `PYTHONPATH` can answer an import. `scripts/verus.sh` runs the verifier with the dump and then `statements.py --check`, `view.py --check` and `controls.py --check`, and fails on any of them.

## What is locked, and what is free

Locked: the manifest; every specification function whole; every `requires`, `ensures`, `recommends` and `decreases` of a function; the statement of every lemma and theorem; every Kani harness and its helpers, whole; the unit checks a row of the theorem index cites, with their helpers; the rows of `axioms/REGISTRY.md`; the rows of every control table in `crates/netcore/verus/`; `controls.toml` whole; the theorem index in `src/lib.rs`; the count the CI script pins; and a digest of each gate script.

Free: proof bodies, `proof!` blocks, loop invariants, function bodies, comments outside `src/lib.rs`, unit tests no row cites, and prose files.

Each source file is read by lines and as tokens, and where both readings see the same thing they must agree, or the file is refused. A line ends at a line feed only, as it does for the compiler. Every attribute and macro in use is on a list, and anything else is refused.

## The second lock

The text lock reads what is written. `view.py` reads what the verifier resolved: each function's kind, its marks (for example an external body or an assumed specification), and a digest of its statement as the verifier saw it, with source positions left out. The two must describe the same functions. This catches what a reading of the text cannot: a name that resolves somewhere else than it reads, or an attribute spelled in a way the text scan does not know.

## Negative controls

A control is a deliberate defect in a copy of the crate, which the verifier must reject inside the functions the control names. `controls.toml` is the file of record. The lists in `crates/netcore/verus/` are generated from it and from `results/`, and are not edited by hand. A control is live (run on every text), accepted with a reason (the verifier accepts it, and why that is fine), retired or not cuttable (with a reason), or caught by the compiler. An error that is the solver's resource limit is recorded as a cost, never as a place. Every theorem of the crate is the place of at least one rejection in the run `results/` holds. That run describes the crate text its first line names; after a change to the crate, the controls are run again on purpose and the new results committed with it, as the locks are rewritten on purpose.

## Changing a statement

1. Change the source, and run `statements.py --check`. The diff names each changed statement and where it is.
2. A weaker or different claim is reviewed as such. If it is meant, `statements.py --write`, and the lock's diff goes in the same change.
3. A change to a contract or a theorem comes with its controls: rerun the ones it touches, and add one for anything new.
4. `view.py --write` after a dump of the changed source, and the self-test.

## Known gaps

The self-test lists what these gates let through, and checks that each still passes, so the list stays true:

- a module's own statement of its theorems in a doc comment outside `src/lib.rs` (comments are free there; the index in `src/lib.rs` is locked);
- a non-live control's reason edited in a generated list alone (the list's second table is not a control table; `controls.toml`, which is locked, still holds the reason);
- the crate's README (free prose).
