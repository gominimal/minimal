# Interactive tests

The suites in this directory test behaviour that needs a person at the
terminal, such as the policy prompts of `min`. A suite checks all that it can
by itself. At each step that needs you, it tells you what to do and then asks
what you saw.

No CI lane runs these suites. Run a suite before you merge a change to the
behaviour that it covers. When you change that behaviour, update the suite.

## Running a suite

```sh
just interactive-test <suite>
```

`<suite>` is the name of a directory here. The `README.md` of each suite
gives its scenarios, its environment variables and its host requirements.

## Writing a suite

A suite is a directory with an executable `run.sh` and a `README.md`. Use the
conventions of the current suites:

- **Isolate everything.** Give `--config-dir` and `--minimal-dir`. Then the
  suite does not read your config, write your `user_policy.toml`, or touch
  your daemon and sessions. Copy the fixtures into
  `.scratch/interactive-tests/<suite>/`. Do not write into the tree.
- **Clean up between scenarios and at exit**, also after Ctrl-C. Destroy the
  sessions of the suite, remove the policy that it made, and stop its daemon.
- **Check before you ask.** Let the script look at each exit code, the
  output, and the state in the session through `min session exec`. Ask the
  person only about things that the script cannot see, such as the number of
  prompts.
- **Tell the person exactly what to do** before each prompt. Say what
  appears, which option to select, which keys to push, and what the script
  checks after. If the answer is not yes or no, ask again.
- **End with a count of passes and failures.** Exit with a non-zero status if
  a check fails.
