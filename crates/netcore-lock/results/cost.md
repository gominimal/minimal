# Cost recorded beside run-1

From run-1's own Verus output (each copy's `--output-json`, `times-ms.smt.smt-run-module-times[].function-breakdown`,
field `rlimit`), Verus at `--rlimit 0.3`, default seed.

`Pool::expire` (pool.rs):

- On the clean text, as it stands in the 774 copies of this run that do not edit pool.rs: rlimit count min 344,465,
  median 354,944, max 535,928.
- In the copies that edit another function of pool.rs and are reported "rlimit exceeded" in `expire`: added:A8 982,294; pins:F6 971,307; pool:2 980,384; sweep:X8 972,228.

An rlimit error is cost, not a place: it does not count against `fail_in`. The `cost` column of run-1.tsv lists
every cost entry of the run. Where the JSON's per-function rlimit is below the ceiling, it is the function's total
over its queries, not the failing query's count.
