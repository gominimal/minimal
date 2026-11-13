# metrics-data

The quality-metrics history of `gominimal/minimal`. One snapshot per
nightly run under `history/`, named by date and short commit, written by
`scripts/metrics/publish-snapshot.sh` from the nightly workflow. Nothing else
lives here, and nothing here is edited by hand: the gate reads the newest
snapshot as its baseline, and the dashboard reads them all.
