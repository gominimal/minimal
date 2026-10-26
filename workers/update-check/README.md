# update-check

The version endpoint of `min`'s daily update check (gominimal/inbox#589).
The client is `crates/minimal/src/update_check.rs`; the user-facing page is
`docs/reference/telemetry.md`, "Update check".

```
GET https://update.minimal.dev/v1/<channel>/<key>?os=<os>&arch=<arch>&install=<method>&id=<uuid>
200 {"channel":"stable","latest":"0.7.2"}   Cache-Control: no-store
404 channel not in {stable, unstable, nightly}, or a field missing or outside its charset; nothing recorded
503 the channel pointer could not be read; nothing recorded
```

`latest` is the channel pointer in `gs://minimal-one/<channel>`, read through
a 5 minute edge cache. Promotion (`scripts/set-channel.sh`) stays the single
source of truth; nothing here is written on release.

## What is recorded

One Workers Analytics Engine data point per answered request, dataset
`update_checks`:

| column | value |
|---|---|
| blob1 | install id |
| blob2 | channel |
| blob3 | key (the pointer the install came from) |
| blob4 | os |
| blob5 | arch |
| blob6 | install method |
| blob7 | country (`request.cf.country`) |
| blob8 | ASN (`request.cf.asn`) |
| double1 | 1 when key equals the pointer (up to date), else 0 |
| index1 | install id |

The request's address is not stored. The client makes at most one request
per install per day, so distinct install ids over a day are the installs
that ran `min` that day:

```sql
SELECT blob2 AS channel, count(DISTINCT blob1) AS installs
FROM update_checks
WHERE timestamp > NOW() - INTERVAL '1' DAY
GROUP BY channel;

SELECT blob7 AS country, blob4 AS os, blob5 AS arch, count(DISTINCT blob1) AS installs
FROM update_checks
WHERE timestamp > NOW() - INTERVAL '7' DAY AND blob2 = 'stable'
GROUP BY country, os, arch ORDER BY installs DESC;
```

## Tests and deploy

```sh
min run test-update-check      # node --test "test/**/*.test.js" over src/logic.js, no Workers runtime needed
min run deploy-update-check    # wrangler deploy, pinned through the package catalog
```

CI deploys a main commit that touches this tree once CI is green on it
(`.github/workflows/deploy-update-check.yml`), the same gate as webapp's
landing-edge Worker. Secrets: `CLOUDFLARE_WORKER_DEPLOY_TOKEN` (Workers
Scripts:Edit, Workers Routes:Edit, Zone:Read on minimal.dev) and
`CLOUDFLARE_ACCOUNT_ID`. The proxied `update.minimal.dev` AAAA record and
the per-IP rate-limit rule are Pulumi's, in gominimal/infra
`cloudflare/main.go`.
