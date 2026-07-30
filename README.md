# fedramp-aion

Watches FedRAMP's authoritative machine-readable sources, detects real change,
and emits a cryptographically signed [`.aion`](https://crates.io/crates/aion-context)
chain as the deliverable.

The chain answers one question with a signature behind it: **what did FedRAMP
require on date X, and who says so?**

## Sources

| id | repo | what |
|---|---|---|
| `rules` | [`FedRAMP/rules`](https://github.com/FedRAMP/rules) | CR26 consolidated rules — 75 definitions, 328 rules, 46 KSIs, 79 control overlays |
| `schemas` | [`FedRAMP/schemas`](https://github.com/FedRAMP/schemas) | 11 machine-readable submission package schemas |
| `marketplace` | [`FedRAMP/marketplace-fedramp-gov-data`](https://github.com/FedRAMP/marketplace-fedramp-gov-data) | 670 products, 244 agencies, 50 assessors, authorization/reuse mappings |

There is no REST API on `fedramp.gov`, and `GSA/fedramp-automation` (the old
OSCAL baselines) now 404s. GitHub raw is the only distribution channel, so every
run pins `main` to a commit SHA before fetching.

## Status

Pipeline and workflows are in place. [DESIGN.md](DESIGN.md) records the
measured upstream behaviour the logic is built around, the change-detection
rules, and the determinism invariants.

## Quick start

```sh
cargo build --release

# one-time signing identity (file-backed, no OS keyring needed)
fedramp-aion keygen --key 1 --author 1 --keystore .keys --registry registry.json

# what would change? read-only, writes nothing
fedramp-aion plan

# fetch, diff, sign a new chain version, verify it
fedramp-aion sync --author 1 --key 1 --keystore .keys \
  --report out/CHANGES.md --outputs "$GITHUB_OUTPUT"

# independently check the chain and that data/ matches what was signed
fedramp-aion verify
```

Working offline against captured snapshots — how the logic is iterated:

```sh
fedramp-aion capture --out snapshots
fedramp-aion plan --from-dir snapshots
```

## What a run produces

| path | contents |
|---|---|
| `fedramp.aion` | the signed chain — one version per detected change |
| `data/*.json` | canonical per-source snapshots, so the PR diff is reviewable |
| `data/provenance.json` | pinned commit, upstream timestamp, and digests per source |
| `out/CHANGES.md` | the human report / PR body |

`sync` exits non-zero if the chain fails verification immediately after being
written, so a bad artifact is never published.

## Change detection

Byte comparison is useless here: the marketplace file is rewritten every day at
06:27 UTC whether or not anything moved. Detection is therefore:

1. canonicalize each source (JCS / RFC 8785),
2. strip the per-source volatile fields (`meta` on marketplace,
   `info.last_updated` on rules),
3. compare that digest against the previous chain payload,
4. run a semantic diff only where it moved.

Measured against 8 real consecutive marketplace days: 7 upstream rewrites, **5
commits**, 2 correctly suppressed.

Severity ranks what moved so a rule change is never buried:

`major` (a rule or schema moved) → `minor` (an authorization event) →
`routine` (counters ticking) → `metadata` → `none` (no commit).

Rule-level output names FedRAMP identifiers, not JSON paths:

```
## rules — major (1 added, 4 removed, 14 modified)
Added:   FRR/CPO/all/CSO/CPO-CSO-OSA
Removed: FRR/CCM/all/AGM/CCM-AGM-NAR, FRR/VER/all/AGM/VER-AGM-DRE …
Attention: FRR/CPO/rev5/CSF/CPO-CSF-CPM (class a) SHOULD → (absent)
```

That output is a replay of the real 2026-07-06 → 2026-07-14 upstream delta; it
reproduces all seven of FedRAMP's own commits for that day.

## Running as an action

`.github/workflows/watch.yml` runs daily at 07:30 UTC (an hour after upstream's
06:27 rewrite) and on manual dispatch. `routine` changes — counters ticking,
mapping rows — are auto-merged. Everything louder waits for a reviewer.

One-time bootstrap:

```sh
# 1. create the signing identity and reveal the seed once
cargo run --release -- keygen --key 1 --author 1 \
  --keystore .keys --registry registry.json --print-secret

# 2. commit registry.json — it holds only public keys
git add registry.json && git commit -m 'pin the signing identity'

# 3. store the printed seed as the AION_SIGNING_KEY repository secret
gh secret set AION_SIGNING_KEY

# 4. run once manually to write the genesis chain
gh workflow run watch.yml
```

The seed is used because the file keystore encrypts key material with a
machine-derived key: a key file copied to a runner cannot be decrypted there.
Nothing key-shaped is ever written to the runner's disk, and `.keys/` plus
`*.key` are gitignored.

Optional: enable *Allow auto-merge* in repository settings so routine PRs wait
for required checks instead of merging immediately.

## Tests

```sh
cargo test          # 51 tests, no network
cargo clippy --all-targets
```

The integration suite drives the whole pipeline offline: genesis, idempotent
reruns, daily no-op rewrites, classified changes, upstream drift, tampered
snapshots, malformed upstream responses, and payload determinism.
