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
fedramp-aion sync --author 1 --key 1 --keystore .keys --report out/CHANGES.md

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

## Obligations

Which rules apply to *you*, with the class-specific variant resolved:

```sh
fedramp-aion obligations --role Providers --class B --type Rev5 --path Agency
fedramp-aion obligations --class B --type Rev5 --force MUST --json
fedramp-aion obligations --with-schema        # only rules binding an artifact
```

Read from the signed chain by default, so what it lists is what was signed.
Against chain v1: a Rev5 Class B provider carries **162 obligations, 101
binding**; a Class A provider carries 47, because most subsets declare classes
B–D only.

Applicability is assembled from four places, because no single one is complete:

| dimension | source | fallback |
|---|---|---|
| certification type | the `data.<type>` path | always present |
| affected party | the rule's `affects` | subset applicability |
| class | `varies_by_class` keys | subset `classes`, else unconstrained |
| path | subset `paths` | unconstrained |

A class absent from `varies_by_class` has **no** obligation under that rule,
whatever the subset declares — that is how "Class A maintenance requirements
removed" is expressed in the data.

When the rules move, the change report gains a **Who this affects** table
translating the diff into per-profile obligation deltas. Replaying the real
2026-07-06 → 2026-07-14 upstream delta:

| profile | added | removed | changed | binding shifts |
|---|---|---|---|---|
| Providers, class A, type Rev5 | 1 | 1 | 0 | — |
| Providers, class B, type Rev5 | 1 | 0 | 0 | — |
| Agencies | 0 | 4 | 0 | — |

Class A Rev5 is the only profile that lost an obligation, and agencies lost
four — matching FedRAMP's own commit messages for that day.

## Receipts

The chain says what FedRAMP required. A receipt says what *you* did about it,
signed by you, against that exact version.

```sh
# the operator is a distinct author, appended to the same registry
fedramp-aion keygen --key 2 --author 2 --keystore .keys --registry registry.json --append

fedramp-aion receipt --operator 2 --key 2 --keystore .keys \
  --role Providers --class B --type Rev5 \
  --obligation CCM-OCR-AVL \
  --action "Submitted the Q3 ongoing certification report to the agency" \
  --decision satisfied --evidence q3-report.json

fedramp-aion receipt-verify receipt.json     # exit 0 valid, 1 invalid
```

A DSSE envelope over an in-toto statement — the format the surrounding
ecosystem already verifies — plus a plaintext claim whose every field is
digest-committed inside the envelope.

Verification is four independent checks:

| check | what it proves |
|---|---|
| signature by the operator | the operator's own registry-pinned key signed it, not the feed's |
| claim bound to signature | no field was edited after sealing |
| cites this chain | the receipt names this chain, version, and bundle digest |
| obligations match the signed rules | the operator did not misstate what binds them |

That last one is the point: `CCM-OCR-AVL / MUST` in a receipt is checked
against what the signed ruleset actually says for that profile, so an operator
cannot quietly downgrade their own obligation.

**Evidence never enters a receipt** — only its BLAKE3 digest, the filename, and
the size. That keeps CUI out of an artifact meant to be forwarded to an agency.

Attacks the format rejects, each covered by a test: editing the action text,
downgrading a cited `MUST` to `SHOULD`, swapping an evidence digest,
reattributing a receipt to another author, and signing with a key the registry
does not pin. Citing a rule that does not apply to the profile is refused at
issue time rather than at verification.

> Receipts are signed by the **operator**, never the feed. `receipt` refuses
> when `--operator` equals the feed author: a receipt the feed signed about
> itself attests to nothing.

## Package validator

Checks a submission package against the signed schemas, **offline**, and can
seal the verdict into a receipt.

```sh
fedramp-aion validate --list-schemas .          # the 11 signed schema names
fedramp-aion validate ocr.json                  # schema inferred from $schema
fedramp-aion validate ocr.json --json           # exit 0 valid, 2 invalid

fedramp-aion validate ocr.json --class B --type Rev5 \
  --receipt validation-receipt.json --operator 5 --key 5 --keystore .keys
```

Real output against the published schemas:

```
# ocr.json — INVALID
| schema        | fedramp-ongoing-certification-report-schema-2026-06-24.json |
| findings      | 9 |
| required by   | CCM-OCR-AVL |

- `/plannedCertificationDataChanges` — "planningHorizonThrough" is a required property
```

Two things make this more than `jsonschema` with extra steps.

**It resolves what FedRAMP publishes.** Their cross-schema `$ref`s are written
as paths rather than fragments — `…common-definitions-….json/$defs/nRating` —
and that URL returns 404, so an off-the-shelf validator dies at reference
resolution before checking a single constraint. Resolution here is offline
against the signed schemas, and **every repair is recorded in the report**, so
the verdict never pretends the published bytes validated as they stand:

```
## Reference repairs
- `…-2026-06-24.json/$defs/reportPeriodDate → …-2026-06-24.json#/$defs/reportPeriodDate`
```

A URI outside the signed set is an error, never a fetch. A verdict whose meaning
depends on what a server returned today cannot be a durable receipt.

**It names the rule that requires the artifact.** `required by: CCM-OCR-AVL` is
a join from schema to the rules that bind it, out of the same signed ruleset —
which is what makes the verdict a compliance statement rather than a syntax
check. The receipt then cites that rule as the obligation it discharges.

The package never leaves the machine, and only its digest enters the receipt.

## MCP server

Serves the signed ruleset to agents over stdio, so an agent's answer about
FedRAMP cites a version rather than being trusted because a model said it.

```sh
claude mcp add fedramp -s user -- \
  /path/to/fedramp-aion mcp \
  --chain /path/to/fedramp.aion --registry /path/to/registry.json
```

Four tools, each returning its citation alongside the answer:

| tool | answers |
|---|---|
| `fedramp_status` | which signed version this server speaks for, and whether the chain verified |
| `fedramp_obligations` | the rules applying to a profile, class variant resolved |
| `fedramp_rule` | one rule by FedRAMP id, e.g. `CPO-CSF-CPM` |
| `fedramp_search` | full-text across the ruleset, returning ids to cite |

Every result carries `provenance`:

```json
{
  "chain_version": 1,
  "chain_verified": true,
  "bundle_sha256": "010e7f1e282c…",
  "upstream_version": "2026.07.14.01",
  "rules_commit": "083137da3b3cbd88eb55575fa2f153fb9a7b0e4c",
  "rules_committed_at": "2026-07-14T21:11:57Z"
}
```

The chain is loaded and **verified once at startup**, so every answer in a
session speaks for the same version and a tampered chain fails before the
server accepts a request. A missing rule is an error, not an empty answer —
an agent should not read silence as "no obligation".

## Running as an action

`.github/workflows/watch.yml` runs daily at 07:30 UTC (an hour after upstream's
06:27 rewrite) and on any push to `main`. `routine` changes — counters ticking,
mapping rows — are auto-merged. Everything louder waits for a reviewer.

**Nothing needs starting by hand.** The genesis chain is written by the first
run that finds no `fedramp.aion`, so pushing the repo is enough to bootstrap it.
Runs triggered by the bot's own auto-merge are skipped, so the loop terminates.

The one unavoidable human act is placing the signing key, because the point of
the artifact is that a person controls the identity behind the signature:

```sh
# once: create the identity, reveal the seed, pin the public half
cargo run --release -- keygen --key 1 --author 1 \
  --keystore .keys --registry registry.json --print-secret
git add registry.json && git commit -m 'pin the signing identity'
```

Then load the secret. `secret` prints the seed on **stdout only** — everything
else goes to stderr — so it pipes without ever being displayed:

```sh
cargo run --release -- secret | gh secret set AION_SIGNING_KEY
```

It refuses to print a key the committed `registry.json` does not pin, which is
the mistake that would otherwise produce a chain that fails verification. Use it
whenever the secret needs restoring — as long as `.keys/` survives, the identity
is recoverable and `keygen` should not be re-run.

`registry.json` carries only public keys. Without the secret, the sync step
fails rather than producing an unsigned artifact.

> The file keystore encrypts to the machine that created it, so `.keys/` is
> local to one box. Back up the seed itself, not the key file.

The seed is used because the file keystore encrypts key material with a
machine-derived key: a key file copied to a runner cannot be decrypted there.
Nothing key-shaped is ever written to the runner's disk, and `.keys/` plus
`*.key` are gitignored.

Optional: enable *Allow auto-merge* in repository settings so routine PRs wait
for required checks instead of merging immediately.

## Tests

```sh
cargo test          # 92 tests, no network
cargo clippy --all-targets
```

The integration suite drives the whole pipeline offline: genesis, idempotent
reruns, daily no-op rewrites, classified changes, upstream drift, tampered
snapshots, malformed upstream responses, and payload determinism.
