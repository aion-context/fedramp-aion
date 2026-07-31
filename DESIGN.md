# fedramp-aion — pipeline logic

Detect change in FedRAMP's authoritative machine-readable sources, and emit a
cryptographically signed `.aion` chain as the deliverable.

Status: **logic under review.** No GitHub Action is committed until the logic
below is settled and the test suite covers it.

## 1. Sources

FedRAMP publishes structured data only through GitHub raw; there is no REST API
on `fedramp.gov` (`marketplace.fedramp.gov/api/v1/products.json`,
`fedramp.gov/data.json` both 404). `GSA/fedramp-automation` — the historical
home of the Rev5 OSCAL baselines — now 404s entirely, but **the content is
published by NIST directly** at `usnistgov/oscal-content`, which is where the
`oscal` source is pinned from.

| id | repo | path | shape |
|---|---|---|---|
| `rules` | `FedRAMP/rules` | `fedramp-consolidated-rules.json` | 567 KB; `info` + `FRD`/`FRR`/`KSI`/`CTL` |
| `schemas` | `FedRAMP/schemas` | `*.json` (dir) | 11 CR26 package JSON Schemas |
| `marketplace` | `FedRAMP/marketplace-fedramp-gov-data` | `data.json` | 4.4 MB; `meta` + 7 collections |
| `oscal` | `usnistgov/oscal-content` | `nist.gov/SP800-53/rev5/json/…catalog-min.json` | 4.9 MB; 1,196 controls in 20 groups |

Neither repo tags releases, so `main` is not a stable reference. Every run
resolves `main` → **commit SHA for that path**, then fetches the raw bytes at
that SHA. The pinned SHA is recorded in the payload; a run is replayable.

## 2. Observed upstream behaviour (measured 2026-07-30)

These measurements drive the design; re-check them if the pipeline misbehaves.

- **Marketplace is rewritten daily at 06:27 UTC.** All 8 sampled days differ at
  the byte level. Dropping `meta.last_change` collapses 3 of 8 into one digest.
  Byte-level detection would therefore open a PR every single day.
- **Marketplace day-to-day deltas are mostly counters** — `reuse 313 → 314`,
  `authorization 36 → 37`, plus the matching `agency_*` arrays. ~15 products
  move per day. Product adds are rarer (666 → 670 over a week).
- **Rules change in bursts.** 2026-07-14 carried 7 commits; `info.version` and
  `info.last_updated` were bumped in a *separate, later* commit than the
  content edits. **Change detection must never key on `info.version`** — a
  mid-burst fetch sees new content under an old version string.
- **`ReuseMapping.id` is not unique** (316 distinct ids across 2813 rows; even
  the `(id, agency_id, sub_id, sub)` composite only reaches 2617). It must be
  diffed as a multiset, not a keyed collection.
- **`.aion` stores one payload, not a payload per version.** Committing a
  second 4.7 MB payload grew the file by 367 bytes. The chain is a signed hash
  trail; it does not archive history. Git holds the content history, the chain
  proves it.

## 3. Pipeline

```
resolve → fetch → canonicalize → project → digest → compare → diff → classify → gate → emit → commit → verify
```

1. **resolve** — `GET /repos/{repo}/commits?path={path}&per_page=1` → `sha`,
   `committed_at`.
2. **fetch** — raw bytes at that SHA. Record `raw_sha256` and byte length.
3. **canonicalize** — parse JSON, re-serialize as JCS (RFC 8785, via
   `aion_context::jcs`). Upstream whitespace and key-order churn cannot reach
   the digest.
4. **project** — a per-source substance projection strips volatile fields:

   | source | stripped | rationale |
   |---|---|---|
   | `rules` | `info.last_updated` | pure timestamp; `info.version` is kept — it is a real identifier |
   | `schemas` | — | identity |
   | `marketplace` | `meta` | `meta.last_change` moves daily with no content change |
   | `oscal` | `catalog.uuid`, `metadata.last-modified`, `metadata.oscal-version` | measured: all three moved between the 2025-08-27 and 2026-05-13 publishes while the control text was byte-identical. `metadata.version` (5.2.0) is kept — it is the real revision |

5. **digest** — `content_sha256` over the whole canonical doc,
   `substance_sha256` over the projection. The gate reads `substance_sha256`.
6. **compare** — against the previous bundle, read **from the existing `.aion`
   file itself**, not a side-car state file. There is no state to drift.
7. **diff** — semantic, per source (§4).
8. **classify** — severity per source, then take the maximum (§5).
9. **gate** — every source unchanged ⇒ exit 0, no commit, no PR.
10. **emit** — canonical snapshots to `data/`, `changes.json` + `CHANGES.md`
    to `out/`. The text files are what a human reviews in the PR; the `.aion`
    is binary.
11. **commit** — `aion_context::operations::commit_version` (or `init_file` for
    genesis), signed by the CI key, message generated from the diff.
12. **verify** — `verify_file` against the registry immediately after writing.
    A chain that does not verify fails the run and is not published.

## 4. Diff semantics

### rules

Flattened to leaf ids, so a diff names rules rather than JSON paths:

| section | leaf id |
|---|---|
| `FRD` | `FRD/{group}/{FRD-XXX}` |
| `FRR` | `FRR/{family}/{applicability}/{class}/{RULE-ID}` — applicability is `all`\|`20x`\|`rev5` and is part of identity |
| `KSI` | `KSI/{family}/{KSI-XXX-YYY}` |
| `CTL` | `CTL/{family}/{CONTROL-ID}` |
| family `info` blocks | `{SECTION}/{family}/info` — carries `status` and `effective` |

Unknown top-level sections are diffed as opaque subtrees and reported as
**schema drift**, so an upstream structural change is surfaced, never silently
dropped.

Per-leaf: added / removed / modified, with the changed field names. Three
transitions are called out because they change what a provider must do:
`force` (`SHOULD → MUST`), `status`, `effective`.

### schemas

Keyed by filename: added / removed / modified. Modified files report changed
JSON pointers, with `required` and `properties` changes called out.

### marketplace

- `Products`, `Agencies`, `Assessors`, `AtoMapping` — keyed by `id`.
- `ReuseMapping` — multiset of canonical row digests; reports rows added and
  removed only.
- `Metrics`, `Filters` — opaque; reports which top-level fields moved.

Product field changes are split into two buckets:
- **material**: `status`, `auth_type`, `auth_date`, `impact_level`,
  `fedramp_ready`, `ready_status`, `ip_*_status`
- **counter**: `reuse`, `authorization`, `agency_reuse`,
  `agency_authorizations`, `service_last_90`, `all_others`

## 5. Severity

| severity | trigger |
|---|---|
| `major` | any `rules` leaf added/removed/modified, any `schemas` change, or an 800-53 control **that FedRAMP references** |
| `minor` | marketplace product add/remove or a **material** field change |
| `routine` | marketplace **counter**-only movement, mapping rows, or an 800-53 control FedRAMP does not reference |
| `metadata` | only `info.*` moved in rules |
| `none` | nothing moved — no commit |

The PR title leads with the highest severity **and names the source that moved**
— with four sources, `major` alone would not distinguish a FedRAMP rules change
from a NIST republish.

A source absent from the previous payload is summarised (`oscal added to the
bundle; 1,196 controls`) rather than listed as 1,196 additions.

## 6. Determinism invariants

The signed payload must be a pure function of the pinned upstream commits.

- **No wall-clock anywhere in the payload.** Fetch time lives in `changes.json`
  and the commit message only. Violating this makes every rerun produce a new
  digest and destroys idempotency.
- The `.aion` version timestamp is pinned to the newest upstream
  `committed_at`, not to `now`.
- All maps are JCS-ordered; all keyed collections are sorted by key; the one
  unkeyed collection (`ReuseMapping`) is compared as a multiset.
- **Idempotency test**: two runs against the same pinned SHAs produce identical
  bundle bytes and the second one commits nothing.

## 7. Failure modes the logic must handle

| failure | required behaviour |
|---|---|
| upstream mid-burst (content edited, `info.version` not yet bumped) | commit on substance; report the version as-is |
| upstream returns HTML/error body instead of JSON | parse failure ⇒ abort, no commit |
| a source is temporarily 404 | abort the whole run; never commit a partial bundle |
| upstream adds a new top-level section | diff as opaque, report as schema drift, still commit |
| chain fails verification after commit | fail the run loudly; the bad file is not pushed |
| CI signing key not in the registry | commit refuses (no `--force-unregistered` in CI) |

## 8. The action

`.github/workflows/watch.yml` runs daily at 07:30 UTC — an hour after
upstream's 06:27 UTC marketplace rewrite — and on manual dispatch:

```
build → sync → verify → branch + PR → close superseded PRs → auto-merge if routine
```

- **Signing.** The file keystore encrypts key material with a machine-derived
  key, so a key file copied to a runner cannot be decrypted there. CI signs
  from a hex Ed25519 seed in the `AION_SIGNING_KEY` secret, via
  `--signing-key`; nothing key-shaped is written to the runner's disk.
  `registry.json` holds only public keys and is committed.
- **Merge policy.** `routine` (marketplace counters, mapping rows) is
  auto-merged — `--auto` when branch protection is configured, an immediate
  squash otherwise. `minor`, `major`, `metadata`, and genesis wait for a human.
  The chain is verified inside the job *before* the PR exists, so an
  auto-merged artifact was never unverified.
- **Branch naming** is `fedramp-sync/<bundle digest prefix>` — hex, unique per
  upstream state, and it keeps upstream text out of the shell. Upstream strings
  reach git and `gh` only through quoted environment variables, never through
  `${{ }}` interpolation into a script.
- **Superseded PRs are closed.** Each PR is a full snapshot diffed against
  merged `main`, not a delta against the previous PR, so a newer PR strictly
  contains an older open one. Without this, an unreviewed `major` PR would
  accumulate a parallel queue of marketplace PRs.

`.github/workflows/verify.yml` runs `fmt`, `clippy -D warnings`, the test
suite, and `fedramp-aion verify` against the committed chain on every PR and
push to `main`.

## 9. Receipts

A receipt binds an action to the obligations in force when it was taken: a DSSE
envelope over an in-toto statement, signed by the **operator's** own
registry-pinned key rather than the feed's. Verification recomputes every claim
digest, then re-derives the operator's obligations from the signed rules and
compares them with what the receipt cites — so a receipt cannot overstate or
downgrade what binds its issuer.

Evidence is committed by BLAKE3 digest only. Content never enters the artifact,
because receipts are designed to be forwarded and packages contain CUI.

**Precision trap, found the hard way:** JCS canonicalization serializes numbers
with ECMAScript semantics, so any integer above 2^53 silently rounds. The
chain's `file_id` is a random u64 and was being written to the signed payload as
`6675964335526257000` instead of `6675964335526256880`. Large integers are now
carried as strings. No upstream source currently contains an integer over 2^53
— verified across all three — but a future one would corrupt the bundle the same
way.

## 10. Agent surface

`fedramp-aion mcp` serves the signed ruleset over newline-delimited JSON-RPC on
stdio. The design constraint is that **every tool result carries the chain
version, bundle digest, and upstream commit it came from** — an agent citing
FedRAMP can then be checked against a signed artifact instead of believed.

The chain is verified once at startup rather than per call, so a session cannot
straddle two versions and a tampered chain fails before any request is served.
Errors are errors: an unknown rule id returns `isError`, never an empty result,
because an agent will otherwise read silence as "nothing applies".

No async runtime, no MCP SDK — the stdio transport is a line loop and the method
set is small enough that a dependency would cost more than it saves.

## 11. Package validation

`fedramp-aion validate` checks a package against the schemas as signed, and
optionally seals the verdict into a receipt citing the rules that require the
artifact.

The resolver is the substance. FedRAMP's cross-schema `$ref`s name a resource
that does not exist (`…json/$defs/name`, which 404s), so resolution is offline
against the signed set, with the path form treated as the fragment it evidently
means. **Every repair is recorded in the report and the receipt** — an artifact
that silently deviated from the published bytes would be worse than none. A URI
outside the signed set is an error, never a network fetch.

Schema-to-rule binding uses the `schema.url` filename as the join key, so a
verdict carries the rule ids that require the artifact (`CCM-OCR-AVL` for an
ongoing certification report).

Deliberately out of scope: semantic rule checking. "Valid per the schema" is not
"satisfies VDR-FRP-*", and conflating them would oversell the receipt.

## 12. Still open

- Rev5 OSCAL baselines have no live home since `GSA/fedramp-automation` began
  404ing. If FedRAMP republishes them, they become a fourth source.
- Key rotation (RFC-0028) is supported by the format but not yet wired into a
  procedure here; the registry pins a single epoch.
