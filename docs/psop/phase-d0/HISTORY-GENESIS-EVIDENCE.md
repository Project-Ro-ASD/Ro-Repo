# History, availability and first Stable genesis

G-06 **BLOCKED**. No genesis or dwell authority is issued here.

## Current read-only findings

[History scan](../../evidence/psop-phase-d0/history.json) inspects all 300 reachable
commits from exact storage `097ba6ba7ab73d87c36f7ec9829b017b083b1883`, nonshallow:
no Stable tree hits and no detected mutation/deletion of inventoried immutable
snapshot/publication/promotion/rollback history. Five snapshots are present,
`20260920`, `20260921`, `20260929`, `20261006`, `20261009` (each suffix `-001`).
Deleted branches, unreachable objects, removed runs and external archives remain
UNVERIFIED. A bounded negative result is not proof of universal absence.

[Public signing audit](../../evidence/psop-phase-d0/public-signing.json) verifies
snapshot metadata and RPMs at all five snapshots (3, 3, 24, 26, 30 RPM paths), plus
six original Beta publication manifests: runs `35530066972`, `35586124137`,
`35587617947`, `35599214422`, `36123484599`, `37935890476`.
Legacy records omit `store_tree_sha256` in four cases; preserve their original
signed bytes. The compatibility adapter verifies original signatures; the strict
history parser rejects unexpected legacy fields. No normalized replacement is
retroactively signed or treated as original authority.

[GitHub capture](../../evidence/psop-phase-d0/github-observations.json) returned
5 snapshot, 7 Beta and 5 rollback workflow runs (all returned within per_page=100),
and 0 runs for the named V2 Stable workflow. Counts cover accessible API records
only; removed workflow names/runs and manual writes remain unknown. Additional
Pages build records are observations in [additional GETs](../../evidence/psop-phase-d0/github-additional.json).

| Fact | Trust meaning |
| --- | --- |
| Valid signature over publication `published_at` | Signer committed to that timestamp/bytes; not an independent public availability witness |
| Git commit timestamp / Actions run time / Pages build status | Provider/author timing observation; no proof all public bytes were available continuously |
| Prior HTTP 404 or absence of Stable in reachable trees | Negative observation at bounded scope/time; no genesis grant |
| Prior signed archive verification | Integrity of observed records; no coverage for missing records/intervals |
| New independently signed full HTTPS observation | Proves observer's bounded observation at that time/place under its trust policy; cannot backdate first-ever availability |

## Recover evidence honestly

Search accessible exact run artifacts/logs, historical signed inventories and
independent contemporaneous monitors or timestamped immutable audit archives.
Authenticate observer identity and verify original signatures, source/result hashes,
region/time and complete-path coverage. Bind retrieved records to exact publication
and check gaps, failures, supersession and key validity. Provider timestamps may
help correlate, but cannot fill absent full-byte coverage. Expired/missing artifacts
remain explicit gaps; owner recollection is context, not cryptographic dwell.

If sufficient historical evidence cannot be recovered, start a **new prospective
observation interval** for the exact candidate. Do not credit elapsed calendar
time from `published_at`. Proposed observer protocol requires independently
provisioned witness keys, trusted clock with bounded skew and append-only external
checkpoint. First verified full-byte observation is conservative `dwell_start`,
never a claim of first-ever availability. Record repo/ref/Git OID, source pins,
publication/signature/result inventory digests, policy, build/deployment/run,
every path/hash/status and probe region/start/end. Sign chained observations with
sequence, previous digest and explicit outage/missing windows.

Proposed reviewed cadence: every 15 minutes, with bounded probe duration and a
maximum 30-minute unobserved interval; any exceeded interval or mismatched member
invalidates coverage and restarts the credited contiguous dwell window. These are
**proposed policy values**, not existing guarantees. Cadence is sampled coverage,
not continuous global availability. Policy reviewers must approve the coverage
model before it becomes production test authority. Canonical risk dwell stays
7 days for normal/desktop, 14 for critical-system. Any canonical fast-track still
needs its exact reason/approval and every signing/test requirement; it cannot
invent historical availability or bypass missing required evidence.

## First Stable decision bundle

A named release operator and independent reviewer must sign one explicit choice:
import a located, verified previous Stable with its exact original tree/history,
or authorize first Stable genesis with a documented bounded-absence finding and
remaining unknown history. Genesis supplies an initial lineage decision; it does
not waive candidate dwell or production gates.

The closed genesis record binds repository ID/node, source repository/tag/commit/
release/run/artifact and acceptance provenance, canonical policy/registry digests,
all external public roots, exact storage base, complete history inventory and
coverage/gap report, availability receipts, selected+retained result and tests,
genesis rationale, prior Stable null **by explicit decision**, named issuer/operator/
reviewer, run/attempt, nonce and bounded issue/expiry. Sign the final result-bound
publication approval separately as in [API contract](PRODUCTION-API-CONTRACT.md).
Atomically consume genesis once in an empty, independently witnessed production
ledger. Concurrent genesis, nonempty ledger, changed base/history/result or a newly
discovered previous Stable rejects initialization and requires renewed review.

Read-only evidence collection and observer code/tests can be developed without live
activation. Provisioning production witness identity, running an authoritative
monitor, assigning genesis approvers and issuing genesis require explicit operator
authority. D-0 creates no monitor, signatures, backdated records or genesis object.
