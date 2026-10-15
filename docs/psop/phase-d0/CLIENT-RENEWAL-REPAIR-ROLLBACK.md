# Proposed client renewal, repair and rollback contract

G-12 **UNVERIFIED**. Existing `psop_client.py` is disposable/test-only and unchanged.
It verifies bounded descriptors, exact receipt/result/publication and all signed
bytes, uses frozen DNF inputs, atomically selects `active.json`, and journals exact
operation/packages in `pending.json`. It rejects known lineage regression and
package downgrades. Same-view resume needs valid authority; expired pending has no
fresh-authority protocol. RPMDB effects and pointer commit are not one transaction.

## Proposed durable client state machine

| State | Input / allowed next state |
| --- | --- |
| UNINITIALIZED | Independently installed roots + authorized bootstrap/checkpoint; valid bounded descriptor -> VERIFIED. Without latest witness, explicitly report latest UNVERIFIED |
| ACTIVE(g,result) | Fresh contiguous successor -> VERIFIED; same result renewal -> ACTIVE with higher authority serial, no RPM transaction or generation decrease |
| VERIFIED | Full HTTPS/signature/inventory/lineage/preparation success -> PREPARED; any failure keeps prior ACTIVE and starts no DNF |
| PREPARED | Persist exact operation, descriptor/authority serial, packages and RPMDB-before fingerprint -> PENDING before transaction I/O |
| PENDING | Crash/DNF failure -> RECONCILING; block all other changes and fallback |
| RECONCILING | Read actual RPMDB + durable DNF history/log; exact completed target -> commit ACTIVE; exact safely resumable state + valid same-operation authority -> PENDING; ambiguity -> REPAIR_REQUIRED |
| EXPIRED_PENDING | Never delete journal or reuse expired token; fresh exact repair capability -> RECONCILING |
| REPAIR_REQUIRED | Explicit fresh reviewed repair plan with exact preconditions; otherwise stay blocked |
| ACTIVE(new generation) | Clear only the exact completed leftover pending record idempotently; do not run DNF twice |

State, generation/result high-watermark, authority serial and operation journal use
atomic durable updates under a client lock. A crash after pointer commit recognizes
its operation ID and only clears matching journal. Unexpected installed packages,
scriptlet failure, history loss or unprovable completion cannot be labeled success.
Do not infer safe replay from package NEVRA alone: reconcile transaction effects
and application-specific repair requirements. Host disk rollback/tampering needs a
separately provisioned monotonic witness; local files alone do not prevent it.

## Proposed APIs and exact fields

| API | Required binding / authority |
| --- | --- |
| `renew_descriptor` | Exact existing generation/result/inventory, previous descriptor digest, higher authority serial, trust/policy versions, fresh nonce/expiry, clean ledger, recent complete Pages reobservation and independently authenticated renewal purpose |
| `authorize_pending_repair` | Client/cohort identity, pending operation+descriptor digest, local generation/result/serial, actual RPMDB and DNF log fingerprints, exact target, allowed package actions and scriptlet/recovery policy, fresh independent approval and expiry |
| `resume_operation` | Same operation/result/packages and authorized preconditions; verify RPMDB and remaining actions again under lock; idempotent completion receipt |
| `authorize_rollback` | Higher generation + previous current result, exact older package bytes/NEVRAs, explicit downgrade/removal set, reason, risk tests, source/policy/evidence, independent approval and new nonce |
| `rotate_trust` | Root-set version/high-watermark, old/new role fingerprints, overlap validity, revocations and independently authenticated distribution proof |

Renewal extends authority for identical content only; it does not refresh original
publication age, create a new package generation, hide a superseding result or
inherit an expired approval. The issuing service checks current policy and
revocation state. A renewal request cannot switch result. Superseded content needs
explicit bounded old-view/repair authority, not a claim it is newest. Lost clients
obtain a fresh bootstrap/checkpoint through an independent trust channel.

First clients may see an old but valid signed descriptor. Until an independent
freshness service/checkpoint is deployed, expose `global_latest=UNVERIFIED` and
bound validity; never assert latest from signature validity. Known clients require
contiguous previous-generation/result linkage (or a separately reviewed signed
checkpoint/chain import), reject lower generation/state/trust-root versions, and
do not permit root-store reinstall to silently reset the high-watermark.

Rollback is a **new** append-only generation; old Git/history/client state never
rewinds. An old result's package bytes may be reused only under explicit downgrade
authority after full selected+retained dependency/file-conflict/scriptlet/runtime
and recovery tests. Do not use generic `--allowerasing`, arbitrary DNF flags or a
replayed old descriptor as repair. Require exact permitted transaction delta and
installed outcome. A higher generation alone is insufficient downgrade permission.

Preinstalled trust root updates come through an independently authenticated OS/
keyring distribution channel, with reviewed overlap and revocation. New roots
inside signed payload alone do not grant trust. Preserve historical verification
while enforcing current revocation for new authority. Compromise of an old root
requires independently trusted recovery, not merely a cross-signature by that root.

## Negative acceptance and future PRs

Renewal PR D5a: reject changed result, stale serial, wrong client/purpose/domain,
replayed nonce, stale Pages witness, revoked issuer/root, expired original token
reuse and lower trust version. Verify valid renewal starts zero package actions.

Repair PR D5b: kill before/after journal, DNF, RPMDB change and pointer commit;
test complete, unchanged, partial and divergent RPMDB, missing logs, duplicate
resume, expired pending, mismatched repair token, concurrent process and power-loss
restore. Verify zero blind reinstall/downgrade/fallback and exact installed NEVRA.

Rollback/trust PR D5c: reject old generation, absent downgrade authority, mismatched
package set, arbitrary flags, unsigned RPM, wrong metadata role and embedded-only
new key. Test dependency/scriptlet failures, new-generation downgrade recovery,
key overlap, revocation, offline expiry and client backup rollback. Use real DNF5
in disposable roots/VMs; production installation/rollout requires later explicit
operator authority and a bounded canary. No D-0 client behavior changes.
