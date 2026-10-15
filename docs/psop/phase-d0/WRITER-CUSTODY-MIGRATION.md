# Writer custody migration design

G-02 BLOCKED; G-03 UNVERIFIED; G-10 UNVERIFIED. **No writer was moved, stopped,
modified or dispatched.** Paths below are under `.github/workflows/` at pinned
main. Every listed storage writer targets `Project-Ro-ASD/Ro-Repo`,
`refs/heads/pages-storage`; source checkout follows the dispatched workflow ref.

## Actual writer inventory

| Writer / workflow | Trigger and writable paths | Credential / environment / concurrency | Git, retry and rollback behavior |
| --- | --- | --- | --- |
| Snapshot `publish-pages-snapshot.yml` | `workflow_dispatch(candidate_run,snapshot_id)`; `.nojekyll`, `snapshots/fedora/44/<id>` | Workflow `contents:write`, `actions:read`, `github.token`/checkout persisted credential; no environment; `ro-repo-pages-storage`, cancel false | Stage immutable bytes; no-op if identical; ordinary non-force push; no durable provider intent/explicit expected-head API, no retry/rebase loop |
| Beta `publish-remote-beta.yml` | `workflow_dispatch(snapshot_id)`; `rpm/fedora/44/beta`, `publications/fedora/44/beta/<run>` | Signing job read-only + `repo-production-signing`; metadata subkey/passphrase names below. Publish job `contents:write`, `actions:read`, persisted checkout token, `repo-beta`; `ro-repo-remote-beta`, cancel false | Signature artifact then reverify/stage/copy; no-op identical; normal non-force push; HTTPS retries are observations, not mutation retries; rollback is separate workflow |
| Beta rollback `rollback-remote-beta.yml` | `workflow_dispatch(target_publication_run,reason)`; Beta view + `rollbacks/fedora/44/beta/<run>.json` | Job `contents:write`, persisted checkout token, `repo-beta`; same Beta concurrency group | Verify old signed publication, restore byte-identical view without re-signing, append rollback record, non-force push; no durable UNKNOWN protocol |
| V2 Stable `promote-remote-stable.yml` | `workflow_dispatch(snapshot_id,validation_run)`; Stable view/history, `evidence/promotions`, `promotions/fedora/44` | Read-only validation/signing; metadata role in `repo-production-signing`; writer `contents:write`, `actions:read`, persisted token in `repo-stable`; `ro-repo-remote-stable`, cancel false | Rebind Beta/evidence; sign publication only; reuse RPM/repodata; append evidence; normal non-force push; no shared durable admission with Beta/snapshot |
| PSOP test gateway | Python tests only; local `storage.git`, `refs/heads/isolated-storage` | No GitHub writer credential; test SQLite realm and local epoch/flock | Exact local CAS, durable UNKNOWN and synthetic drain; cannot mutate production |
| Strict V3 | `v3-stable-promotion-disabled.yml` and guarded entrypoints | Disabled/deny boundary | Locked; no D-0 authority to enable |
| Other App/PAT/manual writer | Not fully enumerable through current API access | UNVERIFIED custodian, scope, ref and bypass | Unknown capability must block exclusivity acceptance |

Only secret **names** were inspected in code:
`RO_REPO_METADATA_SIGNING_SUBKEY_B64`, `RO_REPO_METADATA_SIGNING_PASSPHRASE`
(candidate/Beta/Stable signing), `RO_REPO_RPM_SIGNING_SUBKEY_B64`,
`RO_REPO_RPM_SIGNING_PASSPHRASE` (`accept-component.yml`). Candidate/acceptance
signers are upstream custody dependencies, not additional direct storage pushers.
All workflow files were searched for push/write/environment/secret references.
Secret values, host credential files and private production keys were not read.

## Races and preservation

Beta publish and rollback share a concurrency group, but snapshot and V2 Stable
use different groups. This is not branch-wide exclusion. Ordinary non-force Git
push rejects a diverged ref in many races; it does not bind independent approval,
whole-tree preservation, provider response-loss recovery or old queue age.
Environment approval can release an old workflow against a newer checkout/base;
there is no shared durable nonce/deadline/request-drain protocol today.

Beta equivalence requires exact RPM, repodata, manifest/signature, history and
rollback bytes and paths from V2 staging semantics, including no-op behavior.
Publication/run identities remain explicitly mapped; new transport audit records
are additional immutable records, not rewritten signed V2 history. Compare full
trees with only the operation's declared mutable channel view allowed to change.
Validate snapshot/SRPM/noarch copies and unrelated Stable/Beta preservation.

## Future authorized transition, stop at any unmet prerequisite

1. **Inventory:** operator names every workflow, repository/org App installation,
   PAT/fine-grained token, deploy key, manual account and runner retaining access;
   retain IDs/scopes/custodians/expiry and policy bypass records, never token values.
   Enumerate all queued, waiting, pending, requested, running and rerun-capable old
   jobs and external service requests. Current empty queue GETs are only a sample.
2. **Rehearse:** separate disposable realm executes snapshot, Beta, rollback and
   Stable semantics, no-op, overlapping requests, stale approval, lost response,
   crashes and restore. Obtain Beta operator R-04 acceptance: an UNKNOWN Stable
   request blocks **all** shared-realm successors, including urgent Beta rollback.
3. **Freeze ingress in an explicitly authorized window:** capture storage base,
   full inventories and independent checkpoint; prevent new old-path admission.
   Disabling a workflow alone does not revoke existing job tokens or submitted
   provider requests. Do not enable gateway writes during this interval.
4. **Revoke and prove:** record old token/install/deploy-key revocation or scoped
   permission removal, runner credential disposal and all affected request IDs.
   Independently establish completion or provider-supported drain of each request.
   A cancelled job, revoked credential, elapsed timeout or unchanged HEAD is not
   proof an already accepted request cannot later mutate the ref. If no decisive
   proof is available, remain BLOCKED; do not invent a GitHub drain certificate.
5. **Establish exclusive custody:** only a dedicated gateway process holds the
   restricted writer capability. Workers/signers cannot retrieve it; direct
   workflow tokens must lack an alternative storage-write path. Repository-wide
   token scopes alone cannot confine a token to a branch; enforce server policy
   and service ingress, with negative tests for each old path. Import exact base
   and pending ledger/checkpoint once under independent review.
6. **Enable adapters only after closure:** all five operation kinds enter the
   same durable realm; revalidate base/approval/expiry at dequeue/admission. Reject
   old queued requests, do not transparently rebase them. Operator compares before
   and after inventories and provider observations; exact canary requires separate
   activation authority and all gates, absent in D-0.

## Provider mutation and incident boundary

Object preparation is not ref mutation; still requires separately scoped future
permission. Before any ref request persist exact repo ID/node/ref, expected OID,
complete target tree/commit recipe, hashes, approval/nonce, lease and request time.
Use exact expected-head semantics, never blind PATCH/force/rebase. See
[API contract](PRODUCTION-API-CONTRACT.md) for GitHub protocol constraints.

Lost response or unexplained HEAD => durable UNKNOWN. Read-only reconciliation
may confirm the exact target and every blob plus independently recorded intent.
Expiration after commit records COMMITTED_EXPIRED and cannot mint client authority.
Unexpected descendant is not automatically success; require preserved target
ancestry/tree and accounted successor intents. Unexpected mutation is an incident.
Noncommit needs actual fencing/drain bound to that intent/checkpoint. Absent that,
leave realm blocked indefinitely and escalate; separate-origin redesign requires
a new ADR and new authorization.

Recovery never restores old direct credentials as an automatic fallback. An
aborted pre-mutation migration may resume old service only after a reviewed proof
no new request can escape; any custody uncertainty preserves the freeze. Post-write
failure retains immutable data and outbox/UNKNOWN, with fresh reviewed repair
authority. No force push or ledger reinitialization. Acceptance records must
include named operator and independent reviewer, times, exact heads, revoked
capability IDs, request coverage, Beta equivalence digests and recovery drill.
