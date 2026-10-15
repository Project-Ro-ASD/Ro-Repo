# PSOP operator runbook

This is a preparation/incident contract, **not production execution authority**.
PR-C runs only the disposable test profile. Its domains, local-only gateway and
`publishable=false` artifacts must not be renamed into production authority.
Live custody/settings/signing/client rollout need a separately reviewed operator
stage and explicit authorization for an exact deployment. The normative
[15 MSC rules](MINIMUM-SECURITY-CONTRACT.md), [14 gates](ACTIVATION-GATES.md) and
[nine risks](RISK-ACCEPTANCE.md) remain unchanged.

## Prepare a generation

1. Capture exact main/storage commit, registry/policy digest, external public-role
   pins, full signed Beta/history and the prior verified Stable result. Preserve
   original signed legacy bytes. API/Git timestamps are observations, not trusted
   first availability. Missing coverage/dwell or unsigned required-test evidence
   blocks production preparation authority.
2. For first production Stable, review reachable and potentially deleted history,
   known workflow/publication evidence and any previous Stable import. Require
   an explicit, independently reviewed genesis approval bound to source, history,
   storage base, evidence and policy. A 404 or bounded negative history scan alone
   cannot initialize a production ledger.
3. Use canonical group/risk policy and the selected + retained full set. Verify
   external RPM roles, headers, SRPM linkage/noarch parity and exact bytes. Run
   risk-required native/runtime tests and full-set DNF against independently
   pinned upstream. PR-C's synthetic package success and observed Fedora base
   cannot attest actual application/GUI/boot or production test authority.
4. Review exact source/base/genesis/result/evidence/policy/actor/run/attempt and
   expiry/nonce. Only a fresh authenticated PSOP approval may authorize work.
   Generate deterministic unsigned metadata, then sign only exact metadata with
   the isolated signing subkey; do not rebuild/re-sign existing RPMs. Verify all
   final bytes/signatures and retain the review bundle and hashes.
5. Admit atomically through the sole reviewed writer realm, persist the exact
   base/target intent before I/O, and reconcile exact Git outcomes. Git completion
   is not public success. Independently bind Pages build/deployment/run/commit
   and verify every public signed member, then issue bounded client authority.
   An expired approval or COMMITTED_EXPIRED outcome cannot issue a descriptor.

Current `issue_descriptor` requires the exact current COMPLETE PR-B result,
receipt and unexpired approval, plus contiguous signed descriptor lineage. It
does not implement a long-running production descriptor renewal service. Fresh
authority after expiry requires a separately reviewed protocol; old approval
reuse or changing expiry timestamps is forbidden.

## Writer custody and V2 transition

The real snapshot/Beta/rollback/V2 Stable writers **still push directly** and have
not joined the simulated PSOP realm. No new PSOP production credential may be
added beside them. Operator prerequisites:

- Inventory every workflow, App, PAT, manual writer, queued/old run and storage
  ref; name its custodian without disclosing token/secret values.
- Agree a separately authorized transition window, capture exact prior trees,
  demonstrate Beta publish/rollback/history byte equivalence and failure effects,
  and obtain independent acceptance of R-04's shared-realm outage impact.
- Establish exclusive gateway custody and actual old-request drain/fence evidence
  before enabling any new writer. Concurrency group names or seeing the base HEAD
  do not prove this. Unresolved requests keep the realm blocked.
- Retire old capabilities and verify sole-writer ingress only during that separate
  authorized stage. No PR-C code dispatches, disables or changes these workflows.

## UNKNOWN / provider incidents

Freeze successor admission, retain the original ledger/checkpoint, request times,
approval and exact base/target/tree. Do not delete/reinitialize the ledger, reuse
a nonce, force push, blind retry/rebase or clear UNKNOWN on timeout/cancellation.
After restart, verify the independently retained checkpoint and every target
member. Exact committed target permits reconciliation; expiry is recorded and
cannot advance new authority. An unexpected HEAD is an incident, not a new base.

Noncommit requires independently established fencing/drain and an exact binding
to the unresolved intent/checkpoint. PR-B's local flock/epoch proof works only in
its local transport. It proves no GitHub request drain or provider deadline fence.
Without an equivalent real provider proof, retain UNKNOWN and escalate custody.
Production backup/restore needs an independent monotonic witness, replay-table
and pending-intent restoration, split-brain exclusion and a reviewed recovery
drill; local process restart is not a whole-database rollback defense.

## Pages/CDN and client failure

Do not certify publication from API success, one repomd file or one CDN probe.
The read-only verifier brackets full byte/signature checks with exact provider
identities, but only observes one place/time. Late old builds, missing/mixed
members and global latest remain provider limitations. Withhold new descriptor
authority on an integrity failure; never route clients to mutable `/stable` or an
unsigned fallback. Old immutable paths remain preserved.

Clients first acquire and verify every immutable HTTPS byte, pinned public role,
GPG/RPM signature, result/receipt and generation binding. DNF uses a separate
frozen local transaction repository so it cannot refetch a different CDN view.
The active repo retains the immutable HTTPS URL and all four verification flags.
`active.json` atomically selects repo + state; `pending.json` records exact
descriptor/operation/packages before transaction I/O.

- Verification/preparation failure: active repo/state remains unchanged; no DNF
  starts and no fallback occurs. Unselected preparation slots grant no authority.
- DNF failure/process death: retain the pending intent and previous active state.
  Inspect the actual private RPMDB/logs; RPM transactions are not globally atomic
  with the client pointer and may have partial effects. Only explicit same-view,
  same-operation/package resume is allowed while authority remains valid. A
  completed active-pointer commit can clear its exact leftover journal without
  re-running DNF. Installed NEVRA must equal the verified target before success.
- Expired pending authority: retain the block. This milestone has no production
  fresh-authority/repair service; do not delete the journal or roll the RPMDB back
  automatically. New reviewed authority and an exact repair protocol are required.

New clients can accept a valid older descriptor because no independent latest
discovery service exists. Known clients enforce contiguous previous-generation /
result binding and reject replay or rollback. This is local monotonicity, not
global freshness.

## Authorized rollback, keys, policy and canary

Rollback is BLOCKED until a separately specified downgrade policy exists. It must
be a new higher generation, exact old package/result set, fresh independent
approval, tested DNF downgrade/recovery and append-only history. Do not reset Git
HEAD, decrement local generation or reuse the old descriptor. The current client
rejects package downgrades even with a higher generation.

Production admission requires independent named reviewers, main-only deployment
policy, required checks, branch/ruleset/bypass and self-review controls and an
exact approval actor/issuer/run binding. Historical settings observations are not
fresh acceptance. PR-C changes none of these settings.

Keep production primary keys offline; only isolated role subkeys may enter the
reviewed signing service. Prove custodian separation, backup/restore, revocation
and rotation without exposing secret material. Rotation needs independently
distributed public-root pins, tested overlap/revocation behavior and preserved
historical verification; an embedded new key is never automatic trust.

Only after **every gate**, named risk acceptances and a separate explicit live
activation instruction, define an exact canary cohort/result/origin/expiry and
observer coverage. Require zero cryptographic/inventory/lineage failures, correct
installed NEVRAs and reviewed application/runtime checks. On failure withhold new
authority and escalate; reversal follows the separately authorized rollback
policy, not automatic downgrade or fallback. Strict V3 remains locked regardless.

## External disposable Pages checklist

No external PSOP test target is authorized in this conversation. No repository
creation, remote push or Pages enablement is performed. Before a future external
observation, a human must explicitly authorize and supply:

- A physically separate `owner/ro-psop-disposable-*` repository, numeric ID,
  node ID and `psop-disposable-*` source branch; no production ref or origin.
- Exact `https://owner.github.io/repository` origin, a repository description of
  `RO PSOP DISPOSABLE ACCEPTANCE ONLY`, existing legacy branch Pages source `/`,
  and exact Git commit/build/deployment/run identities.
- Public descriptor/publication/RPM/metadata pins provisioned independently from
  the HTTPS payload, named operator, bounded read authorization and purpose
  `read-only-psop-disposable-acceptance`.
- Read-only public/API access (anonymous where supported, otherwise a scoped
  contents-read credential). The verifier exposes only an exact GET allowlist;
  it cannot create a repository, change Pages, dispatch or push, even with this
  inventory. Any setup/publication needs separate explicit authorization.

`tests/psop-pages-disposable-acceptance.py --mode external` without that inventory
emits BLOCKED and performs zero requests. With explicit authorization it verifies
exact repository identity/branch/Pages facts through reused V3 adapters, every
signed HTTPS member and equality to the exact Git tree, then rechecks identities.
This still cannot prove provider ordering/deadline/global CDN freshness. A local
HTTPS PASS must never be relabeled external Pages acceptance.
