# Proposed production API and state contract

**Unimplemented; production activation BLOCKED.** Names here are future module
contracts, not callable routes. Keep existing PR-A/B/C and Strict V3 guards intact.
Reject every test context, synthetic issuer and `publishable=false` object at the
production boundary. A new domain is necessary but never sufficient for authority.

## Production types and role separation

All schemas are closed, versioned, canonical JSON with strict integer/time/path
rules, explicit purpose and SHA256 digests. Configuration pins repo numeric/node
identity, source commit, storage ref/base, policy/registry version+digest, external
RPM/metadata/approval/publication/witness roots and deployment origin. Mutable
branches, `latest`, unrecognized fields and caller-selected credential/ref/origin
are rejected. Exact digest encoding and excluded signature fields require schema
review and canonical test vectors before implementation.

Proposed workload identity: verified GitHub OIDC issuer
`https://token.actions.githubusercontent.com`, service-specific audience, exact
repository/owner IDs, workflow ref and workflow SHA, source/ref, environment,
actor ID, run ID and run attempt. Validate issuer signature, audience, subject,
time and nonce against independent policy; do not accept caller-supplied claims.
OIDC proves a workload identity, not independent human approval. An approval
broker must verify a protected-environment approval event for that exact run/job,
resolve named reviewer ID and enforce reviewer != initiator/pusher/candidate
author under the reviewed separation policy. Missing event, self-approval,
unverifiable role membership or substituted run fails closed.

Keep offline primary keys out of CI. RPM signer, metadata signer, approval broker,
gateway, deployment observer and backup witness have separate service identities
and capabilities. Signer API accepts only a verified exact signing request and
exact role fingerprint/subkey (`FINGERPRINT!`); never arbitrary paths or bytes.
Production private custody evidence must attest isolated subkeys, custodian and
reviewer separation, access audit, encrypted backup restore, revocation/rotation
drill and primary-key exclusion without disclosing secrets. Role overlap by the
same human must be addressed by actual independent approval, not two role names.

## Exact binding without circular digests

1. `prepare_candidate(pins, source_proofs, history, runtime_evidence)` returns an
   immutable unsigned review bundle. Include selected+retained package inventory,
   header NEVRA/SRPM/noarch checks, provenance, policy/dwell, genesis or previous
   Stable, exact metadata bytes, expected storage base and evidence digests.
2. `authorize_sign(review_digest, workload_identity, human_event, nonce, expiry)`
   returns a signing-purpose authorization. It authorizes only those metadata
   bytes and role subkey; no storage write. Existing RPMs are never re-signed.
3. `sign_metadata(sign_authorization, exact_bytes)` returns signed inventory and
   complete result digest, with independently verified signatures. Detached
   signatures are part of final inventory. A signer response cannot authorize
   publication by itself.
4. `authorize_publish(final_review, human_event)` binds the **final signed** result
   inventory/tree, signing authorization digest, exact policy/source/evidence,
   previous Stable or genesis, expected Git base, target commit recipe, writer,
   workflow/run/attempt, named reviewer/actor, issue/expiry and fresh nonce.
   Signed bytes must be available to the reviewer. A changed signature/tree/base
   requires a fresh authorization. Never sign away a mismatch after approval.
5. `admit(publication_authorization, prepared_target)` atomically consumes the
   nonce and appends outbox+intent under the storage-wide lock. The authorized
   target's immutable payload must not embed its own authorization/receipt digest
   recursively. Store authorization and postcommit receipts in independent audit
   storage; bind their subject to the already computed target. Subsequent audit
   anchoring to Git is a separately authorized intent if desired.

Every endpoint is idempotent only for the same complete request digest. Same nonce
with different bytes is a replay error. Expiry checked at issuance, dequeue,
admission and client-authority issuance; local admission expiry is not a promise
that GitHub will reject a delayed accepted mutation.

## Durable ledger / outbox service

Proposed `psop_prod_ledger` reuses reviewed transaction semantics after a distinct
production adapter review; do not merely point the test SQLite context at GitHub.
A PostgreSQL-backed service is a candidate, not accepted infrastructure. Its
transaction atomically joins nonce consumption, previous generation/result,
storage expected HEAD, intent, outbox and signed audit sequence. Enforce a unique
realm and one nonterminal provider intent, serializable admission or equivalent
database constraints, and fenced worker leases. Workers have no writer token.

| Durable state | Allowed transition / evidence |
| --- | --- |
| PREPARED | Exact signed bytes verified; no provider request |
| ADMITTED | Nonce + outbox committed together; approval still valid |
| IN_FLIGHT | Exact request recipe/expected/target recorded before I/O |
| UNKNOWN | Response loss, process death or ambiguous provider result; realm-wide successor exclusion |
| GIT_COMMITTED | Exact target/parent/full bytes reconciled; not public success |
| COMMITTED_EXPIRED | Commit observed after authority expiry; no new client authority |
| PUBLIC_VERIFIED | Exact provider identity and full public inventory observed while authority valid |
| COMPLETE | Independent receipt/checkpoint and bounded client authority issued atomically/idempotently |
| ABORTED_NONCOMMIT | Only independently proven actual noncommit plus all old requests fenced/drained |

Retain admitted/requested/observed times, actor/attempt, before/target OIDs,
approval/result/evidence digests and every failure/UNKNOWN. No success-only log.
Read-only recovery cannot erase consumed nonces or pending intents.

Encrypted backups include database/WAL, replay table, outbox, audit chain, immutable
result objects and public configuration pins; private signing keys use a separate
custodian backup. Independently durable monotonic witness stores sequence,
checkpoint and pending-intent digests outside the database administrator's rollback
domain. Restore starts QUARANTINED, validates backup against that witness and all
provider outcomes, and never initializes over existing storage. Missing witness
or stale backup blocks admission. Fence old gateway instances and credentials
before failover; a DB lease alone cannot fence an already submitted GitHub request.
Test whole-DB rollback, replay after restore, two active regions, stale worker,
lost witness, unavailable database and loss during each transaction boundary.

## Real GitHub CAS and Pages boundary

REST [update reference](https://docs.github.com/en/rest/git/refs) with `force=false`
is non-force but has no explicit old-OID parameter. It alone is not the exact
expected-head API. Existing `v3_github_provider.py:GitHubStorage._cas` models
GraphQL `updateRefs` with `RefUpdate.beforeOid`, `afterOid` and `force=false`,
behind a live-mutation deny. A production adapter must validate actual protocol
limits and remain separate from that guard.

Preferred contract: prepare the exact child commit and complete tree before
publication approval, then atomically update the fixed ref with exact before/after
OIDs and no force. Git receive-pack with an exact old OID is another candidate;
its wrapper must preserve non-force ancestry and expected-head semantics. Rehearse
real inventory sizes, API/object upload limits and response-loss behavior on the
separately authorized disposable target. No REST read-then-unconditional-write
substitution. The server may apply a previously admitted CAS after local expiry;
neither candidate protocol supplies deadline fencing. GraphQL schema/permission
compatibility must be revalidated before implementation; model success alone is
not real provider acceptance.

The sole gateway fixes the repository/ref, verifies full old-tree preservation
and performs at most the admitted mutation. On response loss reconcile reads;
never resubmit a CAS whose outcome is unknown. Real GitHub noncommit drain remains
unproven, so UNKNOWN may require an indefinite operational pause.

Proposed `psop_prod_pages.observe(target, build, deployment, run, inventory)`
joins exact repository/ref/commit/build/deployment/status/run and independently
fetches descriptor/publication and **all** signed metadata/RPM/SRPM/key members
over HTTPS; verify signatures and SHA256 against exact Git bytes, with identity
checks before and after. Persist time/region/coverage and immutable observation
receipt. A successful API deployment is not public-byte success.

Only GIT_COMMITTED + unexpired exact approval + PUBLIC_VERIFIED + durable clean
ledger + every gate/activation authority permits new client authority. Any byte,
identity or root mismatch withholds it. An expired result needs fresh renewal
authority and reobservation, not edited timestamps. Existing immutable generations
remain retained. GitHub deadline fencing, Pages ordering and global CDN freshness
are **not supplied**; client local monotonicity and R-01..R-04 dispositions cannot
be relabeled those guarantees.
