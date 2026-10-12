# V2 → V3 stable writer migration

Activation: **BLOCKED**. Beta behavior and all current V2 workflows are unchanged.
The legacy stable workflow can publish the complete beta snapshot; its separate
`ro-repo-remote-stable` concurrency group does not serialize a future independent
V3 stable writer. Both writers must not operate independently on stable.

## Rehearsal provided by this PR

`v3_migration.rehearse` freezes a supplied signed V2 snapshot, authenticates
snapshot/repodata/RPM/SRPM bytes with independently pinned public keys, evaluates
every present canonical producer group and architecture, and emits a proposal
with complete inventory, immutable storage commit, registry and RPM preflight
digests. Missing arches/subpackages/source closure produce FAIL, not a silently
repaired package set. Malformed, unregistered or unverifiable inputs fail closed.

The proposal preserves all package identities and signed bytes.
`assert_preserved` rejects any silent group replacement. Fixture acceptance is
PASS; live V2 inventory, authenticated historical publication provenance and
protected import remain UNVERIFIED. No live snapshot was fetched and adopted.

`retirement_patch` produces an unapplied diff adding unconditional false to all
four jobs of `.github/workflows/promote-remote-stable.yml`. The function rejects
unexpected YAML/job shapes. This is a review artifact; it does not edit a workflow.
`writer_gate` always returns BLOCKED in this milestone, including when a proposed
future writer configuration appears internally consistent.

## Future ordered cutover

1. Independently capture the exact Pages storage commit, signed current V2 stable
   publication, full immutable snapshot and historical references. Verify RPM,
   metadata and provenance keys against operator pins and authenticate the existing
   history. Preserve copies, immutable references and independent checkpoints.
2. Rehearse the canonical inventory assessment using the production registry.
   Resolve absent x86_64/aarch64/noarch/SRPM closure through explicitly approved
   package work. Do not import a different whole beta snapshot to fill gaps.
3. Prove full baseline-to-versioned-view dependency/config/application acceptance
   and obtain a fresh exact signed protected **import** authorization. A live
   ledger adoption/import path is not supplied by this PR; implement and review it
   with authenticated legacy state and checkpoint seeding before cutover.
4. Provision shared durable authority, replay ledger, audit checkpoints, outbox,
   Git CAS and deployment witnesses. All stable promotion and recovery actors must
   use one serialization boundary. Verify external failure/recovery behavior.
5. Prepare immutable-client `.repo` changes and an explicit client rollback plan
   in the appropriate repository through separate maintainer review. This task
   did not change Ro-ASD or producer repositories. Verify beta remains compatible.
6. Stage and independently verify the proposed immutable stable view and signed
   publication records. Nothing should advertise it to live stable yet.
7. **Last safe rollback point:** before retiring the V2 stable writer and before
   advertising V3 or migrating any live client. The current verified V2 publication
   and client configuration still form the active rollback baseline. Record that
   digest/configuration and prove recoverability before proceeding.
8. In a separately approved cutover PR, apply/review the legacy stable retirement
   patch and any other stable-writer restrictions. Wait for all in-flight V2 stable
   jobs to finish; do not cancel halfway through an unaudited publication. Verify
   that no legacy stable workflow, manual credential or rollback actor can write
   outside the common authority. Keep production beta behavior unchanged.
9. Perform the protected import under shared CAS; verify current base, replay,
   immutable history and independent checkpoints. Only after successful import
   and real activation acceptance may a separate approved activation change wire
   the eleven V3 jobs and reviewed production adapters.
10. Advertise the exact immutable view and migrate clients through the approved
    procedure. Independently verify every view path, signed advertisement,
    deployment identity and applicable client behavior. Pages/CDN success cannot
    be inferred from a Git commit or green Actions status.
11. On any failure, preserve the journal and historical views. Reconcile the exact
    external deployment/advertisement state. Recover only to previously verified
    immutable history with fresh protected authorization bound to the **current**
    state. Do not re-enable an independent V2 whole-beta writer after V3 activation.
    Never delete history or label a local pointer change successful rollback.

After step 8, returning to V2 is a new reviewed writer/client migration rather
than simply toggling a job. After client cutover, mutable V2 URLs and V3 versioned
URLs may have different observers/cache state; recovery acceptance must check the
actual affected clients and deployed view. These conditions remain BLOCKED until
real external evidence exists.
