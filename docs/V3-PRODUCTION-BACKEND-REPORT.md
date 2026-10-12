# V3 production backend engineering report

Production activation: **BLOCKED**. This is a NON-PRODUCTION backend integration
milestone. Executable writers use private disposable test storage. There is no
live push, Pages deployment, production signing, migration or rollback entry point.

Baseline: PR #71, merged as `fc18d9b3d5cb861358a30bed22b0337c78743741`.
Branch: `feature/v3-production-backend-complete`. The baseline's 377 unit tests
and all eleven unconditional production job disables are preserved. Existing
V2 workflow definitions are byte-identical to main.

## Implemented contracts and their limits

| Subsystem | Isolated acceptance | External acceptance / remaining requirement |
| --- | --- | --- |
| `v3_backend_trust.verify_oidc` | PASS: real RSA signatures, pinned JWKS, issuer, audience, lifetime, duplicate/header/claim rejection | UNVERIFIED: actual protected GitHub workload, provisioned subjects, pinned workflow SHAs, JWKS rotation/revocation |
| `v3_backend_evidence.verify_evidence` | PASS: authenticated source, full candidate/policy, first-seen, claim/log hashes, selected and retained group test floors | UNVERIFIED: independent producer attestations and complete authenticated beta observer history |
| `verify_protected` | PASS: separate canonical approval/witness keys, exact request and evidence, reviewer separation, expiry, workload/run binding | BLOCKED: independently operated protected-environment witness and real exact-result human approval |
| `v3_backend_ledger.Ledger` | PASS: signed audit events, state digests, transactional consumption, CAS, idempotence, process death, corrupt head/schema rejection | UNVERIFIED: externally hosted durability, TLS, HA, restore, audit key custody and monotonic checkpoint service |
| `PostgreSQLAdapter` | PASS: real PostgreSQL 18.6, two independent writer processes and interrupted transactions | BLOCKED: production connection is explicitly rejected; deployment configuration requires a separate PR |
| `v3_publication_backend.Backend` | PASS: all eleven states, illegal skips, stage interruption, stale bases, fresh protected recovery | BLOCKED: live orchestration, distributed deployment reconciliation and activation |
| `v3_immutable_view.verify_result` | PASS: actual signed RPM/SRPM, signed repodata, canonical recomputed composition and exact approved baseline/result trees | UNVERIFIED: actual released producer inputs under independently supplied production roots |
| `IsolatedStore`, `verify_remote` | PASS: immutable freezing, external signed publication envelope, complete byte checks, signed stable advertisement, pre/post separation | UNVERIFIED: independent deployed HTTP verifier, Pages deployment witness and CDN visibility |
| `v3_pages_backend.IsolatedGitStore` | PASS: real Git trees/commits and `update-ref` CAS; immutable history replacement rejection | BLOCKED: live Git/Pages writes; Git CAS does not prove atomic CDN visibility |
| `v3_migration.rehearse` | PASS: signed fixture inventory, canonical closure assessment, exact byte preservation, unapplied writer retirement patch | BLOCKED: authenticated live V2 import, shared writer boundary and client cutover |
| `v3_pinned_upstream.verify_upstream` and extended `v3_full_set_dnf.validate` | PASS: actual signed fixture cache, repomd/primary/RPM checksums and locations, clean/upgrade DNF closure with explicit repos | UNVERIFIED: independently pinned official Fedora 44 feed and complete real application dependencies |
| `v3_real_acceptance.execute` | PASS: negative input/gate tests and no system repository fallback | UNVERIFIED: released Ro-Assist/Control/Installer/Dolphin/release/keyring/repos/defaults package runs |
| `v3_vm_acceptance.run` | PASS: protocol rejection tests; implementation pins/copies disk, executor, firmware and media, disables network/host sharing and records guest logs | UNVERIFIED: actual pinned VM execution, Plasma login, boot/reboot/recovery and Ro-Store GUI; image-specific guest cases are unavailable |

No external approval, application or VM gate is marked PASS from a synthetic
fixture. Application code and capability factories execute in one trusted Python
process. The exported `TOKEN` sentinel guards accidental API misuse; it cannot
isolate malicious imported Python code. No JSON/API deserializer, eval, pickle
or plugin route constructs these capabilities from untrusted data. Untrusted
JSON, API success, actor strings and green CI cannot construct one through the
implemented entry points. Test outputs always contain `publishable=false`; the live publication entry
point `v3_immutable_view.production_publish` always raises BLOCKED.

## Publication protocol

The disabled workflow's future stage contracts map to these implementations;
this PR does not replace its unconditional false guards or wire live credentials.

| Disabled production job | Implemented contract / activation boundary |
| --- | --- |
| proposal | Existing `v3_integration.prepare/prepare_live`, planner and `Backend.create` |
| pinned-beta-evidence | Existing signed archive bridge plus cryptographic source/history envelopes in `verify_evidence` |
| component-policy | Existing registry-derived policy/closure and new authenticated retained-group test floors |
| compose-and-validate | Existing composer/RPM preflight, `verify_result`, pinned upstream and complete-set DNF |
| deterministic-result | Existing deterministic metadata/signed preview; exact resulting tree inventory |
| protected-authorization | `verify_oidc`, `authorization_request`, `verify_protected`, atomic `Backend.authorized` |
| sign-publication | External result-bound publication envelope in `IsolatedStore.stage`; live signing BLOCKED |
| immutable-staging | `IsolatedStore` and `IsolatedGitStore.stage`; live upload/deploy BLOCKED |
| controlled-publication | Ledger digest/generation CAS and isolated Git advertisement; live outbox/lease BLOCKED |
| independent-remote-verification | Complete byte/deployment checks and signed advertisement in `verify_remote` |
| audit-receipt | Independently pinned signed ledger events, state digests and checkpoint verification |

The approved result digest covers the **complete already-signed snapshot tree**.
Stable promotion copies signed RPMs/SRPMs unchanged. Existing metadata generation,
snapshot signature verification and RPM preflight are reused. After approval,
SIGNING signs an external publication envelope; it never changes approved RPM,
repodata or snapshot bytes. This avoids approval/signature digest circularity.

The proposed layout is:

```
v3/views/<result-tree-sha256>/rpm/{x86_64,aarch64,source}/...
v3/publications/<attempt-id>.json
v3/stable.json
```

These are explicitly versioned views of stable, not additional public channels.
Only beta and stable remain public channels. DNF baseurls must name the exact view
digest. A later stable advertisement cannot change an ongoing DNF transaction's
baseurl. RPM and repodata file bytes in a view are immutable; signed publication
records remain attributable to a specific approval, attempt and deployment.

The state sequence is PROPOSED → VERIFIED → COMPOSED → TESTED → AWAITING_APPROVAL
→ AUTHORIZED → SIGNED → STAGED → REMOTE_VERIFIED → PUBLISHED → POST_VERIFIED.
Approval/JTI/witness consumption and audit/state changes commit together. Stable
CAS checks both digest and generation. Another promotion cannot start from an
advertisement that has not been post-verified. Post verification rereads complete
bytes and the signed advertisement, checks the exact staged Git commit, approval
and generation, and validates the authenticated ledger checkpoint.

PUBLISHED means the isolated ledger has committed the advertisement intent; it
does not assert that Pages/CDN visibility succeeded. The isolated Git harness
then advertises and independently rereads the Git tree. Failure between these
providers leaves PUBLISHED or FAILED, preserves last-known-good history and
requires explicit recovery/reconciliation. A live durable outbox/lease and
GitHub deployment reconciliation service are **not implemented** here and are
BLOCKED before activation. Local database restoration is never remote rollback.

Preparation currently uses the existing test-only signed preview. A future live
metadata-preparation signing policy must be independently protected and reviewed;
this PR does not grant production signing authority before human approval. OIDC
and approval expiry are checked at consumption and advertisement. Large deployments
must exercise these deadlines and any separately reviewed identity renewal design.

Recovery names an existing POST_VERIFIED immutable digest, requires fresh signed
human approval and protected witness, binds the current base and attempt, consumes
fresh replay identities and repeats remote/post checks. Historical views are not
deleted or re-signed. An existing completed attempt is inspectable without granting
new authority; restarting write stages still requires fresh unexpired capabilities.

## Pages and client compatibility

Read-only GitHub Pages API inspection on 2026-10-12 confirmed `build_type=legacy`,
source `pages-storage:/`, custom domain `repo.ro-asd.org`, and
`https_enforced=false`. The stored branch tip observed during initial inspection
was `097ba6ba7ab73d87c36f7ec9829b017b083b1883`; it was not modified.

The current stable workflow serves
`https://repo.ro-asd.org/rpm/fedora/44/stable/<arch>/` and promotes a whole beta
snapshot. Existing Ro-ASD clients using that mutable path do not automatically
adopt the proposed view URL. Ro-ASD repository configuration was not changed.
Enforcing HTTPS, migrating client configuration and retiring the whole-beta stable
writer are activation prerequisites.

A single storage commit, successful Pages job or cache-control request does not
guarantee atomic visibility of multiple mutable paths. CDN PoP convergence and
publication availability have not been demonstrated. Immutable URLs prevent a
later update from intentionally mixing versions; partial first visibility still
fails closed and may cause a temporary client error. HTTP verification covers all
approved paths, not enumeration of every unadvertised object at the origin.

## Security corrections made during implementation

Separate commits enforce canonical RSA role identity (including different PEM
encodings of the same key), canonical dwell floors, exact complete stable-base
tree identity, authentic pre/post advertisement separation and signed deployment
commit binding. Regression tests reject missing stable heads and partial database
schemas before a trusted worker can sign a new initialization event. Every backend
envelope now passes its strict outer schema and its exact role-specific payload
contract. No existing security test was weakened.

Signed audit chains detect altered state or rewritten unsigned history. A
verified negative test also exposed an offline ledger integrity defect: a signer
returning a real signature from the wrong key could commit an invalid audit event
and authorization consumption before the next integrity check stopped progress.
Severity MEDIUM, isolated persistence availability/integrity impact; no live write
path was involved. `Ledger._append` now verifies each new event signature against
the independent audit root before insertion/commit. The failing regression is
`test_audit_signature_failure_rolls_back_authority`, and the minimum correction
rolls back state, replay consumption and audit together.
The corrected call is `tools/v3_backend_ledger.py:162`.

The native recovery adapter also preserves a historical snapshot's original
signed parent instead of requiring it to name the new current stable base. That
current base is verified separately against the protected request and publication
envelope. Otherwise recovery would require changing approved historical bytes.
The real Fedora signature fixture now covers this case without re-signing.

A fully
deleted database or restoration to an older valid signed database still needs an
independent monotonic checkpoint. Tests demonstrate this limitation explicitly;
the hash chain is not represented as independent anti-rollback storage.

Pinned upstream validation rejects unsafe repomd references and primary RPM URLs,
including `../`, absolute paths, URL schemes and encoded traversal; each cached
NEVRA, path and checksum must match primary metadata. Gzip, bzip2, xz and bounded
Zstandard decoding are implemented. Actual Zstandard feed execution is UNVERIFIED;
zchunk-only primary metadata decoding is BLOCKED.

## Tests and evidence

The evidence directory is `docs/evidence/v3-backend-20261012/`. Its README records
exact tested source inventories and command results. Acceptance statuses refer to
the documented environment, not production authority.

Required scenarios are exercised by the existing planner/composer/Fedora fixtures
and new backend tests: component bootstrap; retained full sets; upgrades;
unchanged dwell; unapproved group exclusion; subpackage/architecture/SRPM closure;
normal and fast-track restrictions; forged/replayed/expired approval; stale bases;
independent concurrent writers; interruption at every state; partial/corrupt remote
data; fresh verified-history recovery; wrong OIDC claims/signatures; stale evidence;
unpinned upstream and metadata path attacks; V2 writer conflict; missing real
application acceptance; and JSON/CI claims that cannot authorize publication.

Full unit/security, native Fedora 44 fixture DNF, existing V2 compatibility,
PostgreSQL, Git CAS, migration/recovery, schemas and workflow safety checks are
recorded in the evidence README. Native aarch64, real released applications,
official upstream closure, graphical/system VMs and real protected approval remain
UNVERIFIED. All eleven production jobs remain BLOCKED.

Final acceptance: 494 unit tests and 350 V3 tests passed, including 117 additional
tests beyond the preserved baseline. All seven GitHub CI checks passed on the
implementation head; public job links and exact SHA are in `ci-checks.json`.

## Maintainer handoff

Follow `V3-PRODUCTION-ACTIVATION-CHECKLIST.md` and `V3-V2-MIGRATION-PLAN.md` in a
separate activation review. This PR can be evaluated for merging only as an
explicitly NON-PRODUCTION integration milestone after its automated checks pass.
It does not establish production readiness.

Current specifications consulted: [GitHub OIDC](https://docs.github.com/en/actions/reference/security/oidc),
[environment protections](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments),
[Pages API](https://docs.github.com/en/rest/pages/pages#get-a-github-pages-site),
[PostgreSQL transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html),
and [QEMU Guest Agent](https://www.qemu.org/docs/master/interop/qemu-ga-ref.html).
