# V3 integration acceptance report

Historical acceptance record for the pre-review implementation. The subsequent
[PR #71 adversarial security review](V3-PR71-SECURITY-REVIEW.md) found and corrected
eight offline validation defects and adds source-bound evidence for the revised
implementation. The PASS observations below do not establish rejection of those
new negative scenarios or acceptance of the revised source tree.

Session date: 2026-10-11. Branch: `feature/v3-integration-complete`.
Production activation: **BLOCKED**. No release, workflow dispatch, live
promotion/rollback, private production key access, merge, `main` push or
`pages-storage` write was performed.

## 1. Initial baseline

Fetched `origin/main` before edits; its actual HEAD was
`db04a4cbfb0aa904d0a2c1244251e7795987a209`, the merged PR #70. The checkout was
clean. Read issue #44 including its complete roadmap (no comments), the V3
contract, producer registry, all 22 existing V3 modules, their tests, snapshot,
signing, promotion, DNF and provenance code and relevant Actions workflows.

The first host unit discovery was **BLOCKED** by missing `jsonschema` (14
module-import errors, not 14 security failures). Installing `jsonschema` and
PyYAML into `/tmp/ro-v3-venv` resolved the environment dependency. The unchanged
baseline then ran **327 tests successfully**, with 0 failures and 0 skips.

For actual Fedora execution, a disposable container based on Fedora 44 was
created with the source mounted read-only. Its observed base image manifest was
`sha256:07584325a68e0308215aff1de506d8da6452d2e465c25729829a01393446f204`.
Test tools were installed only inside that container. The final runtime package
set is separately hashed in the DNF receipts; the base image digest alone does
not describe installed test dependencies. No graphical host session was used
as application acceptance evidence.

## 2. Existing implementations reused and initial roadmap status

| Roadmap area | Actual implementation on initial main | Integration change |
| --- | --- | --- |
| PR-01 selection | Deterministic offline planner and group delta already implemented | Complete retained-group checks and downgrade rejection |
| PR-02 identity/dwell | Artifact identity, signed archives, API-completed first-seen and fast-track assessment already implemented | Registry-derived versioned identity/profile, signed exact local approval contract |
| PR-03 composer | Exact RPM byte composer, RPM/header/signature preflight, signed test preview existed | Integrate verified sources and whole result inventory; reproducible unsigned repodata |
| PR-04 validation | Group claims, DNF matrices/inputs/receipts and genuine x86_64 fixture transactions existed | Whole-stable-set architecture coverage, real Ro-Assist fixture bootstrap/upgrade/channel/config tests |
| PR-05 workflow | Live read-only source/Pages/run/ZIP audits existed; no integrated V3 production path | Reuse through `prepare_live`; eleven-stage production definition remains unconditionally disabled |
| PR-06 recovery | Existing V2 beta recovery; no isolated V3 stable attempt/recovery engine | New local immutable staging, replay ledger, CAS and signed historical recovery rehearsal |
| PR-07 acceptance | Real Ro-Control/atomic fixtures; real Ro-Store/app/GUI acceptance absent | Real DNF5 synthetic Ro-Assist full-set scenarios; real applications remain unverified |

Reuse includes the signed archive/API bridge, source and metadata-key pins,
pinned Git/Pages metadata, complete expected remote byte parity, runner context,
completed receipt and ZIP verification, live receipt audit, composer, RPM
preflight, signed preview and group validator. No duplicate remote publisher or
new public channel was added. V2 production workflow definitions and canonical
producer acceptance entries were not changed.

## 3. Changes and architecture decisions

- `v3_policy_profile.profile` is the single derived V3 test profile. Registry
  tests are supplemented by versioned V3 risk floors; a divergent supplied
  profile is rejected. Canonical production architecture coverage includes
  aarch64; the x86_64 E2E uses an explicitly narrowed **test-only** registry.
- `v3_integration.prepare` verifies signed snapshot/build metadata, source and
  signing provenance, first-seen archive/API consistency, complete composition,
  real pinned RPM signatures, optional full-set claims and signed result bytes.
  `prepare_live` adds the existing live source/Pages/runtime/ZIP checks, exact
  pinned registry bytes, current stable base and before/after ref checks.
- Candidate identity includes immutable packages, source provenance and policy;
  first-seen is separately bound to its original matching publication, avoiding
  dwell resets when unrelated beta content changes. Exact result/base/evidence
  digests, mode, reason and attempt are bound by the authorization request.
- Metadata signature checks now verify frozen copies, reject duplicate/nonfinite
  JSON and avoid inheriting the host's GPG/keyboxd configuration. Composer input
  inventories are checked before and after integrated verification.
- The planner rejects incomplete retained groups/SRPMs and unapproved RPM EVR
  downgrades. RPM preflight rejects linkage to another producer's SRPM even
  when a source filename happens to exist in the final set.
- Deterministic unsigned metadata uses a fixed epoch/revision, file mtimes,
  SHA-256, gzip, one worker and no database/zchunk generation. GPG signature
  timestamps remain a separate envelope; bitwise signature reproducibility is
  not claimed.
- `v3_authorization.verify_signed` authenticates **local** approval bytes with a
  pinned public key and bounded expiry. `v3_publication_rehearsal` has no Git,
  HTTP write or deployment backend. It checks stable-base CAS twice, consumes
  approvals, preserves immutable history and atomically commits a verified
  complete local view plus its completed audit record.
- `v3_full_set_dnf.validate` enforces actual Fedora 44/DNF5 architecture, full
  signed inventory, separate signing roles, real installations/upgrades, exact
  installed EVR/architecture, whole-set file conflicts, channel-only views and
  configuration preservation. A merged public key is derived **after separate
  role verification** because DNF/librepo can deduplicate isolated subkeys
  sharing a primary fingerprint.
- The compatibility fixture's temporary-path reference and old pathname-only
  conflict check were fixed, using the existing mode/ownership-aware checker.

## 4. Security trust boundaries

API field consistency, repository provenance, GPG/RPM signature verification,
workload/OIDC identity, protected environment approval and production publication
authorization remain separate assertions. Caller-supplied hashes, matching CI
statuses, actor strings and read-only receipt JSON grant no production authority.

Every integrated proposal and acceptance result sets `publishable: false` and
`approval_granted: false`. Every production workflow job has `if: ${{ false }}`,
read-only permissions and only `exit 1`. There are no secret references,
writable tokens, signing/publishing commands or deployment actions in that
definition. Enabling it requires a separate reviewed implementation change.

Local signed approval proves the signer of a local rehearsal request, not a
GitHub human/environment approval. Local audit hashes detect inconsistent edits,
not an adversary rewriting the whole local state. All fixture/API evidence is
explicitly distinguished from real immutable, authenticated release evidence.

## 5. Test commands and actual results

| Command/check | Actual result | Status |
| --- | --- | --- |
| Unchanged baseline: `python3 -m unittest discover -s tests -v` in prepared venv | 327 passed, 0 failed, 0 skipped | PASS |
| Final: `/tmp/ro-v3-venv/bin/python -m unittest discover -s tests -v` | 368 passed, 0 failed, 0 skipped | PASS |
| V3 regression: `python -m unittest discover -s tests -p 'test_v3_*.py' -v` | 224 passed, 0 failed, 0 skipped | PASS |
| Schema and workflow parsing | All schemas validated with Draft 2020-12; all workflow YAML parsed; disabled stage permissions/conditions checked | PASS |
| `python -m py_compile tools/*.py tests/v3-integration-fedora-e2e.py` | Completed successfully | PASS |
| `bash -n tests/e2e-local.sh tests/full-set-validation.sh tests/v3-integration-e2e.sh` | Completed successfully | PASS |
| `git diff --check` | No whitespace errors | PASS |
| Fedora 44: `bash tests/v3-integration-e2e.sh /tmp/v3-integration-evidence-eleven-stages` | Real signed bootstrap, full-set clean/upgrade, retained bytes, channel isolation, `.rpmnew`, reproducible metadata and actual dependency/conflict negative cases succeeded; source inventory unchanged throughout | PASS |
| Initial main in `/work-baseline`: `RO_REPO_E2E_EVIDENCE=/work-baseline/compatibility-evidence.json bash tests/e2e-local.sh` | Exit 0; actual signed RPM/preflight, Ro-Control and atomic-subpackage DNF transactions, full-set solver and rpmlint completed | PASS |
| Updated tree in `/work-current`: `RO_REPO_E2E_EVIDENCE=/work-current/compatibility-evidence.json bash tests/e2e-local.sh` | Exit 0; actual signed RPM/preflight, Ro-Control and atomic-subpackage DNF transactions, full-set solver and rpmlint completed | PASS |
| Compatibility evidence generator with relative output and absolute temporary snapshot | Original main reproduced `ValueError` from `relative_to`; corrected generator executed successfully in the regression test | PASS |
| Persisted evidence integrity | All inventory/log hashes verified, public-only key files checked and source digest matched the exact current tools/tests/schemas/config files | PASS |
| Standalone actionlint | Not installed; YAML/schema/permission checks ran instead | UNVERIFIED |
| GitHub PR CI for implementation commit `23f43d32dcaee236685364abd35ad93f3cc93e82` | All five automatic checks passed: full unit policy, legacy Fedora E2E, runtime contract, V3 security contracts and V3 Fedora full-set E2E; no manual workflow dispatch | PASS |

Draft [PR #71](https://github.com/Project-Ro-ASD/Ro-Repo/pull/71) targets `main`.
Observed successful CI runs for the implementation commit:
[V2 regression/runtime](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38170722823)
and [V3 integration acceptance](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38170722870).
The latter executed 40 integrated security/workflow/pin tests and the real
Fedora full-set fixture. Documentation-only follow-ups can trigger fresh CI;
these recorded observations refer to the exact implementation commit above.
Neither successful run authenticates production source/test attestations,
protected human approval or unavailable real application/graphical acceptance.

The **41 added unit tests** check security decisions, signed approval and local
state transitions, not just output field existence. The 224-test V3 group is a
mix of positive/negative regression tests; it is not 224 distinct attack cases.
Host real-GPG tests ran outside the filesystem sandbox after its agent/socket
restriction was encountered; all keys were generated temporarily and no
production private key was accessed.

## 6. Actual Fedora fixture gates

| Gate | Status | Evidence/limit |
| --- | --- | --- |
| Ro-Assist-only empty stable bootstrap | PASS | Actual signed synthetic RPM/SRPM, real DNF5 installation |
| Unchanged candidate dwell after unrelated beta refresh | PASS | Signed archive/API **fixture** consistency; same candidate and first-seen |
| Second Ro-Assist stable-to-stable upgrade | PASS | Real DNF5 installs baseline 1.0 then upgrades to 2.0 |
| Retained Ro-Control package/SRPM bytes | PASS | Byte comparison plus full-set RPMDB includes retained 1.0 |
| Unapproved Installer exclusion | PASS | Installer exists in real signed RPM beta fixture, absent from stable |
| Unapproved Dolphin exclusion/incomplete subpackages | PASS | Existing planner/composer contract tests; no claim of real Dolphin application acceptance |
| Stable-only and beta-only effective views | PASS | DNF queries select one isolated Ro repository; signatures stay enabled |
| Configuration upgrade | PASS | Locally modified `/etc/ro-assist.conf` retained; real `.rpmnew` produced |
| Incomplete dependency closure | PASS | Real DNF rejected `ro-v3-impossible-dependency` |
| Retained-group file conflict | PASS | Actual RPM payload overlap rejected before transaction |
| Unsigned repodata reproducibility | PASS | Identical inventories from two independent metadata builds |
| Exact full-set signed RPM/metadata verification | PASS | Pinned role keys, actual RPM/GPG checks, complete result inventory |
| Canonical aarch64 execution | UNVERIFIED | No native/aarch64 acceptance run; release gate remains closed |
| Real Ro-Assist/Dolphin/Installer applications | UNVERIFIED | Synthetic packages contain text/config payloads, not application code |
| Real Plasma integration/login | UNVERIFIED | No authorized real candidate graphical VM/session evidence |
| Applicable boot/reboot/recovery/QEMU | UNVERIFIED | No authorized real system candidate VM evidence |
| Ro-Store GUI application acceptance | UNVERIFIED | Separate maintainer-authorized application environment required |
| Full risk profile/rpmlint/smoke for real candidates | UNVERIFIED | Full-set DNF fixture success is not real application acceptance |
| Production activation/publication/rollback | BLOCKED | Backend, protected authority and required acceptance gates unavailable |

DNF5 and libdnf5 observed version: **5.4.6.0**, actual runner architecture
`x86_64`, RPM **6.0.2**. Receipts bind full-set and result/base tree digests,
RPMDB EVR/architecture, log SHA-256, actual OS-release digest and installed runtime
package-set digest. The acceptance record includes tested source-code hashes.
Runner attestation is explicitly `UNVERIFIED`.

The final local fixture evidence is versioned in
[`docs/evidence/v3-integration-local-20261011/`](evidence/v3-integration-local-20261011/):
acceptance record, full-set bootstrap/upgrade receipts, transaction logs,
ephemeral **public-only** keys and SHA-256 inventory. These files are local
test observations, not production attestations or authorization artifacts.

## 7. Negative coverage

Existing security tests were retained. They cover signed RPM/key/manifest
tampering, incomplete binary/SRPM/architecture sets, false/truncated beta history,
timestamps, source refs, forged workflow/job/artifact identities, wrong runner,
ZIP digest/member substitutions, missing mandatory tests and cross-group changes.

Added decisions exercise policy divergence, canonical architecture omissions,
incomplete retained groups/SRPMs, RPM epoch/version downgrades, candidate/policy/
provenance mutation, unsigned read-only approval forgery, **actual forged GPG
approval rejection**, result/base/mode/reason/attempt substitutions, stale expiry,
signed authorized fast-track with mandatory claims, metadata TOCTOU/duplicate
keys, source-registry blob/path/ref forgery, changed SRPM provenance, interrupted/
partial/tampered staging, concurrent stable bases, completed-history tampering,
unverified rollback rejection and signed recovery to an earlier verified snapshot.

The real Fedora E2E additionally rejects missing dependency closure using the
actual DNF solver and a payload conflict using actual RPM headers. Mocked API/
header tests establish contract decisions; their results are not substituted
for real cryptographic, desktop or system acceptance.

## 8. Remaining unverified claims and external requirements

The implementation does **not** prove trusted historical public beta uptime,
independent pin authenticity, OIDC workload identity, protected human approval,
authenticated full test artifact provenance, native aarch64 behavior, actual
producer application integration, real upstream Fedora package closure, real
Ro-Store UI upgrades or production Pages atomicity. Green PR CI cannot establish
these assertions.

Required environments: immutable official Fedora dependency repositories for
real applications; native/verified x86_64 and aarch64 images; real Fedora 44 Plasma
login/session VM; applicable boot/reboot/recovery/QEMU system VM; separately
authorized Ro-Store test machine; cryptographically attested workflow artifacts;
maintainer-configured protected environments/trust roots and a durable protected
approval/replay/CAS store. No missing gate was replaced with an unconditional skip.

## 9. Production activation blockers and exact unfinished surfaces

1. `tools/v3_integration.py::acceptance` keeps independent roots, source
   attestation, complete live history, OIDC, protected environment, production
   approval and independent remote verification `UNVERIFIED`; activation is
   permanently `BLOCKED` in this implementation.
2. `tools/v3_integration.py::prepare_live` combines read-only acquisition but
   cannot upgrade API/key/receipt consistency to authenticated production trust.
3. `tools/v3_full_set_dnf.py::validate` currently uses self-contained local
   repository fixtures. Real application dependencies require independently
   pinned upstream Fedora repository inputs and production baseline evidence.
4. `tools/v3_group_validation.py::validate_claim` validates claims; authentic
   immutable per-architecture test execution/runner evidence still needs a
   protected verifier. Real Plasma/system evidence is not produced here.
5. `tools/v3_publication_rehearsal.py::{begin,finish,audit}` implements local
   semantics only. A production durable replay ledger, authenticated failure
   receipts, protected serialization, remote staging/deployment and recovery
   backend are deliberately absent.
6. `.github/workflows/v3-stable-promotion-disabled.yml` defines all eleven stages
   as disabled placeholders. A separate reviewed change must implement and bind
   those production stages after proving the gates; changing a flag/input is
   insufficient.

## 10. Rollback/readiness and manual acceptance

Local recovery to an earlier verified immutable tree, distinct fresh signed
authorization, idempotence, partial staging and concurrent-base rejection passed
real-GPG unit tests. Historical trees survive both forward operations and
recovery. No actual channel rollback or publication was performed.

Local atomic state-file replacement and a Git commit do not prove atomic
multi-file GitHub Pages/CDN deployment. Mixed cached old/new files and unknown
remote extras remain unresolved. A future backend needs immutable object URLs,
verified complete view advertisement, deployment identity binding, protected
CAS and independent whole-remote-tree verification; no production atomicity
guarantee is claimed.

Maintainer acceptance must, in order:

1. Review the draft PR and keep all production jobs disabled.
2. Obtain authenticated source/acceptance/signing/attestation and full historical
   beta evidence for exact real candidate artifacts.
3. Execute the full canonical architecture matrix with pinned upstream Fedora
   closure, actual clean/upgrade/conflict/rpmlint/smoke and config tests.
4. Execute real Plasma/login gates for desktop risk and applicable system VM
   boot/reboot/recovery/QEMU gates, preserving immutable attributable evidence.
5. In a separately authorized Ro-Store environment, prove real Ro-Assist
   bootstrap and stable-to-stable update, beta-only/stable-only behavior,
   unavailable-channel handling, config preservation and effective DNF priority.
6. Implement/review protected OIDC authorization, exact signed result approval,
   durable replay/CAS, production signing/staging/publication, independent remote
   verification and Pages failure/recovery mechanics.
7. Only after every required gate is proven, separately review and authorize
   production activation. This PR does not supply that authorization.
