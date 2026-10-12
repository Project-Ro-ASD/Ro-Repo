# V3 production integration closure

Production activation remains **BLOCKED**. This PR is a NON-PRODUCTION engineering closure on `feature/v3-production-integration-closure`, based on main `d65aa82b2e7cf5ac4188abbf0c969dddeb7ec8c0`. It extends the merged V3 foundation without changing V2 production workflows or enabling any V3 writer.

## Completed implementation

| Workstream | Implemented behavior | Acceptance boundary |
| --- | --- | --- |
| Legacy beta history | Explicit compatibility verifies original GPG-signed V1 records with optional store digest; absent digests remain null, historical dwell is rejected. A separately authenticated immutable fresh V3 genesis binds full candidate identity and current observer UTC; 7/14-day policy and protected fast-track remain enforced. | Six actual archived publications and their three referenced snapshot signatures rechecked; observer/source deployment remains UNVERIFIED. |
| PostgreSQL | Separate guarded adapter with pinned CA, libpq verify-full/server identity, exact restricted grants, no writer DDL/ownership, UTF8, serializable transactions, common advisory/row lock, synchronous commits and existing signed audit/CAS/replay ledger. Provisioned empty schemas need fresh independent empty-state proof. | Actual isolated PostgreSQL 18.6 TLS, restricted role and two-process tests; no production connection. |
| Independent checkpoints | Nonce/freshness-bound HTTPS interface and reproducible loopback service. Exact next signed audit checkpoint reserved before DB commit and acknowledged afterward. Crash reconciliation accepts committed targets; absent targets need a distinct independently signed fenced noncommit observation. Local old backups cannot erase reservations. | Protocol/restore/response-loss isolated tests; service independence, HA, power-loss durability and external restore/failover remain UNVERIFIED. |
| Publication/recovery | Outbox inside authenticated attempt state, immutable idempotency, leases/fences, durable provider receipts and serialized Git CAS. Approved signed result → immutable stage → deployment pre-verification → DB intent → signed Git advertisement → independent post-verification → completed audit. Exact signed external bytes reconcile lost responses. | Disposable actual Git plus simulated deployments; Git/DB intent never proves Pages/CDN visibility. |
| Identity/protected approvals | Complete public-root provisioning validator, distinct canonical roles, signed monotonic JWKS lifecycle/revocation checks feeding existing exact OIDC verifier. Existing result-bound human approval, reviewer separation, witness and replay contracts preserved. | Ephemeral RSA/OIDC/approval/witness tests; real services/environments and signer identities remain UNVERIFIED. |
| Hardware preparation | Read-only evidence collector with raw-command hashes and machine-readable UNVERIFIED cases; reproducible maintainer kit reuses real transaction and VM frameworks. | No GUI, boot, laptop/university desktop, QEMU image or aarch64 execution claimed. |
| DNF/client/cutover | Fresh signed nonce-bound discovery, complete immutable view and historical publication signature verification, generation/checkpoint antirollback, atomic repo config, common transaction lock, pinned RPM/metadata public roots and one fixed DNF baseurl. Prepared writer retirement/import/empty-stable procedures. | Actual local HTTPS/DNF signed synthetic install 1.0 → discovery → upgrade 2.0 passes. Real client packaging/GUI adoption and cutover not executed. |

The legacy difference is structural, not a broken signature: V1 required `schema_version`, `channel`, `publication_run`, `published_at`, `snapshot_id`, with `store_tree_sha256` optional. Four early records omit it, two later records include it. The former V3 verifier required all six fields. Detached GPG metadata signatures validate the original claimed timestamp and bytes; they do not independently authenticate first public availability. New backend first-seen authority is a distinct signed observer record, never a rewritten legacy publication.

Read-only audit captured 22 public metadata/signature files at Pages commit `097ba6ba7ab73d87c36f7ec9829b017b083b1883`; six publications reference snapshots `repo-f44-20260920-001`, `repo-f44-20260921-001`, `repo-f44-20261009-001`. The existing metadata public bytes hash is `4eaf0b2903e60442c2f05325a43d85046bba850059b732dfc71e330f5e9e0809`. This root was read from the repository, not independently provisioned as new production authority. The compatibility output has an empty candidate_history and `historical_dwell_credit=REJECTED`.

## Exact remaining code blockers

1. **Live fenced provider wiring — BLOCKED:** `Coordinator` deliberately accepts disposable Git only. Production GitHub storage CAS, provider-enforced fence handling for delayed requests, live idempotent deployment transport and independently witnessed deployment reconciliation must be supplied/reviewed against the new interfaces. The production publication/signing/staging factories remain blocked or test-only; authenticated live signing/staging and storage/deploy provider adapters require review. No live storage/deploy credential path exists in this PR.
2. **Activated protected import/bootstrap — BLOCKED:** rehearsal seeding, inventory assessment and unapplied retirement patch are implemented. Consuming a real protected V2 import or empty-stable cutover through activated common authority still needs the separately reviewed activation adapter. A missing historical head cannot be reinitialized. Coordinator resumption retains the original authorization deadline and 60-second pre-verification freshness. After those bounds, a fresh protected recovery/reconciliation adapter is required; the first-bootstrap case has no previously POST_VERIFIED target and must remain BLOCKED until an explicit current-state authorization contract is reviewed. No expired approval is silently renewed or pending view relabelled as verified history.
3. **Real client integration outside this repository — BLOCKED:** package/update GUI/CLI routing, trusted-root installation and host-client rollout belong to a separately authorized Ro-ASD client change. The current client executes only in private disposable roots. The discovery signer must be independently operated and serve only current POST_VERIFIED state.
4. **Feed-specific zchunk-only decoder — BLOCKED if selected:** existing gzip/bzip2/xz/Zstandard support is preserved; a zchunk-only primary feed still requires a decoder and real acceptance. The previously captured Fedora feed has a supported Zstandard primary path, so this is not a reason to weaken verification.

Production adapter/job guards are intentional activation boundaries. Existing isolated adapters and tests remain present. This milestone supplies executable protocol implementations and guarded integration points; it does not claim a live service has been deployed.

## External provisioning and hardware requirements

Follow [exact provisioning specifications](V3-CLOSURE-PROVISIONING.md): reviewed independent public roots and key custody; restricted TLS PostgreSQL with durable HA/backups; independent monotonic reservation/checkpoint and restore/abort observers; authenticated beta availability observer; source/test attestators; protected human approval and independent environment witness; trusted publisher/reusable signer workflow code pins; independently signed JWKS refresh/revocation; live fenced Git/deployment providers; HTTPS enforcement and independent complete Pages/CDN probes; fresh discovery service and real client adoption.

For `repo-stable` and `repo-production-signing`, maintainer provisioning must enable prevent-self-review, require approved reviewers, restrict main deployment branches, disable administrative bypass and independently pin exact configuration. No environment setting or real approval was created. Exact production workflow SHAs/subjects are maintainer inputs, not invented in this report.

Run the [hardware acceptance kit](V3-HARDWARE-ACCEPTANCE-KIT.md) on actual Fedora44 laptop/university desktops, genuine Ro-ASD QEMU and native or accurately labelled emulated aarch64 environments. Complete real Assist install/upgrade/runtime, Dolphin/Plasma/login, Installer GUI and operator-authorized disposable/dedicated-disk installation, boot/reboot, effective repo isolation, component upgrade, retained/config/conflict and recovery cases. Supply pinned images/executors/firmware/media and genuine guest acceptance helper. No disk operation runs automatically.

The prior report's 519 tests, 11/11 released-package scenarios and 262/262 expected public files remain **prior milestone evidence**. This PR does not relabel synthetic packages as those real applications or claim additional real hardware acceptance.

## Production activation requirements

Use the updated [activation checklist](V3-PRODUCTION-ACTIVATION-CHECKLIST.md), existing [V2 migration plan](V3-V2-MIGRATION-PLAN.md) and [prepared closure cutover procedure](V3-CLOSURE-CUTOVER.md). Verify authenticated initial stable state, full canonical release/architecture/application evidence, protected result-bound promotion/import authorization, independent checkpoint/recovery operation, external TLS/HA/fencing/deployment acceptance, full HTTPS pre/post verification and actual client update behavior. Drain/retire V2 only through reviewed cutover; the future V3 writer must never operate concurrently with the independent V2 whole-beta stable writer.

`production_publish()` remains unconditional BLOCKED; the production DB route remains unconditional BLOCKED; all eleven workflow jobs remain `${{ false }}`. No production publication/migration/rollback was executed. Signed RPM history is not overwritten. CDN convergence is observed externally and never described as cross-CDN atomicity.

## Verification and evidence

Final implementation inventory SHA256: `3ba19ca0f7a4d091ada777fdbb573b9af2dba5ca5784cdaa62dd5b90412c9f1f` (132 Python/shell/schema/config files). [Evidence inventory, receipts and compressed raw logs](evidence/v3-closure-20261012/) bind the final implementation.

| Test | Result |
| --- | --- |
| Full Python unit/security suite | PASS: 542 tests, including 398 V3; 0 failures/errors/skips. Earlier read-only run had eight existing scratch-directory errors, resolved by the writable disposable copy. |
| Closure protocol regression suite | 21 cases included in full suite; independent reservations, replay/expiry/config/signature failures, stale leases, provider response loss and client consistency |
| Fedora44 native signed fixture integration | PASS, exit 0; real signed RPM/SRPM, full-set install/upgrade/config/conflict negatives and HTTPS discovery-driven DNF 1.0 → 2.0 |
| PostgreSQL existing adversarial suite | PASS, exit 0; independent writer/recovery races, process death, replay, signed audit corruption and restored old backup/checkpoint rejection |
| PostgreSQL verify-full/restricted roles | PASS, exit 0; actual correct TLS, wrong CA/hostname rejection, permission denials, two-process CAS and rollback |
| Actual disposable Git/backend recovery | PASS, exit 0; existing complete signed rehearsal plus new durable outbox crash/response-loss reconciliation |
| Native DNF metadata URL override | PASS, exit 0; existing xml:base negative |
| Existing V2 compatibility | PASS: complete local V2 E2E exit 0, including single/multi-subpackage native install/upgrade, catalog/publication/recovery and rpmlint 0 errors / 4 synthetic fixture warnings; complete V2 CI also passes. |
| Static checks | PASS: 102 Python files, 10 shell files, all schemas/YAML and diff whitespace |
| Safety audit | PASS: eleven V2 workflows byte-identical; disabled V3 workflow byte-identical and eleven unconditional false jobs; no new private signing keys/tokens in changed artifacts |
| GitHub CI | PASS: 8/8 SUCCESS on `1ec63761119084d39f2891b83d40c0cf825db739`; actual job logs confirm 542 full tests and 398 V3 tests |

No private key, JWT, production credential or database backup is committed. Test passwords are explicitly disposable. Real Pages storage ref is independently checked read-only; no write is attempted. Local service/deployment fixtures cannot satisfy actual production acceptance.

## Türkçe devir

V3 mimarisi korunarak legacy imzalı geçmiş uyumluluğu, yeni authenticated first-seen, guarded TLS PostgreSQL, bağımsız checkpoint reservation/recovery, audited publication outbox, OIDC/JWKS entegrasyonu ve digest'i otomatik keşfeden güvenli DNF güncelleme akışı eklendi. Eski kayıtlara dwell/provenance uydurulmadı; normal 7/14 günlük bekleme ve protected fast-track şartları korunuyor.

Bu PR yalnız **NON-PRODUCTION** entegrasyon içindir. Production **BLOCKED**, on bir job kapalı; V2, pages-storage, production anahtar/credential/environment/database ve gerçek yayın değiştirilmedi. İlk gerçek stable için bağımsız servis/root provisioning, gerçek hardware/GUI/aarch64 kabulü, live fenced provider ve protected import wiring, client rollout ve tek-writer V2→V3 cutover tamamlanıp ayrıca onaylanmalıdır. PR draft teslim edilir; merge/aktivasyon yapılmaz.

## Head-specific public CI and merge recommendation

[Draft PR #74](https://github.com/Project-Ro-ASD/Ro-Repo/pull/74) targets main and remains unmerged. All three workflow runs explicitly report head `1ec63761119084d39f2891b83d40c0cf825db739`, matching the final implementation inventory above and actual 542/398 test logs. Later documentation-only commits preserve that source inventory; their own checks are verified separately at handoff. No older head's result is attributed to a different implementation.

| Check | Result | Public job |
| --- | --- | --- |
| acceptance-runtime-contract | SUCCESS | [job](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38310632623/job/115015211679) |
| backend-security | SUCCESS | [job](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38310632616/job/115015211350) |
| closure-tls-postgresql | SUCCESS | [job](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38310632616/job/115015211311) |
| fedora44-e2e | SUCCESS | [job](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38310632623/job/115015212049) |
| fedora44-full-stable-set | SUCCESS | [job](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38310632613/job/115015211558) |
| postgres-transactions | SUCCESS | [job](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38310632616/job/115015210944) |
| security-contracts | SUCCESS | [job](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38310632613/job/115015211318) |
| unit-policy | SUCCESS | [job](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38310632623/job/115015211592) |

The code is suitable for a **NON-PRODUCTION merge**, subject to normal maintainer review. It is **not suitable for first real stable publication**: live fenced provider/protected import wiring, independently operated trust/checkpoint/observer/witness/discovery/deployment services, external TLS/HA/restore and Pages/CDN acceptance, genuine application/hardware/GUI/aarch64 evidence, and reviewed V2 writer/client cutover remain mandatory. No activation or merge was performed.
