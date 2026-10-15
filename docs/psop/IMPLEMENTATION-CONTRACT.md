# PR-B / PR-C Implementation Contract

Bu harita uygulanacak dosyalar ve somut eksik API'ler için sözleşmedir. Listelenen
`psop_*` runtime modülleri **henüz yoktur**. PR-A yalnız audit kodu ekler.
PR-B offline/read-only hazırlık; PR-C kontrollü entegrasyon ve disposable kabul
olarak bölünür. Hiçbiri kendiliğinden production activation değildir.

## Mevcut modül sınırları

| Mevcut dosya / API | Yeniden kullanım ve entegrasyon | Eksik bağ / sınır |
| --- | --- | --- |
| `tools/v3_promotion_planner.py:plan` | Exact Beta+Stable manifests + registry + group → selected/retained full-set plan. | Acquisition signature/provenance doğrulamasını kendisi yapmaz. |
| `tools/v3_stable_composer.py:compose` | Immutable RPM byte materialization; empty Stable parametresi yalnız explicit genesis sonrası. | Metadata generation/signing/approval yok; output untrusted/nonpublishable. |
| `tools/v3_rpm_preflight.py:verify` | External pinned RPM key ile header/signature/SRPM/noarch/full set kontrolü. | DNF/GUI/VM veya publisher authority üretmez. |
| `tools/v3_policy_profile.py:profile, require_complete` ve `v3_promotion_policy.py:evaluate` | Registry tek policy kaynağı; risk floors, 7/14 gün artifact dwell, fast-track gerekçesi. | Gerçek availability/history ve execution evidence authentication gerekiyor. |
| `tools/v3_github_source_pins.py`, `v3_pages_archive_provenance.py`, `v3_github_beta_api.py`, `v3_github_beta_audit.py`, `v3_beta_evidence_bridge.py:verify_evidence` | Exact commit/artifact/archive/API collection ve byte coverage doğrulaması. | Legacy signed publication formatı ve trusted historical availability bridge eksik; pinned API gözlemi tam provider fence değil. |
| `tools/v3_signed_beta_history.py:signed_archive_bundle` | Signed snapshot/history kontrolü ve immutable archive üyeleri. | Strict mode eski kaydı reddediyor. Legacy compatibility yalnız parse/gözlem; trusted first-seen'e otomatik yükseltilemez. |
| `tools/v3_repository_metadata.py`, `v3_signed_stable_preview.py`, `v3_full_set_dnf.py:validate` | Deterministic metadata mekanikleri, signed isolated result, pinned upstream closure ve actual DNF full-set işlemi. | Preview test-only signing guard'ı korunur; production metadata signer için ayrı PSOP adapter gerekir. |
| `tools/v3_group_validation.py:validate_claim`, DNF receipt/bundle/run-context modülleri | Exact candidate/base/arch/required-test binding; completed run/artifact ZIP digest kontrolleri. | Consistent claim authenticated execution değildir; production evidence issuer binding eksik. |
| `tools/v3_integration.py:prepare, prepare_live` | Read-only acquisition/composition orchestration ve result inventory doğrulaması örneği. | Hardcoded V3 scopes/gates değişmez; PSOP wrapper kendi domain'ini tanımlar. |
| `tools/v3_fenced_publisher.py:FencedPublisher`, `v3_publication_outbox.py:Outbox` | Durable intent, lease/fence, branch-wide UNKNOWN block ve exact reconciliation mekanikleri. | `activate_production` kilitli kalır. Production PSOP gateway/custody/drain kanıtı ayrıca gerekir. |
| `tools/v3_github_provider.py`, `v3_branch_pages.py`, `v3_immutable_view.py` | Prepared target/expected-head CAS, immutable inventory ve exact public-byte/Pages identity verification örüntüleri. | Test/disposable origin guards kaldırılmaz. Native deadline/order/freshness eklenemez. |
| `tools/v3_backend_ledger.py`, `v3_postgresql_production.py`, `v3_authorization.py`, `v3_backend_evidence.py`, `v3_identity_integration.py` | Durable replay/state/CAS ve authenticated identity/approval parsing temel ilkeleri. | PSOP domain, persistence deployment, issuer/root/custody/recovery kabulü eksik. TestSigner production issuer değildir. |
| `tools/v3_client_update.py:Client` | Preinstalled roots, complete immutable hash checks, local monotonic state ve DNF reject/failure testleri. | V3 fresh discovery/independent authority sözleşmesini PSOP diye yeniden etiketleme; ayrı adapter gerekir. |
| `tools/ro_repo.py` V2 verify/stage fonksiyonları | Signed source/snapshot verification ve exact file/history preservation mekanikleri. | Embedded key güveni dış pinle tamamlanır. V2 Stable dispatcher PSOP publisher'ı olamaz. |

## PR-B: kapalı offline pipeline

| Yeni dosya | API ve output | Bağımlılık / kabul testi |
| --- | --- | --- |
| `tools/psop_inputs.py` | `acquire(pins, public_roots, archive) -> VerifiedInputs`; source/beta/previous-stable/history digest'leri. | V3 pins + signed archive; yanlış key/commit, incomplete history, 404-genesis ve V1 reddi. |
| `tools/psop_history.py` | `assess_history(signed_archive, api_observations, availability_evidence) -> HistoryAssessment`. Observed/trusted first-seen ayrı. | R-07 tasarımı review edilmeli; eski imzalar değişmez; coverage ve missing witness fail closed. |
| `tools/psop_plan.py` | `prepare(inputs, group, registry, evidence) -> ReviewBundle`; planner/composer/preflight çağrıları. | Exact selected+retained closure, hash/header/SRPM ve policy binding; mevcut fixture'lar. |
| `tools/psop_result.py` | `build_metadata(composition, deterministic_parameters) -> UnsignedResult`; `verify_result(...) -> ResultDigest`. | Metadata mekanikleri reuse; production secret yok, disposable test signatures; RPM re-sign yok. |
| `schemas/psop-review-v1.schema.json` | Domain/version, exact source/base/result/policy/evidence, explicit genesis, required-test coverage; `publishable=false`. | Unknown fields/domain substitution/claim-as-execution negative tests. |
| `tests/test_psop_inputs.py`, `test_psop_plan.py`, `test_psop_history.py`, `psop-offline-e2e.py` | Existing V2/V3 fixtures/native DNF runner reuse. | Wrong role, malformed history, partial group/arch, retained-byte mutation, missing tests ve offline result determinism. |

PR-B source baseline guard'ı bilinçli ve review edilebilir yeni kapsamla günceller;
beta workflow ve V3 activation guard'larını gevşetmez. ReviewBundle hiçbir write,
signing approval veya production claim oluşturmaz. History bridge çözülemezse
plan/evidence raporlanabilir fakat promotable=false kalır. Fast-track history veya
required-test authority eksikliğine genel istisna olamaz.

PR-B başlamadan çözülmesi gereken tasarım girdileri: legacy archive witness ve
first-seen semantiği; bütün branch writer'larının owner/custody geçiş planı;
explicit genesis kanıt listesi; PSOP client descriptor URL/domain'i ve local
monotonic state politikası. Production secret erişimi PR-B önkoşulu değildir.

## PR-C: ayrı PSOP domain ile entegrasyon

| Yeni / gelecekte değişecek dosya | Eksik API / entegrasyon | Zorunlu gate |
| --- | --- | --- |
| `tools/psop_authorization.py`, `schemas/psop-approval-v1.schema.json` | `verify_approval(raw, authenticated_identity, review_bundle, trusted_policy, now)`; exact profile/policy/base/result/evidence/run/attempt/expiry/nonce + durable consume. | G-04/07/09; environment job approval tek başına exact bundle kimliği değildir. |
| `tools/psop_signing.py` | Verified exact result için production metadata-role adapter; isolated secret handling, exact subkey, output verification. | G-05/09; production RPM re-sign yok; preview guards korunur. |
| `tools/psop_storage_gateway.py` | `prepare(intent)->(before_oid,target_oid)`; `admit(approval, intent)`; `apply(intent)`; `reconcile(intent)`; independently proven noncommit dışında abort yok. | G-02/03/10; tek branch-wide realm, worker credential yok. |
| `tools/psop_receipts.py`, `schemas/psop-publication-v1.schema.json` | Durable attempted/UNKNOWN/failed/completed history; profile, hashes, actor, CAS target, admitted/requested/observed times, probe coverage ve explicit provider limitations. | MSC-11/14; yanlış profile/receipt domain reddi. |
| `tools/psop_client.py`, `schemas/psop-client-descriptor-v1.schema.json` | `verify_descriptor`, `prepare_transaction`; immutable baseurls, external roots, inventory, bounded validity, local generation, atomic repo/state. | G-12; V3 discovery service varmış gibi sunulmaz; first-client freshness limitation kayıtlı. |
| Gelecekteki PSOP workflow ve mevcut dört V2 writer'ın gateway adapter'ları | Signing/approval/publication jobs ayrı; main-only; permission minimal; bütün writer'lar ortak gateway. Beta path/output semantiği korunur. | Ayrı yetkilendirilmiş migration/review; PR-A ve PR-B'de workflow değişmez. |
| `tests/test_psop_publisher.py`, `test_psop_client.py`, disposable provider kabulü | Crash/response-loss/replay, conflicting V2/PSOP attempts, complete byte/client rejection ve Beta regression. | #78 hâlâ açık ise testleri kopyalama; main'deki reusable fixtures + #78 için ayrı diagnostic çalışma. |

Eksik production API'ler mevcut V3 guard'ı kaldırılarak açılmaz. İlk PR-C workflow
yalnız disposable target için çalışmalı; gerçek writer cutover, risk kabulü ve
production dispatch G-01..14 + açık ayrı operator talimatı olmadan kapalı kalır.
DNS, Cloudflare ve HP değişiklikleri bu haritanın varsayılan parçası değildir.
