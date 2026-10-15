# PR-B / PR-C Implementation Contract

Bu harita uygulanacak dosyalar ve somut eksik API'ler için sözleşmedir. Listelenen
`psop_*` runtime modülleri **henüz yoktur**. PR-A yalnız audit kodu ekler.
PR-B uygulama kodunu ve yalnız disposable/test publication yolunu geliştirir.
PR-C istemci entegrasyonu, gerçek runtime testleri ve disposable dış kabulü
tamamlar. Writer custody cutover, GitHub ayarları ve canlı Stable aktivasyonu
ayrı operatör aşamasıdır. Hiçbir PR kendiliğinden production yetkisi vermez.

| Aşama | Teslimat | Açılmayan yetki |
| --- | --- | --- |
| PR-B | Verified inputs/history/genesis, plan/compose/result, PSOP approval/signing, durable ledger/outbox ve ortak writer gateway uygulaması; disposable/test yayın. | Production writer/secret, gerçek V2 cutover ve activation. |
| PR-C | PSOP client descriptor/state, Fedora 44 DNF5, imza/hash negatifleri, provider fault injection, disposable Pages HTTPS, Beta regresyonları ve operator runbook/readiness. | Production custody, GitHub ayar değişikliği ve canlı Stable activation. |
| Ayrı operatör aşaması | Açık yetkilendirme ve tüm activation gate'leri sonrası reviewed writer custody/V2 cutover, gerekli GitHub ayarları ve canlı Stable aktivasyonu. | Yetkilendirme veya herhangi bir gate eksikken işlem yapılamaz. |

## Mevcut modül sınırları

| Mevcut dosya / API | Yeniden kullanım ve entegrasyon | Eksik bağ / sınır |
| --- | --- | --- |
| `tools/v3_promotion_planner.py:plan` | Exact Beta+Stable manifests + registry + group → selected/retained full-set plan. | Acquisition signature/provenance doğrulamasını kendisi yapmaz. |
| `tools/v3_stable_composer.py:compose` | Immutable RPM byte materialization; empty Stable parametresi yalnız explicit genesis sonrası. | Metadata generation/signing/approval yok; output untrusted/nonpublishable. |
| `tools/v3_rpm_preflight.py:verify` | External pinned RPM key ile header/signature/SRPM/noarch/full set kontrolü. | DNF/GUI/VM veya publisher authority üretmez. |
| `tools/v3_policy_profile.py:profile, require_complete` ve `v3_promotion_policy.py:evaluate` | Registry tek policy kaynağı; risk floors, 7/14 gün artifact dwell, fast-track gerekçesi. | Gerçek availability/history ve execution evidence authentication gerekiyor. |
| `tools/v3_github_source_pins.py`, `v3_pages_archive_provenance.py`, `v3_github_beta_api.py`, `v3_github_beta_audit.py`, `v3_beta_evidence_bridge.py:verify_evidence` | Exact commit/artifact/archive/API collection ve byte coverage doğrulaması. | Legacy signed publication formatı ve trusted historical availability bridge eksik; pinned API gözlemi tam provider fence değil. |
| `tools/v3_signed_beta_history.py:signed_archive_bundle` | Signed snapshot/history kontrolü ve immutable archive üyeleri. | Strict mode eski kaydı reddediyor. Legacy compatibility yalnız parse/gözlem; trusted first-seen'e otomatik yükseltilemez. |
| `tools/v3_repository_metadata.py`, `v3_signed_stable_preview.py`, `v3_full_set_dnf.py:validate` | Deterministic metadata mekanikleri, signed isolated result, pinned upstream closure ve actual DNF full-set işlemi. | PR-B PSOP signing adapter'ı yalnız disposable test anahtarları kullanır; PR-C gerçek DNF5 kabulünü tamamlar. Preview guard'ı korunur; production secret bağlanmaz. |
| `tools/v3_group_validation.py:validate_claim`, DNF receipt/bundle/run-context modülleri | Exact candidate/base/arch/required-test binding; completed run/artifact ZIP digest kontrolleri. | Consistent claim authenticated execution değildir; production evidence issuer binding eksik. |
| `tools/v3_integration.py:prepare, prepare_live` | Read-only acquisition/composition orchestration ve result inventory doğrulaması örneği. | Hardcoded V3 scopes/gates değişmez; PSOP wrapper kendi domain'ini tanımlar. |
| `tools/v3_fenced_publisher.py:FencedPublisher`, `v3_publication_outbox.py:Outbox` | Durable intent, lease/fence, branch-wide UNKNOWN block ve exact reconciliation mekanikleri. | `activate_production` kilitli kalır. Production PSOP gateway/custody/drain kanıtı ayrıca gerekir. |
| `tools/v3_github_provider.py`, `v3_branch_pages.py`, `v3_immutable_view.py` | Prepared target/expected-head CAS, immutable inventory ve exact public-byte/Pages identity verification örüntüleri. | Test/disposable origin guards kaldırılmaz. Native deadline/order/freshness eklenemez. |
| `tools/v3_backend_ledger.py`, `v3_postgresql_production.py`, `v3_authorization.py`, `v3_backend_evidence.py`, `v3_identity_integration.py` | Durable replay/state/CAS ve authenticated identity/approval parsing temel ilkeleri. | PR-B PSOP domain ve durable ledger/outbox kodunu disposable ortamda uygular; PR-C recovery kabulünü tamamlar. Production deployment/issuer/custody ayrı operatör gate'idir. TestSigner production issuer değildir. |
| `tools/v3_client_update.py:Client` | Preinstalled roots, complete immutable hash checks, local monotonic state ve DNF reject/failure testleri. | V3 fresh discovery/independent authority sözleşmesini PSOP diye yeniden etiketleme; ayrı adapter gerekir. |
| `tools/ro_repo.py` V2 verify/stage fonksiyonları | Signed source/snapshot verification ve exact file/history preservation mekanikleri. | Embedded key güveni dış pinle tamamlanır. V2 Stable dispatcher PSOP publisher'ı olamaz. |

## PR-B: uygulama kodu ve yalnız disposable/test publication

| Yeni dosya | API ve output | Bağımlılık / kabul testi |
| --- | --- | --- |
| `tools/psop_inputs.py` | `acquire(pins, public_roots, archive) -> VerifiedInputs`; source/beta/previous-stable/history digest'leri. | V3 pins + signed archive; yanlış key/commit, incomplete history, 404-genesis ve V1 reddi. |
| `tools/psop_history.py` | `assess_history(signed_archive, api_observations, availability_evidence) -> HistoryAssessment`. Observed/trusted first-seen ayrı. | R-07 tasarımı review edilmeli; eski imzalar değişmez; coverage ve missing witness fail closed. |
| `tools/psop_genesis.py` | `verify_genesis(inputs, history, bound_approval) -> VerifiedGenesis`; explicit empty Stable ve exact history/base binding. | 404 veya current tree yokluğu tek başına genesis değildir; incomplete history, yanlış scope/approval ve V1 reddi. Disposable genesis production ledger initialize etmez. |
| `tools/psop_plan.py` | `prepare(inputs, group, registry, evidence) -> ReviewBundle`; planner/composer/preflight çağrıları. | Exact selected+retained closure, hash/header/SRPM ve policy binding; mevcut fixture'lar. |
| `tools/psop_result.py` | `build_metadata(composition, deterministic_parameters) -> UnsignedResult`; `verify_result(...) -> ResultDigest`. | Metadata mekanikleri reuse; production secret yok, disposable test signatures; RPM re-sign yok. |
| `schemas/psop-review-v1.schema.json` | Domain/version, exact source/base/result/policy/evidence, explicit genesis, required-test coverage; `publishable=false`. | Unknown fields/domain substitution/claim-as-execution negative tests. |
| `tools/psop_authorization.py`, `schemas/psop-approval-v1.schema.json` | `verify_approval(raw, authenticated_identity, review_bundle, trusted_policy, now)`; exact PSOP domain/policy/base/result/evidence/run/attempt/expiry/nonce ve test-environment binding. | G-09 mekanikleri disposable kimlik/issuer ile; replay store'a bağlı tüketim. Düz JSON veya environment job approval tek başına exact bundle kimliği değildir. Production approval üretmez/kabul etmez. |
| `tools/psop_signing.py` | `sign_result(verified_result, approval, test_signer) -> SignedResult`; PSOP-specific metadata-role adapter, exact subkey ve output verification. | Yalnız ephemeral disposable test anahtarları; production secret erişimi yok, RPM re-sign yok, preview ve Strict V3 guard'ları korunur. |
| `tools/psop_ledger.py`, `tools/psop_outbox.py` | Durable attempt/replay/base-generation kayıtları; atomic approval consumption + intent enqueue; claim/fence/checkpoint/reopen/reconcile API'leri. | V3 ledger/outbox reuse; disposable persistent store'da restart/restore ve UNKNOWN successor block. Production ledger initialize edilmez veya bağlanmaz. |
| `tools/psop_storage_gateway.py` | `prepare(intent)->(before_oid,target_oid)`; `admit(approval, intent)`; `apply(intent)`; `reconcile(intent)`; independently proven noncommit dışında abort yok. | Tek branch-wide realm; bütün simulated V2/PSOP writer'lar aynı gateway'den geçer. Worker credential yok; yalnız disposable Git/test transport. Gerçek V2 workflow/custody cutover yok. |
| `tools/psop_receipts.py`, `schemas/psop-publication-v1.schema.json` | Durable attempted/UNKNOWN/failed/completed history; profile, hashes, actor, CAS target, admitted/requested/observed times, probe coverage ve explicit provider limitations. | MSC-11/14; yanlış profile/environment/receipt domain reddi. Test sonucu production receipt olarak sunulmaz. |
| `tests/test_psop_inputs.py`, `test_psop_genesis.py`, `test_psop_plan.py`, `test_psop_history.py`, `test_psop_authorization.py`, `test_psop_signing.py`, `test_psop_publisher.py`, `psop-offline-e2e.py` | Mevcut V2/V3 fixture'larıyla uygulama kontratları ve local disposable uçtan uca yayın. | Wrong trust/role, eksik history/genesis, partial group/arch, determinism, approval replay/expiry, durable restart, aynı realm'de writer çatışması ve production target reddi. PR-C dış kabulünün yerine geçmez. |

PR-B source baseline guard'ı bilinçli ve review edilebilir yeni kapsamla günceller;
Beta workflow ve V3 activation guard'larını gevşetmez. ReviewBundle kendi başına
write/signing yetkisi vermez; ayrı PSOP approval, signing, ledger ve gateway kodu
yalnız doğrulanmış disposable/test context içinde çalışır. Repository/ref/origin,
trust/issuer ve storage context bağları doğrulanır; caller'ın tek bir `test=true`
bayrağı veya production hedefe işaret eden config'i yeterli değildir. Production
repository/ref/origin hedefleri fail closed reddedilir. Production writer,
secret provisioning, V2 cutover ve activation kapalı kalır. History bridge çözülemezse
plan/evidence raporlanabilir fakat promotable=false kalır. Fast-track history veya
required-test authority eksikliğine genel istisna olamaz.

PR-B içinde tamamlanacak tasarım ve uygulama girdileri: legacy archive witness /
first-seen semantiği, explicit genesis kanıt listesi, ortak gateway'in bütün writer
işlemleri için kontratı ve PR-C'ye verilecek SignedResult/receipt kimlikleri.
Client descriptor/state uyumu için PR-C sınırı belgelenir; client uygulaması PR-C'dedir.
Gerçek production custody/env/secret erişimi PR-B veya PR-C önkoşulu değildir;
bunlar ayrı operatör aşamasında kanıtlanmadan canlı kullanım BLOCKED kalır.

## PR-C: client entegrasyonu, runtime testleri ve disposable kabul

| Yeni / gelecekte değişecek dosya | Eksik API / entegrasyon | Zorunlu gate |
| --- | --- | --- |
| `tools/psop_client.py`, `schemas/psop-client-descriptor-v1.schema.json` | PR-B SignedResult/receipt kimliklerini tüketen descriptor üretim/doğrulama ve `prepare_transaction`; immutable baseurls, external roots, inventory, bounded validity, local generation, atomic repo/state. | G-12; V3 discovery service varmış gibi sunulmaz; first-client freshness limitation kayıtlı. Production client rollout yok. |
| `tests/test_psop_client.py`, `tests/psop-fedora44-dnf5-e2e.py` | Gerçek Fedora 44 DNF5 install/upgrade ve client descriptor/state entegrasyonu; pinned upstream, tam selected+retained küme, imza/hash negatifleri. | Yanlış root/role/signature/hash, eksik/mixed/stale payload, metadata URL override, replay/rollback reddi ve hata halinde önceki repo/state korunması. |
| `tests/test_psop_provider_faults.py`, mevcut publisher testleri | PR-B ledger/outbox/gateway üzerinden delayed CAS, response-loss, concurrent writer, restart, eski Pages build ve stale/missing CDN member senaryoları. | #78 hâlâ açık ise testleri kopyalama/değiştirme; mevcut fixture'ları ve uygun exact-head diagnostic'i yeniden kullan. Model PASS provider garantisi değildir. |
| `tests/psop-pages-disposable-acceptance.py` ve disposable CI/test wiring | Ayrı yetkilendirilmiş disposable repository/origin üzerinde exact commit/build/deployment/run ve tam signed public HTTPS byte kabulü. | Production hedefler/secret'lar reddedilir; Pages ordering/deadline/global freshness garantisi çıkarılmaz. Production GitHub ayarları ve V2 writer workflow'ları değişmez. |
| Mevcut V2 Beta testleri ve PSOP entegrasyon regresyonları | Publication/rollback byte'ları, immutable history ve simulated V2/PSOP ortak gateway çatışmalarını gerçek PR-B koduyla tekrar doğrula. | G-03 disposable kabulü; canlı Beta cutover veya dispatch yapılmaz. |
| `docs/psop/OPERATOR-RUNBOOK.md`, `docs/psop/READINESS-REPORT.md` ve test evidence | Incident/UNKNOWN reconciliation, rollback/restore, risk kabulü ve custody geçiş checklist'i; exact commit/run/digest ile PASS/FAIL/UNVERIFIED/BLOCKED readiness raporu. | G-01..14 kanıt haritası ve unresolved blockers açık kalır; rapor veya runbook activation yetkisi değildir. |

PR-C, PR-B'nin uygulama kodunu kullanır; approval/signing/ledger/gateway geliştirmesini
başlatacağı aşama değildir. Test entegrasyonu için gereken adapter düzeltmeleri
disposable sınırı korumalıdır. B ve C kabulü sırasında production writer/secret,
V2 cutover ve activation kapalıdır; mevcut Strict V3 production guard'ı kaldırılmaz.

## Ayrı operatör aşaması: custody cutover ve canlı aktivasyon

PR-B/PR-C'nin tamamlanması yalnız implementation ve disposable kabul sağlar.
[G-01..14](ACTIVATION-GATES.md) için tüm kanıtlar ve açık operator yetkilendirmesi
olmadan production işlemi yapılamaz. Bu aşama şunları kapsar:

- Bütün gerçek V2/PSOP/manual/App/PAT writer'larının credential/custody envanteri,
  eski run/in-flight request drain kanıtı ve reviewed ortak gateway cutover'ı.
- Gerekli GitHub environment/ruleset/reviewer ayarları ve production signing
  provisioning/custody kabulü; mevcut secret değerlerini açığa çıkarma yetkisi vermez.
- Beta eşdeğerliği, production client/readiness ve risk kabulü doğrulandıktan sonra
  exact deployment için ayrıca açıkça yetkilendirilmiş canlı Stable aktivasyonu.

Gelecekteki production PSOP workflow ve mevcut dört V2 writer'ın canlı gateway
bağlantısı bu ayrı reviewed cutover'a aittir. PR-C'ye production geçişi önkoşulu
konulmaz. DNS, Cloudflare ve HP değişiklikleri varsayılan kapsama dahil değildir.
