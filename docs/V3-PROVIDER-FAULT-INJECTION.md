# V3 adversarial provider kabulü — yalnız yerel disposable test

Bu çalışma üretim kodunu, güvenlik kilitlerini, `pages-storage` veya yayın
workflow'larını değiştirmez. Gerçek GitHub/Pages isteği, RPM terfisi veya production
aktivasyonu çalıştırmaz. Operatörün bildirdiği başarılı disposable cloud kabulü
commit/CAS, build/deployment/run identity ve o anda 5/5 HTTPS byte eşleşmesini
gösterir; deadline fencing veya gelecekteki build sırasını kanıtlamaz. Cloud sonucu
burada yeniden çalıştırılmadı ve yeni yerel test kanıtıyla karıştırılmadı.

## Önceki kapsama envanteri ve eksik sınırlar

| Risk | Halihazırda mevcut test | Bu PR'daki karar |
| --- | --- | --- |
| Geç CAS / authority expiry | `test_v3_live_provider.test_delayed_staging_response_after_expiration_cannot_update_ref`; `test_v3_pages_finalization.test_expired_worker_request_arriving_over_http_has_no_git_effect`, `test_lease_expiring_during_upload_is_checked_again_before_cas`, `test_lease_expiring_during_admission_audit_rolls_back_before_git_cas` | Admission öncesi korumalar zaten var. Yeni test yalnız durable admission **sonrasında** provider kuyruğunda bekleyip approval sona erince uygulanan CAS'ı ekler. |
| Commit kabul edildi, yanıt kayboldu | `test_v3_live_provider.test_lost_cas_response_reconciles_after_client_restart`; `test_v3_pages_finalization.test_lost_git_response_reconciles_durable_service_owned_intent`, `test_lost_advertisement_response_reconciles_without_resigning_or_ref_retry` | Genel response-loss testi tekrar eklenmedi. Geç CAS karşı örneğinde kayıp yanıt ile expiry/restart birleşimi sınandı. |
| Aynı HEAD'de iki publisher | `test_v3_live_provider.test_simultaneous_different_publishers_have_one_git_cas_winner`; `test_v3_pages_finalization.test_two_distinct_publishers_share_one_storage_admission_realm`; `test_v3_backend_adversarial_review.test_two_independent_git_writers_have_one_cas_winner` | Mevcut REST/GraphQL testi güçlendirildi: ayrı adapter'lar ve `before_cas` barrier ile her iki istek aynı HEAD'den hazırlanır; iki farklı target ve tek kazanan doğrulanır. |
| Eski Pages build yeni build'den sonra görünür | `test_v3_pages_finalization.test_branch_build_deployment_and_run_identity_match_exact_commit`, `test_discovery_rejects_out_of_order_or_missing_immutable_public_bytes` | Önceki testler yanlış identity / tek missing-byte fault içeriyordu. Yeni test gerçek disposable Git snapshot'larıyla başarılı yeni POST_VERIFIED build'den **sonra** eski build'i tamamlar. |
| Gecikmeli/eski CDN içeriği | `test_v3_pages_finalization.test_success_api_with_missing_public_bytes_is_not_deployment_verification`; backend mixed/corrupt-view ve client hash testleri | Yeni test publication envelope, signed advertisement ve beş payload üyesini ayrı ayrı missing/stale yapar: 14 deterministik fault. Post-verification'ın eksik bir üyeyi atlamadığı doğrulanır. |
| Kesinti sonrası restart/uzlaştırma | `test_v3_pages_finalization.test_existing_coordinator_disposable_branch_factory_restarts_after_intent`; `test_v3_backend_adversarial_review.test_recovery_interruptions_at_every_ledger_transition`; PostgreSQL process-death testleri | Mevcut `after-db-intent` sınırı tekrar eklenmedi. Branch coordinator için kalan dört dış-I/O sınırında yeni Ledger/Backend/provider nesneleriyle persisted state yeniden açılır. |
| Önceki immutable dosyalar | `test_v3_pages_finalization.test_branch_staging_and_signed_records_preserve_all_previous_bytes`; `test_v3_live_provider.test_authenticated_rest_objects_graphql_cas_preserve_signed_history` | Genel preservation testi tekrar eklenmedi. Yeni her senaryoda eski view'in beş dosyası, signed publication envelope ve beta/history marker byte'ları yeniden karşılaştırılır. Yarışta kaybedenin publication'ı branch'e girmez. |

Dosya adlarındaki test method'ları ilgili test sınıfı içindedir. Yeni kapsam:
`tests/test_v3_provider_fault_injection.py`; güçlendirilen mevcut yarış:
`tests/test_v3_live_provider.py`.

## Deterministik mekanizma ve kanıt sınırı

Provider istekleri mevcut `ProtocolServer` üzerinden loopback HTTP'ye gider;
blob/tree/commit ve expected-head CAS gerçek private disposable bare Git üzerinde
çalışır. Deadline, test clock'u ile ilerletilir; duvar saati sleep'i kullanılmaz.
`Event` CAS'ı uygulamadan önce tutar, `Barrier` iki publisher'ı aynı HEAD'de hazır
eder. Beklemelerin timeout'u yalnız hang/cleanup sınırıdır; test sırası scheduler
veya timeout'a bağlı değildir.

`ControlledPages` exact build/deployment/dynamic-run API kayıtlarını ve public
snapshot seçimini ayrı tutar. Public opener double gerçek `HTTPSReader` ve
`BranchHTTPSReader` URL üretimini, publication/payload hash'lerini, signed
advertisement doğrulamasını ve client state korumasını çalıştırır. Başarılı yeni
API kayıtları, eski public snapshot görünür olduğunda silinmez. Burada TLS, gerçek
CDN cache davranışı veya gerçek bağımsız witness denenmez. Tüm payload'lar synthetic;
envelope'lar geçici test anahtarlarıyla imzalıdır.

Restart testleri `after-git-stage`, `after-pre-verification`,
`after-git-advertisement`, `after-post-verification` noktalarında kontrollü exception
ile çağıranı keser. Yeni Ledger/SQLiteAdapter/Backend/provider nesneleri aynı signed
kalıcı durumu açar. Bu yeni testler gerçek OS process-kill testi değildir; mevcut
PostgreSQL process-death testlerinin yerine geçmez. İlk tamamlama sonrası tekrar
çağrıda ek POST, CAS veya yeniden imza olmaz. Toplam CAS sayısı archive + stage +
advertisement = üç olarak kontrol edilir.

## Senaryo sonucu: kod koruması ile sağlayıcı garantisi ayrı

**PASS**, belirtilen yerel assertion'ın geçtiğini anlatır. **UNVERIFIED**, canlı
sağlayıcı garantisinin kanıtlanmadığını; **BLOCKED**, bu garantiye ihtiyaç duyan
üretim davranışının kapalı kaldığını anlatır. Beklenen zararlı interleaving'in
yeniden üretilmesi, zararın sağlayıcı tarafından önlendiği anlamına gelmez.

| Senaryo | Kod / yerel test sonucu | Gerçek sağlayıcı değerlendirmesi |
| --- | --- | --- |
| 1. Geç CAS ve approval expiry | **PASS**: admission geçerliyken kaydedilir; App credential geçerli kalır; kuyruktaki CAS approval bittikten sonra uygulanabilir. Base HEAD UNKNOWN'u çözmez. Kayıp yanıt sonrası exact target CONFIRMED olur; attempt STAGED kalır, discovery ve yeni expired işlem reddedilir. | Per-request approval deadline fencing **UNVERIFIED**. Strict deadline ve production activation **BLOCKED**. |
| 2. Kabul sonrası yanıt kaybı | **PASS**: durable IN_FLIGHT intent exact target üzerinden uzlaştırılır; kör replay veya kayıp yanıttan success çıkarımı yapılmaz. Advertisement response-loss testi orijinal signed byte'ları korur. | HTTP cevabının ulaşması / exactly-once response **UNVERIFIED**. `clientMutationId` idempotency garantisi sayılmaz. |
| 3. Aynı HEAD'de yarış | **PASS**: iki farklı prepared target için aynı `beforeOid`, iki CAS isteği, tek kazanan; tarih korunur. Shared ledger admission gate ayrıca mevcut testlerle korunur. | Expected-head atomic CAS belgelenmiş primitive'dir. Bütün credential/writer'ların bizim gate'ten geçtiği production exclusive custody **UNVERIFIED/BLOCKED**. |
| 4. Eski build'in geç tamamlanması | **PASS**: model eski public snapshot'ı yeni POST_VERIFIED build'den sonra görünür yapabilir. Latest API identity hâlâ başarılıdır; public verification ve client update reddeder, client repo/state ve ledger geriye dönmez. | Pages completion/visibility ordering **UNVERIFIED**; sürekli latest visibility ve production cutover **BLOCKED**. |
| 5. Gecikmeli veya eski CDN üyesi | **PASS**: 14 missing/stale fault POST_VERIFIED/discovery oluşturmaz. Tüm doğru byte'lar geri gelince fresh window içinde retry geçer. | CDN atomik görünürlük, cache freshness ve sürekli erişilebilirlik **UNVERIFIED**. Byte reddi erişilebilirlik garantisi değildir. |
| 6. Kesinti/restart | **PASS**: dört yeni dış-I/O sınırı ve mevcut DB-intent/response-loss sınırları persisted proof'larla tamamlanır; exact replay ilave CAS/POST üretmez. UNKNOWN+base HEAD otomatik abort olmaz. | Native provider noncommit/request-drain kanıtı **UNVERIFIED**. Böyle bir kanıt yoksa successor / fresh reauthorization **BLOCKED**. |
| 7. Önceki immutable dosyalar | **PASS**: geç CAS, response-loss, race, reordered public snapshot, CDN fault ve restart sırasında önceki Git blob byte'ları korunur. | Preservation bizim append-only tree/comparison kontrolümüzdür; CAS tek başına whole-tree byte preservation veya CDN'de sürekli bulunurluk garantisi vermez. |

## Resmî sağlayıcı sözleşmesi ve çıkarım

- [GitHub GraphQL Git / updateRefs](https://docs.github.com/en/graphql/reference/git#updaterefs)
  atomic expected-head güncellemesini belgeler. `UpdateRefsInput` / `RefUpdate`
  içinde uygulamamızın approval deadline/worker fence alanı bulunmuyor.
  **Çıkarım:** local admission guard bu native API çağrısının uygulama anına deadline
  ekleyemez. Buradaki kuyruk karşı örneği izin verilen bir interleaving'dir; canlı
  GitHub'da bu sıranın gözlendiği iddia edilmez.
- Aynı referans `clientMutationId` alanını bir identifier olarak tanımlar.
  Tek başına durable idempotency veya exactly-once commit sözleşmesi çıkarılmaz.
- [Pages REST](https://docs.github.com/en/rest/pages/pages) ve
  [branch publishing source](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
  build/deployment gözlemlerini sağlar; exact API success, her public byte'ın o
  snapshot'tan geldiğine dair kanıt yerine kullanılmaz.
- [Actions concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
  job scheduling'i kontrol eder; ordering dispatch zamanına göre garanti edilmez.
  Queue/FIFO veya workflow cancellation'dan branch Pages/CDN visibility ordering
  garantisi çıkarılmaz. Workflow'lar bu PR'da değiştirilmedi.

## Gerekli mimari değişiklikler — bu PR etkinleştirmez

1. Strict deadline için doğrulama yalnız worker girişinde yeterli değildir:
   mutation'ın uygulanacağı sınırda approval expiry ve authority epoch/fence'i
   atomik kontrol eden sözleşme gerekir. Native GitHub `updateRefs` bu sözleşmeyi
   taşımıyor. Daha uzun approval/App token süresi veya tekrar client check'i
   çözüm sayılmaz. Bu kontrat aynı stack üzerinde gösterilemiyorsa strict
   production requirement BLOCKED kalmalıdır.
2. Bütün beta/stable writer'lar tek admission realm ve exclusive credential
   custody altında olmalıdır. UNKNOWN istek varken successor açılmaz. Base HEAD
   veya timeout drain kanıtı değildir; ayrı güven köküyle exact intent/checkpoint
   + gerçekten fenced/drained/noncommit observation gerekir. Kanıt üretilemiyorsa
   `abort_noncommit` için imza verilmemelidir.
3. Public cutover için build tamamlanması ile monotonik görünürlük farklı
   sözleşmelerdir. Deployment execution/cutover sınırında generation fence, önceki
   in-flight build'lerin gerçekten durduğu/drain edildiği kanıtı ve sonrasında
   public-byte probes gerekir. Native branch Pages bu kontratı göstermedikçe
   current API status/concurrency yeterli sayılmaz. Immutable view + bağımsız
   fresh discovery + client hash kontrolleri bütünlüğü korur; missing view'de
   BLOCKED davranışı ve erişilebilirlik engeli açıkça korunmalıdır.
4. Production TLS/mTLS publisher ingress, bağımsız checkpoint/witness rolleri,
   durable service recovery ve gerçek dış kabul ayrı reviewed activation işidir.
   Bu PR provider veya production protokolünü değiştirmez ve bu engelleri PASS'a
   çevirecek yeni bir receipt alanı üretmez.

## Çalıştırma

```bash
python3 -m unittest discover -s tests -p 'test_v3_provider_fault_injection.py' -v
PYTHONPATH=tests:tools python3 -m unittest \
  test_v3_live_provider.LiveProviderTests.test_simultaneous_different_publishers_have_one_git_cas_winner -v
python3 -m unittest discover -s tests -v
```

Test ortamı loopback sockets, Git, OpenSSL ve Python jsonschema/yaml gerektirir.
Private disposable Fedora test konteynerinde dış ağ kapalı tutulabilir. Mevcut CI
full/V3 security discovery bu dosyayı zaten kapsar; yeni workflow gerekmez.
Eski V2/V3 signed fixture E2E, native DNF5 URL rejection, PostgreSQL CAS/TLS ve
runtime job'ları mevcut PR CI tarafından ayrıca çalıştırılır.
