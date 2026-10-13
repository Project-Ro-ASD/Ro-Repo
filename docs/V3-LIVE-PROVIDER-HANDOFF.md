# V3 canlı sağlayıcı operatör devri

**Karar: NON-PRODUCTION olarak birleştirme önerisi; üretim aktivasyonu BLOCKED.**
Başlangıç: `main`, `e49abd19b75a784c2a1bd375b23f33147c92ac24` (PR #74 sonrası).
Bu değişiklik hiçbir stable/beta kanalına yazmaz, production job açmaz, V2 workflow,
client yapılandırması, key, secret veya environment değiştirmez. Canlı bootstrap,
import, promotion, rollback ve Pages deploy çalıştırılmamıştır.

## Uygulanan kod ve yürütme sınırı

| İşlev | Uygulama | Bu PR'deki sınır |
| --- | --- | --- |
| Kimlik doğrulamalı sağlayıcı ulaşımı | `v3_provider_transport.ProviderTransport.request` | Operatörün callback ile verdiği süreli bearer; HTTPS CA/hostname doğrulaması; isteğe bağlı doğrulamalı mTLS context; redirect/proxy/retry yok; sınırlı JSON; HTTP hata ve sonucu belirsiz taşıma hatası ayrılır. Credential ömrü en fazla bir saat. Ortamdan secret keşfetmez. |
| GitHub kimliği, commit/tree/blob okuma | `GitHubStorage.identity/head/files/blob` | `https://api.github.com` ve bağımsız repository numeric ID/node ID/full name/ref pinleri. Truncated tree, unsafe mode, duplicate path, blob SHA/size uyuşmazlığı reddedilir. Gerçek API protokolü uygulanmıştır; canlı API kabul testi yapılmamıştır. |
| İmzalı immutable staging | `GitHubStorage.stage` | REST base64 blobs, tam tree ve deterministik commit üretimi. Bütün mevcut dosyaların blob kimliği korunur. Yalnız `v3/views/<digest>/...` ve `v3/publications/<attempt>.json` eklenir; mutable stable reklamı oluşturmaz. Yazımlar sadece private `/tmp/v3-backend-test-*` altında loopback protokol sunucusunda yürütülebilir. |
| Expected-head CAS | `GitHubStorage._cas` | GraphQL `updateRefs`, `beforeOid`, `afterOid`, `force=false`; işlem sonrası head kontrolü. REST read-then-write CAS gibi gösterilmez. No-op retry de CAS yapar. |
| Git yanıt kaybı sonrası uzlaştırma | `GitHubStorage.stage` | Aynı imzalı envelope + parent + tree + sabit author/committer zamanı aynı commit isteğini üretir. Yeniden başlatma mevcut head'i bu tam commit veya eski base ile karşılaştırır, staged bytes'ı yeniden okur. Başka head'i körlemesine overwrite etmez. |
| Kalıcı deployment isteği kimliği | `Outbox.deployment_identity` | Pre/post phase, commit, attempt, result, publication ve authorization hash'i signed DB/audit içinde saklanır. Yeni lease aynı kimliği okuyabilir; farklı commit/authorization çakışması reddedilir. Bu kayıt deployment başarısı değildir. |
| Pages durum okuma | `GitHubPages.status` | Bağımsız repository piniyle exact deployment ID üzerinden read-only API; `succeed` tek başına dağıtım kanıtı değildir. |
| Haricî publication/audit imzası | `ProtectedSigner.sign/envelope` | `/v1/sign` client; canonical domain/purpose ve lifetime kontrolü, bağımsız RSA public pin ile SHA256 imza doğrulama. Private key işlemi yok. `Ledger` audit ve `AuthorityClient` updater arayüzleriyle uyumlu. `IsolatedStore.stage/reopen` publication-purpose signer ile de çalışır; test-only scope korunur. |
| Korumalı onay/witness | `protected_authorization` | `/v1/approval` ve `/v1/witness` cevapları mevcut `verify_protected` üzerinden doğrulanır; exact proposal/result/evidence, reviewer/actor ayrımı, environment digest, run/attempt, workload hash ve süre sınırları korunur. |
| OIDC lifecycle | `workload_from_services` | `/v1/jwks-lifecycle` nonce-bound imza, bağımsız public pin; mevcut `lifecycle_oidc/verify_oidc` ile exact JWT claims, epoch, revocation ve cache age doğrulaması. Offline eski signed lifecycle sözleşmesi de korunur. |
| Independent checkpoint | `authority_client` | Mevcut `AuthorityClient` nonce-bound exchange protokolünü authenticated HTTPS `/v1/exchange` sınırına bağlar; reservation/checkpoint kuralları değiştirilmez. |
| Bağımsız deployment doğrulama | `IndependentDeployment.verify` | `/v1/deployment-observation` exact commit/origin/result/publication + nonce imzasını doğrular; sonra mevcut `HTTPSReader/verify_remote` ile her approved path ve envelope byte'ını okur. Post phase ayrıca signed stable advertisement ve ledger checkpoint bağını doğrular. Geç/görünmeyen veri tamamlanma sayılmaz. |
| Protected empty-state bootstrap | `observe_empty/authorize_empty/initialize_empty` | Depolama ancestry taraması, birbirinden ayrı storage/HTTPS observer root'ları, nonce-bound empty-state kanıtı, bağımsız human approval ve witness. Mevcut empty-ledger initializer'ına bağlanır; approval ve JTI tüketimi aynı initialization transaction'ındadır. İmzalama sırasında expiration olursa transaction rollback olur. |
| İlk yayın kurtarma değerlendirmesi | `interrupted_first_publication` | Signed ledger üzerinden önceki stable'ın gerçekten null olduğu ve aynı onayın geçerli olduğu kontrol edilir. Mevcut outbox devam ettirilir; ledger reset edilmez. |

Yeni schema uzantısı sadece `OUTBOX.receipts.deployment_requests.pre/post` içindir;
kimlik/binding alanları closed-schema ile doğrulanır. Envelope/domain ve publication
schema'sındaki `publishable=false` ve test-only scope değiştirilmemiştir.

## Hâlâ üretim aktivasyonunu reddeden işlevler ve kesin kod engelleri

1. `GitHubStorage._write_guard`: canlı REST object POST ve GraphQL ref mutation
   BLOCKED; sadece loopback disposable factory yürütür. Git staging primitive'i
   uygulanmıştır ama canlı writer authority değildir.
2. `GitHubStorage.advertise`: GitHub ref CAS, provider'ın işlem anındaki worker
   lease/fence kontrolünü sağlamaz. Stable advertisement BLOCKED.
3. `GitHubPages.request`: native Pages API'de durable idempotency key,
   monotonic fencing token, lease deadline veya expected-current deployment
   alanı belgelenmemiştir. Bu eksik garantiler taklit edilmez; POST yoktur.
4. Mevcut `Coordinator` yalnız `IsolatedGitStore` kabul eder; production
   coordinator wiring açılmamıştır. `Backend`, `ProductionPostgreSQLAdapter.transaction`,
   `production_publish`, `writer_gate` ve client'ın disposable-root korumaları açık kalır.
5. `IsolatedStore` ve immutable-publication schema test-only'dir. Üretime geçişte
   imzalı scope ve backend/client acceptance ayrı, onaylı cutover değişikliği gerektirir.
6. Süresi dolmuş **ilk** PUBLISHED attempt için `Backend.create(operation='recover')`
   önceki POST_VERIFIED immutable view ister. İlk stable'da böyle bir view yoktur.
   Yeni onay eski authorization hash'ine bağlı publication/outbox kaydının yerine
   geçirilemez. `interrupted_first_publication` bu nedenle BLOCKED döner/hata verir.
   Exact-result, yeni workload/JTI ve yeni approval/witness'i eski attempt'in
   değişmez kayıtlarını koruyarak bağlayan, ayrı incelenmiş reauthorization
   transition henüz uygulanmamıştır. Fresh authorization olmadan devam edilmez.
7. `import_existing` canlı import'u reddeder. Gerçek stable tarihi bulunursa
   mevcut `v3_migration.rehearse/assert_preserved` yolu, authentic legacy evidence,
   client kabulü ve protected cutover gerekir; boş bootstrap yolu kullanılamaz.

**Pages uyumsuzluğu:** GitHub'ın [GraphQL Git sözleşmesi](https://docs.github.com/en/graphql/reference/git)
`beforeOid` ile atomic ref değişimini belgeliyor. [Pages API sözleşmesi](https://docs.github.com/en/rest/pages/pages)
artifact, environment, build version ve OIDC girdilerini belgeliyor. Buradan
çıkardığımız teknik sonuç: ref CAS eski Git head'i reddedebilir fakat lease sona
erdikten sonra ulaşan ilk isteği, daha yüksek fence gelmeden kendiliğinden
reddedemez. GitHub `clientMutationId` veya `pages_build_version` için required
fencing/idempotency garantisi varsayılmıyor. Cancel ya da Actions concurrency
zaten gecikmiş bir isteği provider mutation sınırında güvenli biçimde fence etmez.

Bu PR başka hosting sağlayıcısı seçmez. Gerekli garanti GitHub tarafından kabul
edilmiş bir sözleşmeyle veya ayrı onaylanmış yayın sınırıyla gerçekten sağlanmadan
native Pages üretim yolu açılamaz. Böyle bir sınırın servis uygulaması bu depoda
mevcut değildir; yalnız client bağları yazılmıştır.

## Provision edilmesi gereken dış servisler ve yetkiler

Önce [mevcut provisioning sözleşmesini](V3-CLOSURE-PROVISIONING.md) ve
[production activation checklist](V3-PRODUCTION-ACTIVATION-CHECKLIST.md) uygulayın.
Aşağıdaki client endpoint'leri GitHub/Vault/KMS endpoint'iymiş gibi sunulmaz;
operatörün sağlayacağı korumalı servis protokolüdür. Ortak envelope domain'i
`ro-repo-v3-backend-1`, imza RSA/SHA256 ve public pinler bağımsız dağıtılır.

- GitHub App installation credential broker: staging için sadece seçilmiş depo
  `Contents:write`, `Metadata:read`; ayrı read-only observer için `Contents:read`.
  Pages status okuyucusuna ayrı `Pages:read`. Bu PR hiçbir `Pages:write`
  credential'ı istemez veya kullanmaz. Runner'a doğrudan stable/Pages writer token
  vermeyin; gerçek fence kontrolünü sağlayacak yetki sınırı önce kabul edilmelidir.
  Runtime credential callback `(token, expires_at)` döndürür, refresh broker'ın
  sorumluluğudur. Kaynak kod/config içinde token saklanmaz.
- Ayrı failure/restore domain'inde PostgreSQL 18: pinned CA ve certificate SAN,
  `verify-full`, restricted `ro_v3_writer`; DDL yalnız NOLOGIN owner/DBA. Writer'ın
  events/consumed/views üzerinde UPDATE/DELETE/TRUNCATE yetkisi yoktur.
  `provisioning_sql()` inceleme artifact'ıdır. WAL/backups/restore/failover ve
  replication kabulü ayrıca yapılmalıdır; sadece TLS PASS yetmez.
- Checkpoint/history authority: `/v1/exchange`, bağımsız monotonic durable CAS,
  reservation protokolü, nonce-bound read, immutable history genesis. History
  observer gerçek beta availability'yi gözleyip güncel UTC atar; eski V2 zamanı
  V3 dwell diye import edilmez. Minimum JWKS epoch aynı runner backup'ında tutulmaz.
- JWKS lifecycle authority: `/v1/jwks-lifecycle`, nonce/issuer/jwks_sha256 isteği;
  cevap bunları ve epoch/fetched_at/revoked_kids/issued_at/expires_at bağlar.
  `jwks-lifecycle` rolünün ayrı root'u kullanılır. Unknown/revoked/stale kid reddedilir.
- Human approval service: `/v1/approval` mevcut request + authenticated evidence
  digest alır, bunlara reviewer_id ve lifetime bağlayarak `human-approval` imzalar.
  Gerçek, izinli ve actor'dan farklı insan onayı gerekir; API `approved=true`
  veya workflow success üretme yetkisi sağlamaz.
- Environment witness: `/v1/witness`; doğrulanmış human envelope, workload hash,
  environment config digest, run/attempt/reviewer ve decision bağlarını bağımsız
  doğrular, `protected-environment-witness` imzalar. İstek içindeki actor/env iddialarını
  körlemesine imzalamaz; OIDC token/service authentication ve gerçek protected
  environment kararını independently kontrol eder.
- Signing boundary: `/v1/sign`, request `{purpose, context, nonce, data, sha256}`;
  data base64url exact canonical unsigned bytes. Response
  `{nonce, sha256, key_sha256, signature}`. Server HSM/KMS custody altında
  publication/audit/updater için ayrı purpose/ACL uygular. Publication context'inde
  exact proposal/result/preflight/evidence, original approval/witness ve workload
  binding'i server tarafından doğrulanır; kısa ömür ve revocation server'da
  kontrol edilir. Client imzanın doğruluğunu doğrular ama key custody, server policy
  ve gerçek human consent'i provisioning yerine sağlayamaz. Audit bytes'ın domain'i
  `ro-repo-v3-audit-1`; publication/updater başka rol adına imza isteyemez.
- Deployment observer: `/v1/deployment-observation`, nonce/origin/result/publication/
  exact commit isteği; aynı alanlar + bağımsız deployment_id + lifetime imzalanır.
  Provider run/status ve actual HTTPS bytes bağımsız gözlenir. Receipt issuer,
  publisher ve storage writer'dan ayrı olmalıdır. Bir Git commit deployment ID değildir.
- Bootstrap için **iki ilave bağımsız root**: storage observer ve HTTPS observer.
  `/v1/empty-stable` cevabı exact database/schema/storage_commit/inventory digest,
  remote evidence digest, origin, history digest, nonce, observation kind,
  `stable_absent=true`, `writer_exclusive=true` ve lifetime bağlar. Storage observer
  tüm refs/retained history ve writer yetkilerini; HTTPS observer pinned public
  origin, deployment identity, mevcut/önceki stable yokluğunu gözler. İkisi aynı
  `remote_sha256` evidence bundle'ını independently kabul etmelidir. Genel 404,
  auth failure, missing branch, eksik tree veya force-deleted Git tarihi absence
  kanıtı değildir. Reachable ancestor scan deleted stable'ı da reddeder; unreachable
  history ve geçmiş deployment kayıtları dış retention audit'inin sorumluluğudur.
- Discovery ve restore-observation servisleri mevcut sözleşmeleriyle ayrıca
  provision edilmelidir. Restore observer gerçek noncommit + fenced writers
  kanıtı olmadan reservation temizlemez; discovery sadece POST_VERIFIED sonucu sunar.

Mevcut `verify_root_set` içindeki 12 role bağımsız canonical key pinleri sağlanır;
bootstrap iki observer root'u bunlardan ve approval/witness/audit root'larından
ayrı tutulur. Production private key, JWT, bearer, certificate private key veya
password bu PR'de üretilmedi, kullanılmadı ve depoya eklenmedi.

`repo-stable` ve `repo-production-signing` environments için authorized reviewer
IDs, prevent-self-review, main-only branch policy, bypass-disabled ayarları ve
normalized config digest operatörce provision edilir. OIDC issuer, audience,
verbatim subject, repository/owner IDs, ref, source/workflow/reusable workflow
SHA, run/attempt ve actor pinleri gerçek dağıtım için yeniden doğrulanır.
Bu PR yeni bir production signer workflow SHA'sı uydurmaz.

## Güvenli dağıtım ve bağımsız kabul sırası

1. Production job'ları kapalı tutarak servisleri staging domain'lerinde kurun;
   publisher/approval/witness/checkpoint/observer yöneticilerini ve key custody'yi
   ayırın. Server'larda bounded request, doğrulanmış mTLS/bearer, trusted UTC,
   denied-role testleri, durable storage ve redacted logs uygulayın.
2. Public trust pinlerini ayrı kanaldan dağıtın; response içindeki key'e güvenmeyin.
   Her role için yanlış key/purpose, revoked OIDC, stale epoch, wrong audience,
   self-review ve exact-result substitution isteklerinin reddini independently test edin.
3. Disposable GitHub deposunda seed edilmiş bir ref üzerinden gerçek REST blob/tree/
   commit ve GraphQL `beforeOid` kabulünü test edin. Bu PR'nin mutation factory'si
   loopback dışını reddeder; gerçek disposable GitHub write acceptance için ayrı
   incelenmiş test runner gerekir. Production deposu veya `pages-storage` kullanılmaz.
4. Gelecek fenced deployment sınırını gerçek sağlayıcıda test edin: lease süresi
   dolana kadar request'i geciktirin; yeni worker henüz gelmese de stale isteğin
   provider tarafından reddedildiğini gösterin. İki eşzamanlı publisher ve kayıp
   response/restart için aynı request identity'nin tek durable sonucu olmalıdır.
   Native Pages bu acceptance için şu an uyumsuzdur.
5. PostgreSQL+checkpoint için backup restore, commit öncesi/sonrası process death,
   independent reservation response loss, DB-behind restore ve stale abort evidence
   deneylerini yapın. Dış monotonic state rollback olmamalıdır.
6. Empty/bootstrap testlerini yalnız disposable DB/repo/domain'de yapın. Storage
   ve HTTPS kanıtlarına gerçek stable geçmişi ekleyip bootstrap'ın reddini gösterin.
   İmzalama sırasında onayı expire edin; initialization'ın rollback ve tüketilmemiş
   durumda kaldığını doğrulayın. Sonra yeni bağımsız evidence ve fresh approval alın.
7. Her approved RPM/metadata/SRPM/publication byte'ını HTTPS üzerinden pre ve post
   aşamalarda independently ölçün. CDN gecikmesi tamamlanma değildir. Histories ve
   beta'nın bütün önceki signed byte'larını karşılaştırın; değişen bir byte reddedilir.
8. Gerçek x86_64/aarch64 native/hardware/full-set client kabulü ve immutable discovery
   rollout'u tamamlanınca, V2 writer retirement ve production scope/adapter wiring
   için **ayrı protected cutover PR** hazırlayın. Bu PR hiçbir cutover yapmaz.

## Bu PR'nin testleri ve kanıtın sınırı

`tests/test_v3_live_provider.py` gerçek HTTP taşıması ve gerçek bare-Git object/ref
işlemleri kullanan disposable protocol double üzerinden çalışır. GitHub cloud,
Pages CDN, protected-reviewer hizmeti veya üretim HSM kabulü değildir.

```bash
python3 -m unittest discover -s tests -p 'test_v3_live_provider.py' -v
python3 -m unittest discover -s tests -v
bash tests/v3-closure-postgres-e2e.sh /tmp/new-disposable-pg-evidence
bash tests/v3-integration-e2e.sh /tmp/new-disposable-fedora-evidence
```

Son iki komut disposable Fedora 44 container içinde çalıştırılır. Mevcut CI'de
`unit-policy` ve V3 `security-contracts` yeni test dosyasını discovery ile çalıştırır;
Fedora 44, V2, PostgreSQL ve V3 jobs değiştirilmemiştir. CAS yarışları, stale head,
kayıp CAS response, auth/signing expiration, historical bytes, empty bootstrap,
nonce replay, delayed lease worker, durable request/restart ve first-publication
interruption testleri eklenmiştir. Mevcut closure crash matrix'e `before-git-stage`
eklenmiştir; after-stage/DB-intent/Git-advertisement/post-verification matrisi korunur.

Test sonuçları ve exact CI run URL'leri `docs/evidence/v3-live-provider/` altında
raporlanır. Dış sistemlerin production acceptance durumu **UNVERIFIED** kalır.

## İlk stable için net yanıt

**Yalnız provisioning ve onayların tamamlanması yeterli değildir.** Geçerli onay
penceresinde authenticated-empty initialization ve interrupted-first-publication
outbox recovery disposable ortamda uygulanabilir ve test edilmiştir. Ancak native
Pages fencing/idempotency uyumsuzluğu, production adapter/coordinator/schema
cutover guards ve expired-first-publication reauthorization transition kod engelleri
çözülmeden gerçek ilk stable teknik olarak açılmaz. Gerçek history bulunduğunda
empty bootstrap yerine protected migration gerekir. Beta dwell yeni gözlem
zamanından başlar; hızlı geçiş gerekirse yalnız mevcut explicit fast-track politikası
ve gerçek korumalı onayı kullanılabilir. Sahte geçmiş dwell üretilemez.
