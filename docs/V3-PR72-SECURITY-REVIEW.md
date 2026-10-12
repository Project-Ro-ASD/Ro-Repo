# PR #72 adversarial güvenlik incelemesi

İlk incelenen head: `5905b4a8cad65114d72c0df28d1544ede4fdfcde`.
Karşılaştırılan `main`: `fc18d9b3d5cb861358a30bed22b0337c78743741`.
Dal: `feature/v3-production-backend-complete`; PR: [#72](https://github.com/Project-Ro-ASD/Ro-Repo/pull/72).
Tarih: 2026-10-12. Son implementation/test commit'i:
`12d0d1a6efe02e4bda1ec882649f6134b6646fdd`.

**Dokuz doğrulanmış kusur: sekiz MEDIUM, bir LOW; tamamı düzeltildi.**
CRITICAL/HIGH üretim yetkisi bypass'ı doğrulanmadı. Dereceler mevcut izole
mimarinin bütünlük, sözleşme ve kullanılabilirlik etkisine göre verilir.
Başlangıç head'i düzeltmesiz merge önerisi almamalıdır. Düzeltilmiş sürüm yalnızca
**NON-PRODUCTION integration milestone** olarak değerlendirilebilir.
Üretim stable aktivasyonu **BLOCKED** kalır.

V3 sözleşmesi, önceki PR71 güvenlik raporu, backend raporu, aktivasyon checklist'i,
V2 migration planı; PR72'nin on yeni backend modülü, değiştirdiği DNF validator,
altı yeni schema, backend/Pages/input testleri ve workflow değişiklikleri kod ile
karşılaştırıldı. Sadece doküman PASS iddialarına dayanılmadı.

## Doğrulanmış bulgular

Aşağıdaki kusur satırları ilk `5905b4a` head'ine aittir. Düzeltme satırları son
implementation'a aittir. Regresyonlar `tests/test_v3_backend_adversarial_review.py`
içindedir. Kullanılan package planları synthetic fixture'dır; RSA imzaları, Git
commit/ref işlemleri ve ayrıca belirtilen PostgreSQL/DNF işlemleri gerçektir.

### F1 — MEDIUM: authorization süresi staging ve transaction bitiminde korunmuyor

- Konum: `tools/v3_publication_backend.py:149`, `:160`, `:111`;
  `tools/v3_backend_ledger.py:190` ve `:195`.
- Kök neden: `STAGED`/remote aşamaları kayıtlı authorization deadline'ını
  denetlemiyor. AUTHORIZED giriş kontrolü audit signer gecikmesinden önce kalıyor.
- Senaryo: SIGNED geçtikten sonra authorization expire olur; STAGED yine yazılır.
  Başka durumda audit imzası sırasında deadline geçer, approval/JTI tüketimi ve
  AUTHORIZED event'i birlikte commit edilir. Tek transaction olması tazelik sağlamaz.
- Yeniden üretim: `test_expired_authorization_cannot_advance_staging` ve
  `test_expiry_during_audit_signing_rolls_back_consumption`. İlk sürümde ikisi
  **FAIL**; injection signer sonunda trusted clock'u deadline'a taşır.
- Minimum düzeltme: state değişikliklerinde ilgili deadline'ı kullan; audit
  imzasından önce ve sonra, commit öncesinde aynı transaction içinde guard çalıştır.
  Hata bütün state/replay/audit değişikliklerini rollback etsin.
- Patch: `6d44221`; `Ledger.execute` guard'ı `tools/v3_backend_ledger.py:193`,
  `:201`; state guard'ları `tools/v3_publication_backend.py:167`, `:180`, `:199`.
- Sonuç: iki regresyon **PASS**; gerçek PostgreSQL'de slow signer/deadline ve üç
  consumption/audit interruption sınırı da atomik rollback **PASS**.
- Sınır: DB transaction bitiminden sonraki Git/Pages işlemiyle ortak atomik saat
  veya dağıtık lease garantisi verilmez.

### F2 — MEDIUM: eskimiş pre-verification ile publication intent yazılabiliyor

- Konum: `tools/v3_publication_backend.py:184` ve `:193`.
- Kök neden: REMOTE_VERIFIED'da denetlenen 60 saniyelik freshness PUBLISHED'da
  tekrar kontrol edilmiyor; yalnızca approval expiration kontrol ediliyor.
- Senaryo: remote check'ten 61 saniye sonra, 300 saniyelik approval hâlâ geçerli
  olduğundan stale deployment proof ile head/generation değişir. Git adapter'ın
  ayrıca reddetmesi, DB intent'in yanlış yazılmış olmasını geri almaz.
- Yeniden üretim: `test_stale_pre_verification_cannot_publish`; ilk sürüm **FAIL**.
- Minimum düzeltme: kayıtlı pre-verification yaşını locked publication işlemi ve
  audit sonrası commit guard'ında tekrar denetle.
- Patch: `6d44221`; `tools/v3_publication_backend.py:208` ve `:222`.
- Sonuç: regresyon **PASS**, reddedilen işlemde ledger/checkpoint değişmez.
  Süresi dolan proof'un sessiz yenilenmesi uygulanmadı; yeni yetkili attempt gerekir.

### F3 — MEDIUM: audit ve approval/witness anahtarları aynı olabilir

- Konum: `tools/v3_publication_backend.py:115`; `v3_backend_evidence` sadece
  approval ile witness anahtarlarının birbirinden farklı olduğunu denetliyordu.
- Kök neden: belgelenen audit/authorization rol ayrımı consumption sınırında yok.
- Senaryo: audit public key aynı zamanda human approval root olarak provision
  edilir. O key ile gerçek imzalı approval ve bağımsız witness, Backend tarafından
  tüketilir. Böyle bir konfigürasyon audit key'in korunmasını human approval rolüne
  de bağımlı yapar; ayrı kök şartı uygulanmamış olur.
- Yeniden üretim: `test_audit_key_cannot_also_authorize_human_approval`; gerçek
  audit-key approval yeniden imzalanır, witness hash'i ona bağlanır; ilk sürüm **FAIL**.
- Minimum düzeltme: consumption öncesinde canonical RSA identity üzerinden
  audit key'i approval ve witness key'lerinden ayır. PEM byte farkına güvenme.
- Patch: `f297130`; `tools/v3_publication_backend.py:129`.
- Sonuç: regresyon **PASS**; yetki/replay kayıtları değişmez. Tek başına audit key
  kompromisinin bağımsız witness veya canlı environment bypass'ı olduğu iddia edilmez.

### F4 — MEDIUM: no-op Git staging retry CAS yapmadan başarı dönüyor

- Konum: `tools/v3_pages_backend.py:93` ve `:94`.
- Kök neden: yeni tree eskiyle eşitse başlangıç HEAD kontrolünden sonra ref CAS yok.
- Senaryo: ikinci writer tree hesaplaması sırasında ref'i ilerletir. İlk writer
  eski commit'i güncel staging başarı kaydı olarak döndürür; race reddedilmez.
- Yeniden üretim: `test_noop_staging_retry_still_performs_ref_cas`; aynı disposable
  bare Git üzerinde ikinci store ref'i değiştirir; ilk sürüm **FAIL**.
- Minimum düzeltme: no-op retry'da da `update-ref ref expected expected` kullan.
- Patch: `b8c2c20`; `tools/v3_pages_backend.py:95`.
- Sonuç: regresyon **PASS**; ayrıca iki bağımsız process ile gerçek Git ref
  yarışında yalnızca bir CAS kazananı **PASS**. Kazananın commit'i ezilmez.

### F5 — MEDIUM: yanlış advertisement imzası Git ref'ine commit ediliyor

- Konum: `tools/v3_pages_backend.py:142` ve `:143`.
- Kök neden: signing sonucunun bağımsız public pin ile doğrulanması CAS'ten önce yok.
- Senaryo: doğru public pin'i olan signer arızalanıp başka key ile gerçek imza
  döndürür. İmzası geçersiz `v3/stable.json` güncel ref'e yazılır; sonraki verifier
  fail-closed davranır fakat advertisement kullanılabilirliği zaten bozulmuştur.
- Yeniden üretim: `test_advertisement_signer_failure_cannot_move_ref`; signer
  callback'i başka ephemeral RSA key'i kullanır; ilk sürüm **FAIL**.
- Minimum düzeltme: yeni advertisement envelope'unu expected record ve pinned
  key ile doğrula, bundan sonra ref CAS yap.
- Patch: `5ebc41d`; `tools/v3_pages_backend.py:145`.
- Sonuç: regresyon **PASS**, ref staged commit'te kalır. Audit imzası için PR72'de
  daha önce yapılmış `895e945` düzeltmesi korunur.

### F6 — MEDIUM: Git uzak okuması witnessed commit'e sabitlenmemiş

- Konum: `tools/v3_pages_backend.py:154`; `tools/v3_immutable_view.py:251`, `:259`.
- Kök neden: her dosya ayrı current HEAD'den okunuyor; deployment claim'deki
  commit'in okunan commit olduğu denetlenmiyor.
- Senaryo: doğru artifact/publication digest'leri olan başka commit'e ait signed
  deployment kullanılır veya doğrulama sırasında ref ilerler. Byte karşılaştırması
  aynı immutable dosyaları görebilir, fakat başka deployment kimliğiyle remote
  receipt verir. Bu receipt bir current-ref tutarlılık kanıtı değildir.
- Yeniden üretim: `test_deployment_commit_must_match_git_reader` ve
  `test_ref_change_during_remote_read_is_rejected`; ilk sürümde ikisi **FAIL**.
- Minimum düzeltme: reader tek commit'i yakalasın, bütün blob'ları ondan okusun,
  başlangıç/sonda expected deployment commit ve ref eşitliğini denetlesin.
- Patch: `c044164`; `tools/v3_pages_backend.py:157`, `:159`, `:164`;
  `verify_remote` reader check'lerini byte okumasından önce/sonra çağırır.
- Sonuç: iki regresyon ve mevcut actual Git rehearsal **PASS**.
- Sınır: Git reader kontrolü HTTP/CDN'nin deployment identity'sini ispatlamaz.
  HTTPS transport için bağımsız deployment witness ve dış kabul hâlâ gereklidir.
  Ref'in son kontrol noktasından sonra değişmeyeceğine dair lease iddiası yoktur.

### F7 — MEDIUM: primary XML `xml:base` pinned cache'i aşabiliyor

- Konum: `tools/v3_pinned_upstream.py:104`, `:111`, `:113`.
- Kök neden: sadece `location.href` relative path'i denetleniyor; libdnf'nin ayrıca
  yorumladığı XML base URL göz ardı ediliyor.
- Senaryo: href, NEVRA ve checksum approved cache ile aynı kalır; location'a
  `xml:base="file:///v3-outside-pinned-cache/"` eklenir. Validator kabul eder,
  native DNF5 `file:///v3-outside-pinned-cache/probe.rpm` konumunu seçer.
  HTTPS base ile dış erişim de aynı izolasyon şartını ihlal eder.
- Yeniden üretim: `python3 tests/v3-upstream-url-e2e.py`. İlk sürümde native query
  dış URL'yi yazdırdı ve validator reddi oluşmadığı için **FAIL** oldu.
  Probe sadece disposable metadata repoquery'dir; RPM install veya network yoktur.
- Minimum düzeltme: primary/repomd içinde XML base override'larını reddet;
  location attribute contract'ını `href` ile kapat; metadata member'larında URL
  scheme/encoding/query/control karakterlerini reddet.
- Patch: `27985a6`; `tools/v3_pinned_upstream.py:107`, `:115`, ayrıca repomd/member
  kontrolleri. Native probe V3 Fedora CI job'ına eklendi; V2 workflow değişmedi.
- Sonuç: native probe ve iki unit regression **PASS**; signed fixture cache
  validation ile full dependency closure hâlâ **PASS**.
- Sınır: RPM signature/checksum bypass'ı veya key'siz paket yürütme gösterilmedi.
  URL yorumlama davranışı [DNF5 primary API](https://dnf5.readthedocs.io/en/stable/api/c%2B%2B/libdnf5_rpm.html)
  tarafından da belgelenir; asıl kanıt bu incelemenin native query sonucudur.

### F8 — LOW: JSON sayı overflow'u non-finite kontrolünü aşıyor

- Konum: `tools/v3_backend_trust.py:39` ve `:40`.
- Kök neden: `parse_constant` NaN/Infinity literal'lerini reddederken `1e999`
  ve `-1e999` normal float decoder üzerinden Infinity'ye dönüşüyor.
- Yeniden üretim: `test_numeric_overflow_cannot_enter_strict_json`; ilk sürümde
  iki subcase **FAIL**; strict decoder non-finite Python float döndürüyor.
- Etki: strict input sözleşmesi bozulur, sonraki canonical encoding beklenen
  `PlanningError` yerine numeric serialization hatası verir. Yetki veya imza bypass'ı
  gösterilmedi; bu nedenle LOW.
- Minimum düzeltme: `parse_float` içinde `math.isfinite` denetimi.
- Patch: `30f8c92`; `tools/v3_backend_trust.py:35` ve `:48`.
- Sonuç: regresyon **PASS**, duplicate key ve literal non-finite negatifleri korunur.

### F9 — MEDIUM: staged reopen tam onay ve schema bağlamasını atlıyor

- Konum: `tools/v3_immutable_view.py:177`, `:178`, `:181`.
- Kök neden: retry path üç digest'i kontrol ediyor; expected payload'u okuduğu
  descriptor'ın kendisinden kuruyor. Normal stage'in strict publication schema'sı
  ve authorization request/result/preflight equality şartları uygulanmıyor.
- Senaryo: publication rolü yanlış ama gerçek imzalı record verir; authorization
  hash ve inventory doğruyken attempt request'i, preflight veya result digest'i
  değişiktir. Reopen bunu typed StagedView olarak kabul eder. `publishable=true`
  descriptor da outer envelope schema'sından geçer. İmza doğru olması exact human
  approval ve test-only contract'ın yerine geçemez.
- Yeniden üretim: `test_reopen_requires_exact_authorized_request_and_preflight`
  (üç subcase) ve `test_reopen_cannot_import_a_publishable_descriptor`;
  ilk sürümde toplam dört beklenen red **FAIL**.
- Minimum düzeltme: fresh typed prerequisites/original result kontrolü;
  strict `immutable-publication-v3` schema; exact authorization request,
  result/preflight digest, canonical publication key ve deadline equality.
- Patch: `a00ba53`; `tools/v3_immutable_view.py:173`, `:184`, `:187`.
- Sonuç: iki yeni regression ve eski after-rename recovery retry **PASS**.
  `production_publish` tüm sürümlerde BLOCKED idi; bu bulgu canlı üretim yayını
  yapıldığını veya açıldığını göstermez.

## Process trust ve doğrulanmayan saldırı iddiaları

`TOKEN` public Python sembolüdür; trusted application code onu import edip
Workload/Attestation/Evidence/Authorization constructor'larını çağırabilir.
Sentinel, aynı process'te kötü niyetli Python koduna karşı security boundary
değildir. Mutable capability attribute'ları da böyle bir boundary sayılmaz.

Kod/entry point incelemesinde untrusted JSON veya API verisinin eval, pickle,
arbitrary import/plugin veya capability constructor route'una girdiği bir yol
bulunmadı. CLI input doğrulaması cryptographic verifier üzerinden yürür. Bu
nedenle yalnızca `TOKEN` import edilebildiği için exploit raporlanmadı. Doğru
process trust açıklaması kod/dokümana eklendi; wrong seal, plain JSON ve missing
typed capability negatifleri PASS. Application code'un kendisini sandbox'lamak
ayrı bir mimari değişikliktir; bu PR'de yapılmadı.

JWKS/authentication roots bağımsız caller/operator provision'udur. Caller'ın
kendi saldırgan key'ini kendi trust pin'i diye vermesi tek başına root substitution
exploit kanıtı değildir. Mevcut RSA/JWT/claim/time/role ve protected reviewer
negatifleri yeniden geçti. Gerçek JWKS rotation/revocation ve witness servisinin
gözlem güvenilirliği dış kabul engeli olarak kalır.

## Patch commit'leri

| Commit | Değişiklik |
| --- | --- |
| `3ca91a4` | Başlangıç 494 test log'u ve sekiz failing adversarial regression |
| `b8c2c20` | F4: no-op Git ref CAS |
| `5ebc41d` | F5: advertisement imzasını CAS'ten önce doğrulama |
| `6d44221` | F1/F2: transaction deadline ve remote freshness guard'ları |
| `c044164` | F6: witnessed Git commit'e sabitlenmiş byte verification |
| `f297130` | F3: canonical audit/authorization root ayrımı |
| `27985a6` | F7: XML base ve metadata URL reddi, native probe/CI |
| `30f8c92` | F8: JSON overflow reddi ve process trust açıklaması |
| `a00ba53` | F9: reopened publication exact contract/schema |
| `12d0d1a` | 17 targeted test; PostgreSQL replay/corruption/restore/crash ve recovery yarışı |

## Test sonuçları ve kanıt kapsamı

Test edilen tools/tests/schemas/config source inventory SHA256:
`c76d8c028bfed67ac6e3a1637f4bfa5f60b91555c008be5a994bcdbbf8d9f825`.
Native Fedora ve signed backend rehearsal aynı inventory'ye bağlıdır. Final
testler `git archive 12d0d1a` ile alınan yazılabilir sabit disposable kopyada
çalıştırıldı; kaynak testler sırasında değiştirilmedi. Doküman/evidence eklenmesi
bu implementation inventory'sini değiştirmez.

| Test | Sonuç / sınır |
| --- | --- |
| İlk head full Python | 494 PASS; 0 fail/error/skip; yedi başlangıç CI check SUCCESS |
| İlk sekiz negative | 8 FAIL; expected rejection oluşmadı; before log korundu |
| Overflow/reopen/native URL before | Ayrı failing reproducer log'ları korundu |
| Final full Python | 511 PASS; 0 fail/error/skip |
| Final V3 discovery | 367 PASS; 0 fail/error/skip; full suite'in alt kümesidir |
| Gerçek PostgreSQL 18.6 | PASS: iki bağımsız promoter, recovery/promoter yarışı, replay, invalid signer, deadline, process death, üç consumption/audit crash sınırı, event/head/replay corruption, audit truncation, checkpoint substitution |
| Eski geçerli PG backup | Dış recent checkpoint ile red PASS; dış checkpoint olmadan UNDETECTABLE (tasarım sınırı) |
| Actual bare Git | PASS: immutable overwrite/stale ref, no-op CAS, iki independent process, invalid signer, commit substitution/read race |
| Recovery | PASS: on bir ledger transition'ın her birinde audit sonrası interruption ve tam rollback/retry; historical bytes korunur |
| DB/Git sınırları | PASS: staging commit öncesi/sonrası, remote proof öncesi/sonrası, DB publication intent sonrası Git advertisement öncesi, Git commit response kaybı ve post receipt'in DB'ye kaydından önceki kesinti |
| Native Fedora44/DNF5 | PASS: gerçek imzalı synthetic RPM/SRPM bootstrap, retained bytes, clean install/full upgrade, rpmnew, isolated beta/stable query, deterministic metadata, pinned synthetic upstream dependency closure |
| Native negatives | PASS: gerçek eksik dependency, retained payload conflict, unsigned SRPM; metadata XML base URL probe |
| V2 compatibility | PASS, `tests/e2e-local.sh` exit 0: signed role separation, existing catalog/publication fixture, single/multi-subpackage real DNF clean-install/upgrade; rpmlint 0 error, 4 fixture warning |
| Static | PASS: Python compile, shell syntax, tüm Draft2020-12 schema ve workflow YAML parse, workflow guards, diff whitespace |

Başlangıç ve targeted failing/passing log'ları
[`docs/evidence/pr72-adversarial-20261012/`](evidence/pr72-adversarial-20261012/)
altında önceki düzeltme commit'lerinde bulunur. Son yerel full-suite/Fedora/PG/Git
receipt'leri ayrıca üretildi ve source inventory eşitliği kontrol edildi. Kullanıcının
son talebi doğrultusunda bu rapor commit'ine yeni evidence dosyası eklenmedi;
aşağıdaki public CI job log'ları `12d0d1a` için uzaktan doğrulanabilir kanıttır.
Private keys, JWT'ler, credentials veya veritabanı backup'ları repo'ya eklenmedi.

### `12d0d1a` için 7/7 CI kanıtı

Üç workflow run'ının tamamı
`12d0d1a6efe02e4bda1ec882649f6134b6646fdd` head'ine aittir. PR metadata'sındaki
head SHA ve her check'in COMPLETED/SUCCESS sonucu doğrulandı; başka head'in yeşil
sonucu bu değerlendirmeye taşınmadı. Public job log'unda unit-policy **511 test / OK**
(90.551 saniye), security-contracts **367 test / OK** (86.627 saniye) kaydı da okundu.

| CI check | Sonuç ve public kanıt |
| --- | --- |
| unit-policy | [SUCCESS — 511 test](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38233081115/job/114757026624) |
| backend-security | [SUCCESS — backend negatives ve signed Git rehearsal](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38233081130/job/114757026781) |
| security-contracts | [SUCCESS — 367 V3 test](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38233081191/job/114757026763) |
| fedora44-e2e | [SUCCESS — mevcut V2 native E2E](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38233081115/job/114757026614) |
| postgres-transactions | [SUCCESS — gerçek transactional adversarial E2E](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38233081130/job/114757026989) |
| fedora44-full-stable-set | [SUCCESS — signed full-set ve native XML-base negatifleri](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38233081191/job/114757027161) |
| acceptance-runtime-contract | [SUCCESS — acceptance runtime contract](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38233081115/job/114757026450) |

Bu rapordan sonraki yalnızca doküman commit'inin kendi CI sonuçları yukarıdaki
sonuçlar diye sunulmaz. İnceleme ve doğrulanmış 7/7 kanıt açıkça `12d0d1a` kapsamındadır.

## Ayrı publication garantileri ve kalan engeller

1. **PostgreSQL CAS:** digest+generation ve replay/audit aynı transaction'da
   commit/rollback eder. Dış HA/durability ve bütün DB antirollback servisi UNVERIFIED.
2. **Git CAS:** yalnızca `refs/heads/isolated-storage` ref'inin serialized güncellemesidir.
   DB ile ortak transaction değildir. Git commit başarısı Pages deploy başarısı değildir.
3. **Pages deploy:** gerçek GitHub deployment/witness çalışması UNVERIFIED.
4. **CDN:** complete HTTPS checks implement edilmiş olsa da gerçek origin/PoP
   görünürlüğü ve cache convergence test edilmedi. CDN atomicity iddiası verilmez.
5. **DNF client:** tam view digest'ine bağlı URL gereklidir. Mevcut mutable V2 stable
   URL'leri migration olmadan bu garantiyi almaz; canlı client adoption yoktur.

PUBLISHED, isolated DB advertisement **intent**'idir; last_verified ancak ayrı
post check'ten sonra ilerler. Git advertisement commit'i sonrası caller response
kaybında eski ref'le kör retry reddedilir; mevcut signed bytes doğrulanarak explicit
reconciliation yapılır. Live durable outbox/lease/deployment reconciliation
bilerek BLOCKED'dır. Test harness'in reconciliation sonucu bu dış servisin
kurulu olduğunun kanıtı değildir. Power-loss/disk fsync dayanıklılığı da bu
process interruption testleriyle ispatlanmaz.

Recovery history yalnızca POST_VERIFIED digest'leri kabul eder, current base/attempt
ve fresh approval/witness/JTI'ye bağlanır. Native fixture historical signed parent
korunmasını gerçekten doğrular. Bu native test **RPM/GPG preflight**'tır; actual
released package downgrade/recovery DNF transaction acceptance değildir. Normal
promotion planner downgrade yasağı korunur. GUI/system recovery ve released
package recovery execution hâlâ UNVERIFIED.

Official Fedora mirror provenance/cache, native aarch64, gerçek producer uygulamaları,
Plasma/login/boot/reboot/QEMU ve Ro-Store acceptance UNVERIFIED'dır. VM protokol
testleri mock rejection testleridir; gerçek VM boot/GUI çalıştırıldığı iddia edilmez.
gzip/bzip2/xz/Zstandard decoder kodu ve bound'lar incelendi; real Zstandard feed
acceptance UNVERIFIED, zchunk-only primary decoder BLOCKED kalır.

Önceki rapordaki 494/350 PASS bu yeni race/binding negatiflerinin test edildiğini
kanıtlamıyordu. O raporun eski inventory receipt'leri yeni head için acceptance
sayılmaz. Yeni kayıtlarda synthetic, native, mocked ve external sonuçlar ayrılmıştır.

## Production safety ve merge önerisi

`.github/workflows/v3-stable-promotion-disabled.yml` main ile byte-identical;
on bir job'un tamamı unconditional `${{ false }}` ve `exit 1` olarak kaldı.
`production_publish()` koşulsuz BLOCKED. İzole writer'lar private `/tmp` roots,
remote'suz bare Git ve loopback `ro_v3_test_*` DB ile sınırlı; live pages-storage
write route'u veya deploy workflow yok. Test workflows production secrets,
protected environment veya write/id-token permission kullanmıyor.

Mevcut V2 beta/stable/publishing/rollback workflows main ile byte-identical.
Legacy `promote-remote-stable.yml` bütün beta'yı kendi concurrency realm'inde
stable'a taşıyabilir; gelecekte bağımsız V3 writer ile aynı anda açılması hâlâ
çatışmadır. Reviewed writer retirement, ortak CAS authority ve explicit client
migration aktivasyondan önce zorunludur; bunlar uygulanmadı.

**A — NON-PRODUCTION merge:** `12d0d1a` düzeltmeleri, 511 testlik final local suite
ve aynı implementation head'e ait 7/7 başarılı CI ile **uygun**. Raporu ekleyen
yalnızca doküman commit'i executable implementation'ı değiştirmez. Doğrulanmış açık implementation kusuru
bırakılmadı; bu sınırsız saldırı yüzeyinin yokluğunun formal proof'u değildir.

**B — Production stable aktivasyonu:** uygun değil, **BLOCKED**. Bağımsız roots,
protected witness/environment, gerçek package/arch/VM acceptance, external monotonic
checkpoint, durable DB/outbox, gerçek Pages/CDN doğrulaması ve V2 writer/client
cutover ayrıca kabul edilmelidir. Yeşil CI veya bu rapor production authority değildir.

PR draft tutulur. Merge, yeni PR, main/pages-storage değişikliği, live publication,
migration/rollback, production signing/key access veya job activation yapılmadı.
Son kullanıcı talebine göre yalnızca bu eksik rapor dosyası commit edilip mevcut
PR dalına gönderilir; tamamlanmış implementation değişiklikleri yeniden yapılmaz.
