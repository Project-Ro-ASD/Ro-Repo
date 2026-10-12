# V3 gerçek paket acceptance raporu

Tarih: 2026-10-12. Repository: `Project-Ro-ASD/Ro-Repo`.
Dal: `feature/v3-real-world-acceptance`. Temel main:
`22e16af97d22d680e8e79298378ff9faaa0e2fad`.
Test edilen implementation: `b44995a`.

**Sonuç: 11/11 gerçek released-package native DNF senaryosu PASS;
519 Python testi PASS, bunun 375'i V3 testi. Production aktivasyonu BLOCKED.**
Bu bir NON-PRODUCTION acceptance milestone'dur. Container transaction başarısı,
native aarch64, Plasma/login, installer disk işlemi veya protected publication
kabulü değildir. Hiçbir gerçek kanal yayımlanmadı, migrate veya rollback edilmedi.

## Önkoşul ve değişiklik kapsamı

[PR #72](https://github.com/Project-Ro-ASD/Ro-Repo/pull/72), 2026-10-12 10:41:28 UTC'de
main'e yukarıdaki commit ile merge edilmişti; son `fcdd3a7` PR head'inin yedi CI
check'i SUCCESS idi. Bu doğrulamadan sonra tek yeni dal main'den oluşturuldu.
Issue [#44](https://github.com/Project-Ro-ASD/Ro-Repo/issues/44), aktivasyon checklist'i,
migration planı, backend raporu, PR72 güvenlik raporu ve mevcut araçlar okundu.

Planner/composer, RPM/GPG preflight, deterministic metadata, signed preview,
pinned-upstream validator, DNF5, backend ledger/Git CAS ve VM sözleşmeleri tekrar
uygulanmadı. Yeni test driver'ları bu araçları kullanır. Production workflow'ları,
producer registry, başka repository veya application source'u değiştirilmedi.

## A — Güncel production inputlarının salt okunur doğrulaması

- Pages commit: `097ba6ba7ab73d87c36f7ec9829b017b083b1883`.
- Gerçek Git tree: `69fda4e20cf3082631228a5a7eca5b0ee3b2b0b1`.
  Disposable bare clone üzerinde Git fsck PASS; 268 blob'un API inventory'siyle
  eşitliği doğrulandı. Tar capture'ın her blob'u boyut ve Git SHA1 ile kontrol edildi.
- Current beta: `repo-f44-20261009-001`; snapshot inventory SHA256:
  `58d5a74b70360a4319069c6928671fb3ddf249cfa7cc1c2a0697e938ea470e97`.
- Public HTTPS üzerinden **262/262 expected file byte parity PASS**: current beta,
  archived publications ve immutable snapshots dahil. Son ref tekrar okunarak
  aynı commit doğrulandı. Unknown extra CDN files ve farklı PoP'lar UNVERIFIED.
- Beş tarihsel snapshot'ın metadata, bütün binary RPM/SRPM signature/header/linkage
  preflight'ı PASS. Altı archived publication detached signature'ı PASS.
- Canonical `config/producers-v2.json` file SHA256:
  `b011cd414d690f715572bed88054b0acf2fc18695dfebf2aef2e85cc9ba289c8`.
- Public RPM key SHA256:
  `d73e92fcbf1dc9f8900459fa34b5eaa053570f11532ffc8e53373e8289b7ee51`;
  metadata key SHA256:
  `4eaf0b2903e60442c2f05325a43d85046bba850059b732dfc71e330f5e9e0809`.
  Bunlar pinned main'den okunan public key'lerdir; independent production root
  provisioning kabul edildiği iddia edilmez.

Current beta'da 23 logical package entry ve noarch'ın iki mimariye kopyalarıyla
30 physical RPM path bulunur. Ro-Control ve Ro-Theme absent. Envanter yeniden
okundu; eski gözlem varsayılmadı. Native test inputları /inputs ve /upstream
read-only mount edildi; original snapshot inventories test sonunda tekrar eşleşti.

**Verified existing stable yok:** pinned Git tree'de stable publication/kanal
bulunmadı ve public stable pointer GET'i HTTP 404 döndü. Empty-stable bootstrap
sadece disposable test ortamında kullanıldı; production ledger initialize edilmedi.

**History gate BLOCKED:** eski imzalı publication'ların mevcut strict V3 archive
contract'ında beklenen alanları eksik; `signed_archive_bundle` gerçek archive için
`unexpected signed publication fields` reddi verdi. İmzalı kayıtları değiştirmedik,
store digest veya authenticated first-public-availability uydurmadık. Archived
timestamps gözlemdir; bağımsız trusted availability/history observer kabulü değildir.

## B — Actual Fedora 44 / released RPM sonuçları

Transaction ortamı native x86_64 Fedora44 container, DNF5 ve RPM6'dır; exact runtime
çıktısı evidence/runtime.txt içindedir. Final runner `--network none` kullandı.
DNF sadece frozen file:// Ro/Fedora repository'leriyle çalıştı; host/system repo
fallback, network package download veya weak-dependency fallback yoktu.

Acquisition ayrı ortamda, resmî Fedora metalink'lerinden HTTPS üzerinden yapıldı.
Farklı mirror denemeleri yalnızca **aynı captured repomd SHA256** ile kabul edildi.
Her metadata member checksum'u ve seçilen RPM'in primary path/NEVRA/SHA256 bağı
kontrol edildi. Sonra bütün RPM signature'ları doğrulanarak cache kullanıldı.

| Feed | Exact repomd SHA256 | Verified cached RPM |
| --- | --- | ---: |
| Fedora44 release | `da3845427d188097f6fd71b417a039bdfb8efefc4f38ca44b5cbb94f95a18991` | 264 |
| Fedora44 updates | `f1902ee7042cbf18bc9372ec8148a01c935c7a779b2314f09ceb07734b10d9fa` | 307 |

Fedora RPM root fingerprint, container key'i ile
[Fedora'nın resmî security kaynağı](https://fedoraproject.org/security/) arasında
eşleşti: `36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6`.
Gerçek Zstandard primary metadata decoder/validator yolu çalıştı ve PASS oldu.
Unsigned Fedora repomd için signed-pin **test observation** kullanıldı; bağımsız
production metadata-attestor servisi kurulmuş veya kabul edilmiş sayılmaz.
zchunk-only primary yolu hâlâ BLOCKED.

Released RPM'ler yeniden imzalanmadı. Yalnızca disposable stable preview metadata'sı
yeni TEST ONLY key ile imzalandı. Validator, original production metadata public
root'u ile test-preview public root'unu açıkça pinned public bundle'dan doğruladı.
Production private key okunmadı veya kullanılmadı.

### Component acceptance matrix

DNF PASS hücreleri x86_64 clean-install/full-set upgrade/addition, pinned dependency
closure, transaction conflict rejection, exact target EVR/RPMDB ve beta/stable
isolation kapsamındadır. Source/signature PASS hücreleri SRPM linkage'i de içerir.

| Component / exact released NEVRA | Signature/closure | Actual x86_64 DNF | Runtime / GUI / diğer acceptance |
| --- | --- | --- | --- |
| `ro-assist-0:0.2.4-1.fc44.{x86_64,aarch64,src}` → `ro-assist-0:0.2.5-1.fc44.{x86_64,aarch64,src}` | PASS | PASS: gerçek bootstrap ve version upgrade | x86 CLI help PASS; native/emulated aarch64 UNVERIFIED; GUI UX UNVERIFIED |
| `dolphin`, `dolphin-libs`, `dolphin-devel`: `0:26.08.1-1.roasd1.fc44.x86_64`; `dolphin-0:26.08.1-1.roasd1.fc44.src` | PASS: complete group | PASS: yeni grubun clean install ve retained stable'a eklenmesi | Installed target CLI version PASS; Plasma/login/integration UNVERIFIED; earlier Dolphin version upgrade UNVERIFIED |
| `ro-installer-0:2.4.4-1.fc44.{x86_64,src}` | PASS | PASS: clean/full-set addition | Bare-chroot startup probe FAIL; gerçek GUI/installation UNVERIFIED — ortam tanısı aşağıda |
| `ro-asd-keyring-0:0.1.0-1.fc44.{noarch,src}` | PASS | PASS: yeni grup ve sonraki Assist upgrade'inde retention | Boot/key lifecycle UNVERIFIED |
| `ro-asd-release-0:0.1.2-1.fc44.{noarch,src}` | PASS | PASS | Real boot/reboot/system acceptance UNVERIFIED |
| `ro-asd-repos-0:0.1.1-1.fc44.{noarch,src}` | PASS | PASS | Gerçek immutable-client migration BLOCKED |
| `ro-asd-defaults-0:0.1.0-1.fc44.{noarch,src}` | PASS | PASS | Real desktop/system behavior UNVERIFIED |
| `ro-asd-branding-0:0.1.0-1.fc44.{noarch,src}` | PASS | PASS | Plasma/login acceptance UNVERIFIED |
| `ro-asd-desktop-standard-0:0.1.0-1.fc44.{noarch,src}` | PASS | PASS | Plasma/login acceptance UNVERIFIED |
| `ro-asd-kernel-policy-0:0.1.0-1.fc44.{noarch,src}` | PASS | PASS | Real kernel/boot/recovery acceptance UNVERIFIED |
| Ro-Control; Ro-Theme | BLOCKED: actual input absent | BLOCKED | Actual product acceptance BLOCKED |

Noarch binary bytes'in x86_64/aarch64 published kopyaları doğrulandı; actual noarch
transaction'ları x86_64 üzerinde çalıştı. Bu, aarch64 application execution değildir.
Installer veya Dolphin için önceki signed sürümle gerçek component version upgrade
yapıldığı iddia edilmez; captured archive'da o baseline yoktu.

### Eleven actual transaction senaryosu

`assist-bootstrap`, `keyring-retained`, `assist-upgrade`, `dolphin-full-group`,
`installer-full-group`, `noarch-release`, `noarch-repos`, `noarch-defaults`,
`noarch-branding`, `noarch-desktop`, `noarch-kernel`: **11/11 PASS**.

Ro-Assist 0.2.4-only snapshot'tan başlanır. Keyring grubu eklenir; Ro-Assist 0.2.5
upgrade'i sırasında unrelated keyring binary/SRPM bytes değişmeden korunur. Sonraki
Dolphin/Installer ve noarch grupları component-scoped composition ile eklenir.
Ro-Assist bootstrap'a unapproved Dolphin/Installer dahil edilmez.

Her resulting complete view için clean install, baseline install, installed-target
upgrade ve genuinely new-group install çalıştı. Exact installed dependency closure
yalnızca approved Ro/Fedora NEVRA setinden oluştu. Genuine source, selected ve
retained RPM byte identity kontrolleri PASS. Aynı actual RPM seti ve epoch ile iki
unsigned metadata generation'ın inventories'i birebir eşleşti: deterministic PASS.

Actual Ro-Assist config preservation PASS: yerel değişiklik upgrade sonrası kaldı.
`/etc/xdg/autostart/ro-assist-autostart.desktop` packaged digest'i iki sürümde aynı:
`844ae4fae40556fee25ee4a774dfda39474f6204a150f19caaccedf2600384f8`.
Bu yüzden RPM `.rpmnew` üretmek zorunda değildir; **actual changed-config `.rpmnew`
acceptance UNVERIFIED** olarak tutuldu. Ayrı mevcut synthetic signed fixture'da
gerçek changed-config `.rpmnew` üretimi ve digest kontrolü PASS; bu actual product
sonucu diye sunulmaz.

Actual inputs üzerine yapılan negatifler PASS: Assist aarch64 eksikliğinde
canonical architecture floor reddi; Dolphin-libs eksikliğinde complete group reddi;
yalnızca disposable kopyadaki actual SRPM imzası kaldırıldığında trusted RPM
signature reddi. Original production inputlar değişmedi.

### Installer probe'unun doğru yorumu

Bare chroot `ro-installer --help` exit127 verdi: `libflutter_linux_gtk.so` yüklenemedi.
İlk izlenim bir runtime packaging sorunu olabilirdi; ayrıca araştırıldı. Kütüphane
pakette `/usr/lib64/ro-installer/lib/` altında mevcut; ELF RUNPATH `$ORIGIN/lib`.
Chroot'ta `/proc/self/exe` yok. Aynı genuine signed RPM/dep setiyle ikinci disposable
root'ta `LD_ORIGIN_PATH=/usr/lib64/ro-installer` sağlandığında library yükleme hatası
kalktı, GTK yalnızca display bulunmadığı için exit1 verdi.

Bu nedenle **producer packaging bug doğrulanmış değildir**. Bare-chroot FAIL log'u
korunur; gerçek installer GUI/partition/install/reboot acceptance UNVERIFIED'dır.
Normal proc/GUI/guest ortamında doğrulanmalıdır. Dolphin baseline'ında henüz Dolphin
kurulu olmadığı için oluşan exit127 de application failure sayılmaz; target clean
ve final upgrade CLI version probe'ları PASS'tır. Offscreen CLI hiçbir zaman GUI PASS değildir.

## C — Aarch64 ve VM acceptance

Native aarch64 host sağlanmadı. Actual Assist aarch64 RPM signature/header/source
closure PASS; native veya emulated execution **UNVERIFIED**.
Host x86_64 QEMU executable mevcut, ancak V3 spec'e uygun independently pinned raw
guest image, firmware/executor pin seti, approved media ve
`/usr/libexec/ro-repo-v3/acceptance` guest cases sağlanmadı. VM execution **BLOCKED**;
Plasma/login/Dolphin integration/installer disk işlemi/boot/reboot/recovery **UNVERIFIED**.
Mevcut VM protocol unit tests mock rejection testsidir; gerçek guest kabulü değildir.

## D — Stable rehearsal ve authority ayrımı

Actual composition/native stable bootstrap/upgrade/retention PASS. Resulting Assist ve
keyring snapshot, aynı bytes ile disposable
`v3/views/16f2295c732e970303da714e1f121b5f1e64ef1ea01c0a49e5fdaadadf6c8f15/`
altına kopyalandı. Native DNF5 signed repodata stable-only query, yalnızca Assist ve
keyring'i gördü; before/after inventory digest eşitliği PASS. Bu layout query'si
HTTPS Pages deployment veya protected authorization değildir.

Existing signed backend/Git rehearsal POST_VERIFIED PASS; gerçek PostgreSQL18.6
iki writer CAS, recovery/promotion race, replay, signer/deadline rollback, audit
corruption/truncation, interruption ve checkpoint testleri PASS. Bunlar **synthetic
protocol fixtures** kullanır. Actual package execution sonucunu fake approval veya
GUI claim'iyle completed production attempt'e dönüştürmedik.

Actual complete protected promotion **BLOCKED**: independent roots/source/history/
runner attestations, all required architecture/application tests ve protected exact
approval yok. API success, observed key pin, green CI veya test signer production
authority değildir. PUBLISHED DB intent, Git CAS, Pages deployment, CDN visibility
ve actual client consistency ayrı garantiler olarak kalır. Whole valid DB restore
antirollback'i external recent monotonic checkpoint olmadan sağlanmış sayılmaz.

## Bu sprint'te doğrulanan ve düzeltilen araç kusurları

| Commit | Reproduction ve minimum düzeltme |
| --- | --- |
| `53cf21a` | Genuine Fedora `gstreamer1-plugins-bad-free-libs` imzası geçerliyken filename'deki `bad` yüzünden reddediliyordu. `trusted_rpm_status` yalnızca tek summary'nin status kısmını parse eder; missing/BAD/NOKEY/ambiguous signatures hâlâ reddedilir. |
| `506f4c5` | Native new-group cases DNF5 `available, but not installed` hatası verdi. Upgrade yalnızca installed approved names'in exact NEVRA'larını hedefler; yeni names ayrıca exact NEVRA ile install edilir. Mevcut real-signed retained fixture'a regression eklendi. |
| `506f4c5` | `.rpmnew` her config upgrade'inde zorunlu varsayılıyordu. Unchanged packaged config yerel değişiklik korunarak `.rpmnew` olmadan kabul edilir; changed config exact target header digest'e bağlı `.rpmnew` gerektirir. Wrong digest ve symlink negatives eklendi. |
| `070745c`, `b44995a` | Bounded read-only acquisition/public parity; loopback-only actual transaction driver; source before/after inventory, actual negatives ve gerçek CLI observation hook'u. DNF/RPMDB sonuçları mock edilmez. |

Production guard veya existing security test zayıflatılmadı. Sekiz yeni regression
eklendi. Initial native attempts içindeki FAIL'ler ve harness sorunları kanıtta
ayrı tutuldu; yalnız final fixed-source receipts acceptance sayılır.

## Test, kaynak ve kanıt digest'leri

Final tools/tests/schemas/config inventory:
`9fdb8c241ea9fad1a4b4e30247f0fa03b2f6174df96475303a84b9a7902d9f58`.
Actual driver, synthetic Fedora ve backend rehearsal inventories'i final source'a
bağlıdır; kod testler sırasında değişmedi. Testler `git archive b44995a` kopyasında
çalıştı; yalnız documentation/evidence eklenmesi bu inventory'yi değiştirmez.

| Check | Sonuç |
| --- | --- |
| Full Python unit/security | 519 PASS; 0 fail/error/skip; 375 V3 dahil |
| Actual released RPM transaction matrix | 11/11 PASS; actual source/candidate negatifleri PASS |
| Real Fedora44 signed synthetic fixture | PASS; new-group regression, missing deps, payload conflict, unsigned SRPM, changed-config rpmnew, deterministic metadata |
| Real PostgreSQL/Git/backend/recovery | PASS; isolated test authority, external services UNVERIFIED |
| Existing V2 compatibility E2E | PASS, exit0; rpmlint0error/4fixturewarning |
| Python compile, shell syntax, all schemas/YAML | PASS |
| Eleven unconditional disables / V2 workflows vs main | PASS, byte-identical |
| GitHub CI | Final PR head'e ait sonuç handoff'ta doğrulanır; local PASS, CI sonucu yerine kullanılmaz |

Exact component/package signed-artifact hashes, complete source inventory,
upstream manifests/metadata/checksums, public key'ler, per-case DNF receipt/log,
remote parity, environment configuration ve runtime çıktıları
[`evidence/v3-real-world-20261012/`](evidence/v3-real-world-20261012/) içindedir.
Tek tek package digests `released/acceptance.json` inventory'sindedir; evidence
inventory dosyası bütün public outputs için SHA256 verir. Private key, JWT,
credential, DB backup veya binary RPM cache repository'ye eklenmedi.

## E — Exact maintainer actions / external blockers

1. **Root ve history authority:** yukarıdaki observed public key pin'lerini out-of-band
   doğrula; ayrı source/history/test/approval/witness/publication/audit roots provision
   et. Legacy signed publications'ı yeniden yazmadan eksik store/history bilgisi için
   bağımsız authenticated supplement/observer sağla. Actual first-public availability
   ve complete source release/build attestations doğrulanmadan dwell authority açma.
2. **GitHub protections:** repo-stable ve repo-production-signing mevcut; release-engineering
   reviewer team ID19418500, main-only branch policy ve admin bypass=false gözlendi.
   **prevent_self_review=false → true** yap; configuration digest'i independent witness'e
   pin'le. API reviewer varlığı exact-result signed approval yerine geçmez.
3. **OIDC/witness:** repository ID1159460821/owner ID248876122, issuer/audience/subject,
   actor/run/attempt, exact main/reusable workflow SHAs ve runner class'ını bağımsız
   provision et; JWKS rotation/revocation prosedürü kur. Exact proposal/base/result/
   policy/evidence/attempt-bound human approval ve environment witness servisini kabul et.
4. **Durable authority:** production PostgreSQL TLS verify-full, restricted roles,
   HA/restore tests, audit signer custody ve independent monotonic checkpoint provider
   kur. Mevcut adapter test-loopback ile sınırlı; production config için ayrı reviewed PR gerekir.
5. **Cross-provider recovery:** DB intent ↔ Git CAS ↔ deployment outbox/lease,
   response-loss idempotence ve independent reconciliation implement/kabul et.
   Local CAS'ı remote publication/recovery diye raporlama.
6. **Pages/CDN/client:** source pages-storage:/, build_type legacy ve
   **https_enforced=false** gözlendi. HTTPS enforcement, pinned deployment witnesses,
   complete immutable-view byte probes ve CDN convergence kabulünü gerçekleştir.
   Ro-ASD clients'ı reviewed `.repo` değişikliğiyle exact digest URL'lerine migrate et;
   bu sprint hiçbir client config veya live view yayınlamadı.
7. **Writer cutover:** legacy V2 whole-beta stable writer'ı reviewed migration ile
   retire et; in-flight writers'ı reconcile et; tüm stable actors için tek CAS authority
   kur. Yeni V3 writer'ı bağımsız concurrency realm'inde V2 ile aynı anda açma.
8. **Actual architecture/GUI/system gates:** native aarch64 veya labelled emulated
   signed runner evidence; actual Plasma/login/Dolphin, installer, boot/reboot/recovery
   ve Ro-Store cases sağla. Pinned raw VM/QEMU/firmware/media ve genuine guest helper
   provision et. Earlier signed Installer/Dolphin versions'la gerçek upgrades çalıştır.
   Ro-Control/Ro-Theme için mevcut kapsam dışında producer release inputları gerekir.

## Öneri

Bu sprint'in kod/kanıt değişiklikleri automated CI de final head'de başarılı olduğunda
**NON-PRODUCTION milestone olarak merge'e uygundur**. Gerçek x86_64 package/DNF
ve integrity kabulü önemli ölçüde ilerledi; tüm release gates tamamlandı denmez.
**Production stable aktivasyonu uygun değildir, BLOCKED.** On bir job kapalı,
`production_publish` koşulsuz BLOCKED, main/pages-storage ve V2 publishing değişmedi.
Yeni PR yalnız draft olarak teslim edilir; merge/production signing/live publication/
migration/rollback yapılmaz.
