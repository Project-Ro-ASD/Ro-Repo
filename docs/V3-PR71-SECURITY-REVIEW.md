# PR #71 adversarial güvenlik incelemesi

İlk incelenen PR head: `580b8f825d3afe8f5613b45f113bbdcdc7d81c2d`.
Karşılaştırılan güncel `main`: `db04a4cbfb0aa904d0a2c1244251e7795987a209`.
İnceleme dalı: `feature/v3-integration-complete`. Tarih: 2026-10-12 (Europe/Istanbul).
Test edilen son implementation commit'i: `4649257` (tam SHA kanıt inventory'sinde).
Sonuç: **1 HIGH + 7 MEDIUM doğrulanmış kusur; sekizi de düzeltildi**.

Bu rapor çevrimdışı entegrasyonun güvenlik kararlarını değerlendirir. Üretim
aktivasyonu **BLOCKED**; bir release veya üretim hazır olma değerlendirmesi değildir.
Yeni PR, merge, workflow dispatch, üretim anahtarı erişimi veya canlı yayın/rollback
yapılmadı. Düzeltmeler aynı PR dalında tutulur.

## Doğrulanmış bulgular

Satırlar ilk incelenen `580b8f8` head'ine aittir. Yeniden üretimler yeni
`tests/test_v3_adversarial_review.py` testleriyle yapılır:

```bash
python3 -m unittest discover -s tests -p test_v3_adversarial_review.py -v
```

GPG ve Git sınırları gerçek geçici anahtar/imza/commit'lerle çalışır. DNF baseline
ve integration result testlerinde RPM/DNF yürütme sınırı mock edilir; bu testler
uygulama veya gerçek DNF acceptance kanıtı olarak sunulmaz.

### F1 — HIGH: hash kontrolünden sonra public key değiştirilmesi

- Konum: `tools/v3_signed_beta_history.py:72` ve `:79`; aynı desen
  `tools/v3_rpm_preflight.py:94` ve `:123` içinde de vardır.
- Senaryo: güvenilir key'in SHA-256 kontrolü tamamlandıktan sonra path'in içeriği
  saldırganın public key'i ile değiştirilir. GPG import doğrulanmış byte'lar yerine
  değiştirilen path'i okur. Saldırganın gerçek imzası, güvenilir key digest'i
  verilmesine rağmen `local_approval_signature_verified: true` sonucunu alır.
- Yeniden üretim: `test_pinned_key_cannot_be_replaced_between_hash_and_import`;
  iki gerçek Ed25519 key ve saldırganın detached signature'ı kullanılır. İlk head'de
  test **FAIL**: beklenen `PlanningError` oluşmaz.
- Minimum düzeltme: key byte'larını bir kez oku, bu byte'ların hash'ini kontrol et,
  özel geçici dizine dondur ve yalnızca bu kopyayı GPG/RPM keyring'e import et.
- Uygulanan patch: `_keyring` ve `v3_rpm_preflight.verify` bu işlemi yapar.
- Sınır: bu bir yerel imza pin'i bypass'ıdır; üretim yetkisinin açıldığı gösterilmedi.
  Desenin kökü eski V3 helper'dan gelir; yeni local authorization bu helper'ı kullanır.

### F2 — MEDIUM: doğrulanmış result ile onaya bağlanan result farklı olabilir

- Konum: `tools/v3_integration.py:195`, `:197`, `:205` ve `:206`.
- Senaryo: `_signed_view` doğrulamasından sonra result manifest değiştirilir.
  Result, son inventory kontrolüne dahil değildir. Proposal, artık imzası geçersiz
  olan manifest'i içeren yeni tree digest'ini complete result olarak bağlar.
- Yeniden üretim: `test_result_signature_toctou_cannot_bind_unsigned_manifest`;
  gerçek imzalı result metadata doğrulandıktan sonra manifest'in run alanı değiştirilir.
  İlk head'de test **FAIL**: proposal yazılır.
- Minimum düzeltme: result'ı özel bir kopyada doğrula, başlangıç inventory'sini
  bağla ve hem kopyanın hem orijinalin doğrulama boyunca değişmediğini kontrol et.
- Uygulanan patch: `prepare` result'ı input inventory kapsamına ekler, dondurur,
  sonunda yeniden kontrol eder ve parent snapshot'ı stable base ile karşılaştırır.

### F3 — MEDIUM: bozulmuş immutable history ile işlem/success devam eder

- Konum: `tools/v3_publication_rehearsal.py:93`, `:96`, `:108`.
- Senaryo: tamamlanan snapshot'ın bir dosyası bozulur. Aynı signed attempt için
  `begin` hâlâ completed receipt döndürür; farklı geçerli signed attempt de bozuk
  önceki snapshot üzerinde başlayabilir. `finish` ve `audit` bazı bozulmaları
  yakalarken `begin` aynı güvenlik koşulunu uygulamaz.
- Yeniden üretim: `test_completed_begin_must_recheck_historical_tree` ve
  `test_corrupted_previous_snapshot_blocks_new_attempt`; ilk head'de ikisi **FAIL**.
- Minimum düzeltme: her locked işlem girişinde verified history'yi doğrula;
  staged/completed idempotent dönüşünden önce ilgili tree'yi de kontrol et.
- Uygulanan patch: `_integrity` tüm işlemlerde çalışır; `begin` tekrar dönüşünde
  staged tree'yi de rehash eder. Bozuk state üzerinde pointer değiştirilmez.

### F4 — MEDIUM: audit zinciri bozukken completion kabul edilir

- Konum: `tools/v3_publication_rehearsal.py:64`, `:67`, `:139`, `:163`, `:174`.
- Senaryo: staging sonrasında önceki audit event değiştirilir; sonraki event'in
  previous hash'i artık tutmaz. `audit()` bu hatayı bulur fakat `finish()` zinciri
  kontrol etmeden current pointer ve completed event yazar.
- Yeniden üretim: `test_broken_audit_chain_blocks_completion`; ilk head'de **FAIL**.
- Minimum düzeltme: hash zincirinin tutarlılığını her state mutasyonundan önce kontrol et.
- Uygulanan patch: `_locked` içinde ortak `_integrity` kontrolü; JSON duplicate ve
  non-finite değerlerini reddeden loader kullanılır; yeni local root private 0700 olur.
- Sınır: tamamen yeniden yazılmış yerel state'in authenticated olduğu iddia edilmez.
  Bu, mevcut tutarsızlık tespitinin write path'te uygulanmaması kusurudur.

### F5 — MEDIUM: retained grubun canonical mimari closure'ı eksik kalabilir

- Konum: `tools/v3_policy_profile.py:56`, `:59`, `:61`.
- Senaryo: Ro-Control stable'da yalnızca x86_64 + SRPM içerir; yeni Ro-Assist
  x86_64/aarch64 tamdır. `require_complete` yalnızca selected grubu kontrol ettiği
  için resulting stable'daki Ro-Control aarch64 eksikliğini kabul eder. Tüm repo
  için iki architecture test claim'i olması bu eksik paketi kanıtlamaz.
- Yeniden üretim: `test_retained_group_requires_all_registered_architectures`;
  canonical `config/producers-v2.json` kullanılır; ilk head'de **FAIL**.
- Minimum düzeltme: resulting set içindeki her grubun bütün registered architecture
  ve package name closure'ını registry'den denetle.
- Uygulanan patch: `require_complete` selected + retained grupları kontrol eder;
  `noarch` registry politikası korunur. V2 producer registry değiştirilmez.

### F6 — MEDIUM: yanlış baseline ile upgrade PASS üretilebilir

- Konum: `tools/v3_full_set_dnf.py:104`, `:106`, `:151`, `:183`.
- Senaryo: plan önceki snapshot A'ya bağlıdır, fakat validator'a snapshot B verilir.
  B'nin RPM'leri hedefe yükseltilebiliyorsa validator B üzerinde çalışıp `upgrade: PASS`
  üretir; plan'ın stable base identity'sini B ile karşılaştırmaz.
- Yeniden üretim: `test_dnf_baseline_must_match_plan_identity`; işlem sınırları mock
  edilen test karar hatasını gösterir; ilk head'de **FAIL**. Gerçek DNF'nin çalıştığı
  iddia edilmez.
- Minimum düzeltme: baseline null/id ve result parent snapshot'ını plan'ın stable base'i
  ile transaction öncesinde karşılaştır.
- Uygulanan patch: `validate` bu iki karşılaştırmayı transaction'lardan önce yapar.

### F7 — MEDIUM: live stable base pinned Pages tree'ye bağlanmıyor

- Konum: `tools/v3_integration.py:249`, `:250`, `:255`, `:256`.
- Senaryo: Pages HEAD doğru pinned commit'te kalır. Stable pointer daha eski fakat
  geçerli imzalı bir publication ile değiştirilir. Beta audit stable channel prefix'ini
  kapsamıyor; `prepare_live` sadece yeni local pointer'ın imzası/id'sini kontrol ederek
  eski base'i kabul eder. Tracked stable klasörünü silmek de yanlış boş bootstrap kabulüne
  yol açar.
- Yeniden üretim: `test_live_stable_pointer_must_match_pinned_git_bytes` ve
  `test_live_bootstrap_cannot_hide_tracked_stable_directory`; gerçek local Git commit
  ve GPG imzaları kullanılır, unrelated API audit sınırları mock edilir. İlk head'de **FAIL**.
- Minimum düzeltme: stable varlığını pinned Git tree'den belirle; JSON/signature byte'larını
  tracked blob ile karşılaştır, özel kopyada doğrula, operasyon sonunda ref/blob'ları recheck et.
- Uygulanan patch: `prepare_live` mevcut `verify_checkout`, `_tracked_bytes`, `_git`
  helper'larını reuse eder. Remote stable deployment acceptance hâlâ UNVERIFIED'dır.

### F8 — MEDIUM: full-set validator SRPM imzasını ve header closure'ını atlıyor

- Konum: `tools/v3_full_set_dnf.py:110`, `:111`, `:115`, `:116`, `:118`.
- Senaryo: source RPM'in gerçek RPM imzası kaldırılır; yeni hash manifest ve plan'a
  yazılıp manifest yalnızca metadata role key ile yeniden imzalanır. Validator sadece
  çalışan mimarinin binary RPM'lerini `verify_signed_rpms`'e verdiği için imzasız
  SRPM ile clean-install/upgrade gözlemi kabul edilir. Metadata imzası, ayrı RPM
  signing role doğrulamasının yerine geçer. Diğer mimarilerin header/signature ve
  SRPM linkage kontrolü de aynı yürütme yolunda yapılmaz.
- Yeniden üretim: `tests/v3-integration-fedora-e2e.py` içindeki `unsigned-source`
  senaryosu; gerçek Fedora 44 RPM/SRPM, `rpmsign --delsign`, ephemeral metadata role
  imzası ve gerçek DNF5 transaction'ları kullanır. İlk validator ile probe **FAIL**:
  `security decision unexpectedly accepted unsafe input`. Önceki log ayrıca saklandı.
- Minimum düzeltme: stable, beta ve baseline manifest'lerindeki bütün binary/source
  RPM'leri mevcut `v3_rpm_preflight.verify` üzerinden imza, header ve SRPM linkage
  denetiminden geçir; sadece native architecture DNF transaction'ına güvenme.
- Uygulanan patch: `_rpm_set_preflight` tüm set için mevcut preflight'ı kullanır;
  receipt preflight digest'lerini taşır. Repository ve key byte'ları özel kopyalarda
  sabitlenir, orijinal ve frozen inventories sonuçtan önce tekrar kontrol edilir.
- Düzeltme sonrası: gerçek unsigned-source reddi **PASS** (`RPM signature missing
  or not trusted`). Eksik dependency ve payload conflict negatiflerinin beklenen
  solver/conflict sebepleri korunur; fixture parent kimliği yeni doğrulamaya uygun
  bağlanmıştır. Bu fixture düzenlemesi negatif testi daha erken unrelated red ile
  geçirmemek içindir.

## Uygulanan patch'ler

Hepsi aynı mevcut PR dalındadır; V2 production workflow'ları değiştirilmedi.

| Commit | Değişiklik |
| --- | --- |
| `fe312d0` | Pinned key byte'ları, frozen result ve pinned Git stable base |
| `554182f` | Her rehearsal işleminde audit/history integrity ve idempotent tree kontrolü |
| `4c1fbe7` | Selected/retained architecture closure, doğru DNF baseline/parent ve tüm RPM/SRPM preflight |
| `4649257` | Dokuz izole adversarial regresyon; CI'da bütün `test_v3_*.py` testleri |

Güncel patch girişleri: `tools/v3_signed_beta_history.py:68`,
`tools/v3_rpm_preflight.py:82`, `tools/v3_integration.py:150` ve `:229`,
`tools/v3_publication_rehearsal.py:56` ve `:72`,
`tools/v3_policy_profile.py:56`, `tools/v3_full_set_dnf.py:81` ve `:99`.
Bu satırlar son implementation dosyalarına aittir; bulgu satırları yukarıda
ilk head için ayrı verilmiştir.

## Test sonuçları ve kanıt sınırları

- İlk tam PR baseline: **368 geçti, 0 başarısız, 0 atlandı**.
- İlk beş adversarial test: **5/5 beklenen reddi bulamadı (FAIL)**.
- Result TOCTOU/baseline ilaveleri: **7/7 beklenen reddi bulamadı (FAIL)**.
- İlk düzeltmelerden sonra live stable ilaveleri: yeni **2/2 FAIL**.
- Dokuz adversarial test düzeltmelerden sonra: **9 geçti**.
- Son unit kontrolü: **377 geçti, 0 başarısız, 0 atlandı**.
- Son V3 security discovery: **233 geçti, 0 başarısız, 0 atlandı**.
- Sistem RPM version/release segment karşılaştırması: gerçek `rpm.vercmp` ile
  planner'ın kabul ettiği gramerde 1.500 deterministik örnek, **0 fark (PASS)**.
  Epoch/downgrade sınırları ayrı unit testlerindedir. Bu bir formal proof değildir.
- Gerçek Fedora 44/DNF5 full-set E2E: **PASS**; bootstrap, retained bytes,
  upgrade, `.rpmnew`, channel isolation, deterministic metadata ve gerçek eksik
  dependency/payload conflict/unsigned SRPM negatifleri geçti.
- Yeni acceptance kaynak digest'i:
  `d53511af1a9f90bc4038fddc66c9f829a43421db6a60710976bbf9b5a956bf98`.
- Python compile, shell syntax, Draft 2020-12 schema/YAML parsing, disabled
  workflow ve `git diff --check`: **PASS**.
- Implementation `464925754e27714fda30305f9373b50a45368151` için otomatik GitHub
  CI **5/5 PASS**: unit policy (377), V3 security contracts (233), eski V2 Fedora
  E2E, runtime contract ve yeni V3 Fedora full-set E2E. Sayılar CI loglarından da
  kontrol edildi. Run'lar: [V2 regression/runtime](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38176096590),
  [V3 isolated acceptance](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38176096573).
- Yerel V2 E2E ilk denemesi upstream mirror timeout'undan sonra tamamlandı:
  **PASS**; final `compatibility-review.json` ve log saklandı. Rpmlint 0 error,
  4 fixture warning verdi. İkinci deneme yanlışlıkla aynı disposable evidence
  output'u kullandı ve `evidence directory already exists` ile exit 1 oldu.
  Bu ikinci deneme **PASS değildir**; review driver kaynaklı çıktı çakışmasıdır
  ve PASS toplamlarına dahil edilmez. V2 sonucunun bağımsız doğrulaması yukarıdaki
  tamamlanmış otomatik CI job'ıdır.

Yeni kanıtlar [`docs/evidence/pr71-adversarial-20261012/`](evidence/pr71-adversarial-20261012/)
içinde inventory ile hash'lenir: önceki başarısız negatifler, güncel unit/security
logları, gerçek Fedora acceptance/transaction receipt'leri ve sadece ephemeral
**public** anahtarlar. Bunlar production attestation veya authorization değildir.
CI timestamp'leri UTC 2026-10-11'e, rapor tarihi Europe/Istanbul 2026-10-12'ye aittir.

## Üretim sınırları ve V2 uyumluluğu

Tüm on bir V3 production job `if: ${{ false }}`, contents read ve `exit 1`
ile kalır. Untrusted proposal/claim/API/CI status'larının production authority'ye
geçtiği bir yürütme yolu bulunmadı. `acceptance`, claim ve local signed approval
çıktıları production publishability'yi false tutar. Pinned key consistency,
trusted root authenticity, OIDC ve protected human approval ayrı kalır.

Mevcut V2 beta/stable workflow dosyaları `main` ile byte-for-byte aynıdır.
Aktivasyondan önce çözülmesi gereken çatışmalar:

1. `.github/workflows/promote-remote-stable.yml:20` ayrı `ro-repo-remote-stable`
   concurrency grubuyla bütün beta snapshot'ını stable'a taşır (`:172`, `:251`).
   Gelecekteki V3 group composition'ı bu yol tarafından semantik olarak ezilebilir.
   Contract'ın rollout şartına göre bu yol ayrı reviewed migration ile devreden
   çıkarılmalı ve bütün stable writer'lar ortak protected CAS/serialization kullanmalı.
2. V2 promotion-validation/manifest v1 kanıtları, V3 full-set/group approval yerine
   yorumlanamaz. Şu anda böyle bir dönüşüm uygulanmadı.
3. V2 bootstrap'tan kalan kısmi architecture set, artık V3 canonical full-set gate'inde
   reddedilir. Bu V2 workflow değişikliği değildir; migration'da önce closure kanıtlanmalıdır.

## PASS kayıtları ile gerçek assurance arasındaki fark

`docs/V3-INTEGRATION-ACCEPTANCE-REPORT.md` ve 20261011 evidence dosyaları önceki
implementation commit'ine ait gerçek pozitif fixture sonuçlarıdır. O testlerin
PASS olması yukarıdaki race/negative senaryoların reddedildiğini kanıtlamaz.
Kaynak digest'i değişen review patch'leri için eski receipt'ler güncel acceptance
kanıtı sayılmaz. Yeni sonuçlar ayrıca kaynak/commit bağlamıyla kaydedilir.

Synthetic Ro-Assist/Control RPM'leri uygulama kodu içermez. Normal dwell ve
authorized fast-track'ın bir kısmı signed local contract testidir; gerçek protected
GitHub authorization değildir. DNF channel testleri izolasyon/query ve stable
transaction davranışını kanıtlar; Ro-Store UI veya real producer application kabulü değildir.

`proposal()` pure untrusted helper'dır. History artifact digest'e bağlıdır; signed
build içindeki source-release iddialarının aynı acceptance digest'in gerçek source'u
olduğu authenticated değildir. Full candidate provenance için source attestations
ve historical build-chain verification hâlâ production activation gate'idir.
Bu incelemede bu eksiklik production-authority bypass olarak sunulmadı.

## Kalan engeller ve öneri

Independent source/key roots, authenticated source/test attestations, protected
OIDC/environment approval, durable external replay/CAS, actual upstream Fedora
dependency closure, native aarch64, real Plasma/login/system/QEMU, separately
authorized Ro-Store acceptance ve Pages/CDN atomicity **UNVERIFIED/BLOCKED** kalır.
Yerel state'in tamamen yeniden yazılmasına karşı authenticated koruma veya ani
güç kaybının tüm filesystem etkileri bu testlerle ispatlanmaz.

İlk `580b8f8` head'i, doğrulanmış çevrimdışı kusurlar nedeniyle değişmeden merge
edilmemelidir. Düzeltmeler ve tamamlanan unit/Fedora/CI kontrolleriyle PR #71'in
yalnızca açıkça **NON-PRODUCTION integration milestone** olarak merge edilmesini
uygun buluyorum. Bilinen açık implementation kusuru bırakılmadı; bu, bütün saldırı
olasılıklarının yokluğunun kanıtı değildir. On bir production job kapalı kalmalı,
V2 writer migration'ı ve bütün production gates ayrı reviewed aktivasyon çalışması
ile çözülmelidir. **Production readiness önerisi verilmez.** Merge yapılmadı.
