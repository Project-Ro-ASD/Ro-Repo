# V2 component Beta orkestratörü: güvenlik ve test raporu

## İncelenen kapsam

Taban: `9fb1deb` (gerçek `origin/main`, PR #84 dahil). Tek dal ve tek PR.
Mevcut V2 yayın mimarisi ve trust anchor dosyaları korunur. Stable/V3 runtime,
producer registry, schema ve production secret/environment/ruleset değişmez.
Yereldeki ana checkout'un kullanıcı dosyaları ayrı worktree ile korunur.

Değişen/eklenen işlev dosyaları:

- `.github/workflows/publish-component-beta.yml`: iki kimlik girdisi ve isteğe
  bağlı preflight; sadece mevcut token, `contents: read`, `actions: write`.
- `tools/component_beta.py`: allowlist/Release/tag/manifest/parent preflight,
  UUID request correlation, run/ref/SHA/attempt/artifact doğrulaması, dört
  mevcut dispatch aşamasının sonlu sıralaması, state ve summary.
- `scripts/component_beta_storage_guard.py`: iki yazıcıda exact storage HEAD
  ön koşulu; request kimliği varsa koşulsuz zorunlu, manuel eski yol korunur.
- Dört mevcut workflow: opsiyonel request ID ve run-name. İki yazıcıda ayrıca
  opsiyonel exact storage commit girdisi ve kilit altında guard çağrısı.
- `tests/test_component_beta.py`: izole transport ve orkestrasyon fixture'ları.
- `docs/PUBLISH-COMPONENT-BETA.md`: Türkçe operatör rehberi.
- Bu inceleme, README bağlantısı ve kesin kaynak hash sözleşmesi/pin güncellemesi.

## Güvenlik kanıtları

- `accept-component.yml` kabul, native immutable kontrolü, kayıtlı signer,
  exact attested workflow attempt, test evidence ve signing adımları aynıdır.
  `repo-production-signing` ve signing secret erişimleri taşınmaz.
- Candidate'nin production imzası, incremental parent doğrulaması ve mevcut
  artifact teslimi korunur. Orkestratör exact run ve artifact ID/digest'lerini
  sınar; indirilen accepted/candidate ZIP SHA-256'sını API digest'iyle kıyaslar.
  Candidate metadata'sı parent manifest digest ve tek signing run'a bağlanır;
  mevcut Pages workflow'u tüm imzalı candidate'i tekrar doğrular.
- Son Beta işi `repo-production-signing` ve `repo-beta` environment'larını,
  `ro-repo-pages-storage` kilidini, expected-head CAS ve uzak ağaç/imza
  doğrulamasını korur. Yeni guard bu kontrollere eklenir.
- Yalnızca main ve canonical repository kabul edilir. Dispatch sonrası run
  SHA, branch, event, path, repo ve attempt doğrulanır. UUID birden fazla run
  ile eşleşirse veya süre içinde bulunamazsa akış durur. En yeni run seçilmez.
- İki eşzamanlı ana istek concurrency ile ayrılır. Bağımsız manuel yazıcıya
  karşı initial storage SHA → tek Pages commit'i → aynı SHA ile Beta writer
  koşulu uygulanır. Parent değişip geri alınsa bile git ancestry değişir.
- API çağrıları sonludur; belirsiz POST ve rate limit tekrar edilmez. Bilinen
  aktif run için iptal istenir. Zorla iptal veya belirsiz dispatch durumunda
  insan uzlaştırması gerekir; run linkleri/istek ID'si state'te tutulur.
- Ana işi rerun etmek reddedilir. Yarım yayın otomatik tekrar oynatılmaz;
  remote verification hatası Beta'nın değişmediği iddiasına dönüştürülmez.
- Kaynak koruma denetimi gevşetilmez: mevcut 234 dosyalık historical baseline
  korunur; yalnızca bu PR'ın tam dosya SHA-256 değerleri reviewed V2
  sözleşmesine eklenir/güncellenir ve sözleşmenin kesin pini yenilenir.

## Test kapsamı

`python3 -m unittest tests.test_component_beta -v` izole API fixture'larıyla:
allowlist; draft/mutable/eksik immutable; exact tag ve annotated tag peel;
repo/tag/commit/release/component uyuşmazlığı; yanlış run/path/event/ref/SHA/
attempt; sıfır/çoklu run; yanlış/eksik/expired/duplicate artifact; ZIP hash ve
metadata; signing hata/iptal/ret; environment timeout; parent/digest değişimi;
eşzamanlı storage yazımı/rollback; snapshot numarası çakışması/tükenmesi;
API timeout/rate limit; son bağımsız doğrulama hatası; preflight'ın dispatch
etmemesi; eski manuel girişler, environment'lar ve CAS kontrolleri.

V2 regresyonları: production signing/snapshot, Pages publication, remote Beta,
rollback, producer registry, incremental candidate, selected Stable ve remote
Stable promotion. Normal PR CI mevcut Fedora 44 RPM/DNF ve pinned gerçek
producer payload testlerini de çalıştırır. Tüm test signing anahtarları geçici
ve test içindir. PR CI üretim kabulü, protected signing veya yayın dispatch'i
yapmaz. Gerçek environment reviewer davranışı ve canlı CDN yayını bu PR'da
çalıştırılmaz; bunlar ilk yetkili operatör yayınının operasyonel kontrolleridir.

Testlerin kesin sonuçları ve CI bağlantısı PR açıklamasında kaydedilir.

Dahili `expected_source_commit` ve `request_deadline` alanları otomatik taşınır.
Her alt iş, environment onayından sonra kaynak SHA/ref/repo/attempt ve süreyi
kontrol eder; iki yazıcı mutasyondan hemen önce süreyi yeniden sınar.
Eski manuel çağrılarda bu isteğe bağlı alanlar boş kalabilir.

## Yerel doğrulama kaydı

- 25 orkestratör testi ve seçilmiş V2 Beta/Stable testleri birlikte: **113 test,
  PASS**. Değişen beş workflow: **actionlint 1.7.12 PASS**; Python derleme ve
  `git diff --check`: PASS.
- Kesin source-preservation audit: **PASS**, issues boş; production activation
  hâlâ **BLOCKED**. Trust kökleri ve Stable workflow'larında değişiklik yok.
- Güncel Pages commit'i `5b959bcf835d625cb5e3085f3cc1a0910c005e13` yerel
  kopyasında Fedora 44, ağsız ve salt okunur `verified_parent` testi: PASS.
  Parent `repo-f44-20261021-001`, manifest SHA-256
  `46f88b2aa5db0478017e994c166ff277e6172e8b7b14607195c96d1c316b490c`.
- Gerçek immutable Theme `v1.1.7` için sadece GET/asset indirme ile
  `producer_identity`: PASS; Release `418396556`, commit
  `89f1251f8e5509331eb620a5a19c49dca4df36d9`. Kabul dispatch'i yapılmadı.
