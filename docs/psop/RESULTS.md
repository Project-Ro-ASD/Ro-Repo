# PR-A sonuç raporu

Bu PR yalnız PSOP hazırlığıdır. **Production activation BLOCKED.**

## Değişiklikler ve kararlar

- `docs/psop/`: ADR, minimum security contract, threat model, risk acceptance,
  Strict V3 karşılaştırması, operator gates, audit ve PR-B/PR-C dosya/API haritası.
- `tools/psop_audit.py`: sabit allowlist GitHub GET collector, reachable Git tree /
  immutable history kontrolü, pinned public signing audit ve phase-A source guard.
- `tests/test_psop_contract.py`: inert profile/authority, wrong trust, Strict V3
  lock, V1 rejection, source mutation/new writer, deleted historical Stable ve Beta
  rollback isolation için 11 kontrat testi. Mevcut fixture/testler yeniden kullanılır.
- `docs/evidence/psop-phase1/`: exact main/Pages/GitHub/HTTP/signing/source/test
  kanıtları; mevcut production materyaline değişiklik yok.

Temel mimari karar: PSOP ayrı approval/receipt domain'idir. Aynı storage branch'i
için bütün V2/PSOP/manual writer'lar tek durable admission realm ve exclusive
credential custody altında olmadan PSOP açılamaz. Provider deadline fencing,
Pages ordering ve global CDN freshness vaat edilmez. Full immutable-byte integrity,
signing, required evidence, client fail-closed ve UNKNOWN successor block zorunludur.

## PASS / FAIL / UNVERIFIED / BLOCKED

| Denetim | Sonuç | Kanıt / etkisi |
| --- | --- | --- |
| Main/Pages/current Beta/run/#77/#78 referansları | PASS | `github-before/after.json`; iki API observation seti içerik olarak aynı. |
| Başlangıçta #79 varlığı | UNVERIFIED → bu PR oluşturuldu | İki başlangıç GET'i 404 idi; sonrasında PR-A'ya #79 tahsis edildi. |
| Tarihsel araştırma ve immutable history | PASS | 300 reachable tree, Stable hit yok; parent→child snapshot/history drift yok. Mutlak tarihsel yokluk UNVERIFIED. |
| Production public signing | PASS | Beş snapshot, 86 physical RPM path, altı publication; helper recheck snapshot/build/run bağlarını da doğrular. |
| Client keyring/repo trust | PASS | Signed RPM payload: canonical public key hashes, Beta açık, Stable kapalı; iki GPG check açık. |
| Mevcut V2/V3 kod ve Beta workflow korunması | PASS | 234-file hash/mode source guard; yeni PSOP workflow yok. |
| Yerel testler | PASS | Son tam discovery: **619/619**, bunun 11'i yeni PSOP testi. Önceki main-runtime seti 608/608; `tests.json` ve compressed loglar kayıtlı. |
| Sandbox ilk full deneme | FAIL — ortam kısıtı | Loopback/GPG socket izinleri nedeniyle 55 error; izinli yerel tekrarları ayrı kaydedildi. Bu deneme başarılı test kanıtı sayılmaz. |
| PR #78 diagnostic | PASS | Exact head'in `/tmp` kopyası; fault tests ve güçlendirilmiş CAS race. Bu PR'a taşınmadı. |
| GitHub CI | PASS — 8/8 SUCCESS | `72186d7` implementation head'i için `ci.json`; sonradan yalnız CI kaydı/belgeler güncellendi. [Son head checks](https://github.com/Project-Ro-ASD/Ro-Repo/pull/79/checks) ayrıca zorunludur; skip/allow-failure değişikliği yok. |
| Eski archive'ın Strict V3 history uyumu | BLOCKED | `unexpected signed publication fields`; imzalı tarih değiştirilmedi. |
| Public first-availability witness, private custody, App/PAT/manual authority | UNVERIFIED | Public imza veya current API cevabı bunların kanıtı değildir. |
| Environment/ruleset okuma | PASS | Reviewer/main-only policies var; `prevent_self_review=false`, min reviews 0, CODEOWNERS enforce false, Pages branch unprotected. |
| PSOP writer isolation/approval/client implementation | BLOCKED | PR-B/PR-C ve activation gates gerekiyor. |
| aarch64 / Plasma / gerçek VM/boot/installer kabulü | UNVERIFIED | 12 Ekim x86_64 DNF başarısı bu kapsamları karşılamaz. |
| Strict V3 production / PSOP production | BLOCKED | Mevcut hard deny + disabled workflow; bu görev activation yetkisi vermiyor. |

CI koşuları: [V2 tests](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38724034417),
[V3 backend](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38724034420),
[V3 integration](https://github.com/Project-Ro-ASD/Ro-Repo/actions/runs/38724034440).
`unit-policy`, `fedora44-e2e`, `acceptance-runtime-contract`, `backend-security`,
`postgres-transactions`, `closure-tls-postgresql`, `security-contracts` ve
`fedora44-full-stable-set` başarılıdır. Local test kanıtından ayrı GitHub job
state'leri kaydedildi; production activation hâlâ BLOCKED.

## Yeniden kullanım, aşama dağılımı ve açık girdiler

Planner/composer/RPM preflight/policy profile/full-set DNF/deterministic metadata,
source/history/API pinning, group/receipt validation, ledger/outbox/fenced publisher
ve immutable client verification mekanikleri yeniden kullanılır. Production/test
scope sınırları korunur. Ayrıntılı dosya/API/dependency haritası
[implementation contract](IMPLEMENTATION-CONTRACT.md) içindedir.

PR-B verified inputs/history/genesis, planner/composer, deterministic result,
PSOP approval/signing, durable ledger/outbox ve ortak writer gateway uygulamasını
yalnız disposable/test publication için geliştirir. Legacy archive/first-seen witness
ve explicit genesis semantiği bu aşamada çözülür; yeterli kanıt yoksa fail closed
kalır. PR-C client descriptor/local monotonic state entegrasyonunu, gerçek Fedora
44 DNF5, imza/hash negatifleri, provider fault injection, disposable Pages HTTPS,
Beta regresyonları ve operator runbook/readiness raporunu tamamlar.

Gerçek writer custody/V2 cutover, GitHub ayarları ve canlı Stable aktivasyonu ayrı
operatör aşamasıdır; açık yetkilendirme ve bütün gate'ler geçmeden yapılamaz.
Production writer/secret ve activation B/C boyunca kapalı kalır. Bağımsız olmayan
review düzeni ve gerçek required-test authority üretim gate'i olarak açık kalır.
Provider'ın üç sınırlaması yeni boolean/receipt alanlarıyla PASS yapılamaz.

## Beta ve production'a müdahale edilmediğinin kanıtı

Exact main'den yeni feature branch kullanıldı. Source guard existing workflows,
runtime/config/keys/schema/scripts/tests ve V1 kayıtlarını byte/mode olarak
koruyor. Main ve Pages ref'leri iki GET'te aynı; #78 metadata/head/state aynı;
environment/ruleset/Pages response'ları aynı. Yalnız feature branch push ve bu
tek PR için GitHub write kullanılır; `pages-storage` push, publication dispatch,
secret value okuma/değiştirme, environment/ruleset mutation, DNS/Cloudflare/HP
işlemi veya merge yapılmaz. Before/after snapshots bu gözlem aralığındaki drift'i
gösterir; bütün repository aktörlerinin geçmiş eylemlerine dair exhaustive audit
log iddiası değildir.
