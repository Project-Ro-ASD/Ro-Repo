# PSOP Risk Acceptance Register

15 Ekim 2026. **Henüz imzalanmış production risk kabulü yoktur.** Aşağıdaki owner
rolü önerilen sorumludur; atanmış/onaylamış kişi anlamına gelmez. Kabul kaydı exact
policy/result/attempt, named actor, tarih, geçerlilik süresi ve review gerekçesi
taşımalıdır. Risk kabulü MSC-01..15'i veya Strict V3 lock'u bypass edemez.

| ID | Risk / etkisi | Kontrol ve kabul koşulu | Owner / durum |
| --- | --- | --- | --- |
| R-01 | Admission'da geçerli istek approval expiry sonrası GitHub'da uygulanabilir. | Intent zamanları ve exact target kalıcı; UNKNOWN successors'ı bloke eder. PSOP yalnız local admission deadline vaat eder. Provider deadline fence gerektiren kullanım kabul edilemez. | Release engineering; PENDING, activation BLOCKED. |
| R-02 | Önceki Pages build sonradan public görünümü geriletebilir. | Immutable URLs, tam byte verification ve local client monotonicity; verification zaman/noktası kaydedilir. Sürekli latest visibility vaat edilmez. | Release engineering + client owner; PENDING. |
| R-03 | CDN stale/missing/mixed içerik verir; ilk client valid eski signed view görebilir. | Exact inventory/signatures; expiry ve local state; transaction fail closed. Global freshness, zero downtime ve bütün PoP coverage vaat edilmez. | Release engineering + client owner; PENDING. |
| R-04 | UNKNOWN provider request bütün shared storage realm'ini, gelecekte Beta işlemlerini de durdurur. | Manual incident escalation, durable reconciliation; base HEAD/timeout/cancel ile unlock yok. Gerçek drain kanıtı yoksa pause sürer; ayrı origin alternatifi yeni ADR ister. Beta operasyon etkisine açık kabul gerekir. | Beta operator + release engineering; PENDING. |
| R-05 | Aynı maintainer farklı teknik rolleri kullanabilir; self-review mümkün. | Environment reviewer mevcut fakat `prevent_self_review=false`; main gerekli review sayısı 0, CODEOWNERS enforce değil. Named operator kontrolü ve bağımsız review/uygun düzeltilmiş ayarlar gösterilmeli. | Repository admin; PENDING. |
| R-06 | aarch64 Tier 2, Plasma/login, gerçek VM/boot/installer kabulü yok veya kısmi. | Exact risk-class evidence tamamlanmadan o group/arch aktive edilmez. x86_64 testlerini diğer mimarilere genişletilmiş başarı sayma. | Package/group owner; UNVERIFIED/BLOCKED. |
| R-07 | Historical archive alanları Strict V3'e uymaz; gerçek first availability kanıtı eksik. | İmzalı byte'lar değişmez. PR-B'de legacy witness/coverage adapter tasarla; observed timestamps trusted first-seen diye gösterilmez. | Evidence owner; BLOCKED. |
| R-08 | Eski silinmiş/unreachable Stable geçmişi mevcut gözlemde görünmez. | 300 reachable tree + workflow runs + explicit operator genesis kararı; geçmiş yokluğu mutlak iddia edilmez. | Release engineering; UNVERIFIED. |
| R-09 | Root key/custody compromise. | Canonical public role roots ve fail-closed verification; private custody/restore/rotation dış kabulü gerekir. Secret okunarak kanıt toplanmaz. | Signing custodian; custody UNVERIFIED. |

Eksik signing, bilinmeyen public root, untrusted execution claim, key-role
karışması, eksik required evidence veya paralel yetkili writer risk acceptance ile
geçirilemez. Provider'ın üç sınırlaması PSOP'de açık kalabilir; bunları Strict V3
başarısına dönüştürmek yasaktır. Bu kayıt hiçbir credential veya channel açmaz.
