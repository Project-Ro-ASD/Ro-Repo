# Strict V3 ve PSOP karşılaştırması

Strict V3 sütunu istenen sözleşmeyi anlatır; native Pages üzerinde sağlandığı
anlamına gelmez. PSOP sütunu tasarım hedefidir; PR-A bir uygulama değildir.

| Konu | Strict V3 | PSOP |
| --- | --- | --- |
| RPM/source integrity | Pinned provenance, full result, role signing. | Aynı alt sınır; planner/composer/preflight yeniden kullanılır. |
| Component policy | Group atomicity, retained set, risk floors ve authenticated required tests. | Aynı policy; V2 whole-Beta promotion ile karıştırılmaz. |
| Snapshot/history | Immutable signed views ve complete inventory. | Additive immutable result/history; Beta byte preservation zorunlu. |
| Approval | Exact request/base/result/evidence, authenticated identity, replay consumption. | Ayrı PSOP domain; aynı exact binding ihtiyacı. V3 rehearsal/approval otomatik aktarılmaz. |
| Writer scope | Tek fenced storage authority ve durable replay/audit ledger. | Aynı dalda bütün writer'lar tek custody/admission realm olmadan activation yok. |
| Deadline | Provider mutation uygulanırken approval deadline/fence garantisi gerekir. Native GitHub'da kanıt yok: BLOCKED. | Yerel admission expiry kontrolü; kabul edilmiş istek daha geç uygulanabilir. R-01 açık kabul gerekir. |
| Pages build ordering | Monoton cutover/visibility gereği native branch Pages'de kanıtlanmadı: BLOCKED. | Exact identity ve gözlem anında full-byte doğrulama; sonraki eski build görünürlüğü garanti dışı. R-02. |
| CDN freshness | Fresh discovery + complete view; global freshness/continuity ayrıca kanıt ister. | Global freshness/atomik PoP görünümü vaat edilmez. Missing/mixed fail closed; R-03. |
| Client | Independent fresh discovery, checkpoint/generation, immutable view. | Yeni PSOP descriptor/client adapter; pinned roots, bounded validity, immutable hashes ve local monotonic state. Global latest discovery servisi varmış gibi gösterilmez. |
| Recovery | Exact durable intent/independent evidence; UNKNOWN successors'ı durdurur. | Aynı güvenlik alt sınırı; timeout/operator varsayımıyla unlock yok. |
| Bugünkü üretim durumu | `production_publish` ve `activate_production` reddeder; workflow bütün job'ları false. | Writer/API/client henüz yok; `phase-a-profile.json` authority boş, activation false. |

Provider değerlendirmesi: [GitHub updateRefs](https://docs.github.com/en/graphql/reference/git#updaterefs)
expected `beforeOid` kontrolüyle atomic ref mutation belgeler; approval deadline
alanı sunmaz. [Actions concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
workflow/job scheduling içindir. [Pages REST](https://docs.github.com/en/rest/pages/pages)
build/deployment gözlemleri verir. **Çıkarım:** bu API'lerden provider deadline
fence, monoton public build ordering veya global CDN freshness sonucu çıkarılmaz.
15 Ekim 2026'da resmi kaynaklar yeniden kontrol edildi. PR #78'in test modeli bu
sınırlamaların karşı örneklerini sınar; gerçek provider kabul kanıtı değildir.
