# PR-B kabul raporu

**Yalnız local disposable implementation. Production activation BLOCKED.**
Base main `e11ad5160d4dbd53a320562742ad66190d408f6e`.
Dosya/API/güvenlik modeli: [implementation report](PR-B-IMPLEMENTATION.md).
Exact source inventory, local logs ve E2E çıktıları:
[phase-2 evidence](../evidence/psop-phase2/).

## Sonuç matrisi

| Kapsam | Sonuç | Sınır |
| --- | --- | --- |
| Başlangıç main/Pages/#78 ref audit'i | PASS | Main exact e11ad51, Pages exact 097ba6b; #78 OPEN/DRAFT head aynı. |
| Legacy compatibility / gerçek signed history | PASS_INTEGRITY | Altı gerçek public signature, orijinal byte'lar; gerçek coverage/first availability BLOCKED. |
| Verified synthetic inputs/provenance/genesis | PASS_TEST_ONLY | Exact input/root/source/history/approval binding; 404/absence authority değil. |
| Planner/composer/RPM preflight/policy | PASS | Actual V3 reuse; selected + retained, actual header/signature/SRPM/noarch checks, canonical 7/14 günlük risk floors değişmez. |
| Deterministic unsigned result | PASS | Aynı approved composition/epoch için repodata ve unsigned inventory byte eşitliği. GPG signature timestamp'leri için determinism iddiası yok. |
| Local dependency closure | PASS_LOCAL_RPM_TEST | Tam synthetic selected+retained küme `rpm --test --upgrade` ile doğrulanır; missing retained dependency reddedilir. Native aarch64/DNF5 kabulü değildir. |
| PSOP approval/signing | PASS_TEST_ONLY | Gerçek asymmetric issuer signature, closed schema, exact result/key/identity/run/expiry/nonce binding; signer yalnız ephemeral metadata subkey. |
| Atomic consume/enqueue, shared realm | PASS | Existing V3 signed transaction engine; independent Ledger instance'ları arasında tek admission kazananı. |
| UNKNOWN/restart/reconciliation | PASS | Gerçek process death before/after CAS, lost response, restart, timeout/base-HEAD reddi; exact tree veya bağımsız local drain proof. |
| Production target/credential/domain reddi | PASS_REJECTION | Production repo/ref/origin/issuer, config helper/remote/hooks/alternates, V1/V2/V3 domain ve plain approved JSON reddedilir. |
| Üç local disposable E2E publication | PASS | Genesis; committed PSOP Stable'dan restart sonrası successor; explicit synthetic previous-base import + selected/retained publication. |
| Gerçek RPM/GPG negatifleri | PASS_REJECTION | Wrong root/role, rehashed unsigned RPM, actual wrong-arch header, partial group, missing availability/dependency, kısa dwell ve production metadata key. |
| Eski immutable byte ve receipt korunması | PASS | Current Beta/snapshot/history marker'ları korunur; sonraki publication önceki receipt checkpoint'ini değiştirmez. |
| 234-file / Beta / Strict V3 guard | PASS | Original baseline/digest aynı; yalnız explicit PSOP additions. Workflow/production profile/key/registry değişmedi. |
| Yerel full discovery | PASS | 619 başlangıcı + 33 yeni test = 652; exact log/komut `tests.json` içinde. Yeni test skip/allow-failure/assertion kaldırma yok. |
| Final-head CI | Gerekli | Exact head ve mevcut sekiz check'in son sonuçları PR'ın checks/teslim açıklamasında doğrulanır. Historical veya yerel PASS CI yerine sayılmaz. |
| Gerçek production first-seen/dwell/test authority | BLOCKED | Synthetic issuer ve consistent claim gerçek üretim kanıtına yükseltilmez. |
| DNF5 client descriptor/state / external Pages HTTPS / GUI | UNVERIFIED | PR-C'ye aittir; bu milestone'da tamamlandı denmez. |
| Production writer custody/GitHub policy/keys/client rollout | BLOCKED | Ayrı açık operator yetkilendirmesi ve tüm gate'ler gerekir; burada müdahale edilmedi. |
| Strict V3 / PSOP production activation | BLOCKED | Mevcut hard-deny ve disabled workflow aynıdır; bütün PSOP artifacts publishable=false. |

Geliştirme sırasında raw bytes evidence hashing ve moving global checkpoint'in eski
receipt'i değiştirmesi tespit edilip düzeltildi. Son incelemede history
candidate digest'i planner candidate'ına ayrıca bağlandı; başka candidate'tan
dwell taşınması unit ve gerçek RPM E2E negatifinde reddedilir. PASS, yalnız raporlanan final
koşular içindir; önceki başarısız geliştirme koşuları başarılı kabul edilmez.
Sandbox içindeki tekrar koşusunda GPG agent socket erişimi reddedildi; final
local koşular disposable test anahtarlarıyla socket erişimi olan ortamda yapıldı.

## PR-C'ye kalanlar

PSOP client descriptor/state entegrasyonu, gerçek Fedora 44 DNF5 install/upgrade,
client imza/hash/freshness negatifleri, provider fault injection'ın genişletilmiş
entegrasyonu, ayrıca yetkilendirilecek disposable Pages HTTPS kabulü, Beta
regresyonlarının dış kabulü ve operator runbook/readiness raporu. PR #78'in
fault testleri kopyalanmadı veya branch'i değiştirilmedi; mevcut V3 fixtures ve
PR-A incelemesi reuse kaynağıdır. Local signed SQLite/Git başarılarından provider
deadline fence, Pages build ordering veya global CDN freshness çıkarılmaz.

Production ortamına bağlantı veya V2 custody geçişi PR-C'nin önkoşulu değildir.
Ayrı operator aşamasından önce gerçek Stable/Beta publication, main/pages-storage
push, production secret/issuer provisioning, GitHub environment/ruleset/reviewer
değişikliği, DNS/Cloudflare/HP işlemi veya merge yapılmaz.
