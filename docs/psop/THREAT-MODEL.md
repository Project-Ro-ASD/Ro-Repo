# PSOP Threat Model

Varlıklar: production public trust root kimliği, exact signed RPM/repodata,
immutable history, Beta kullanılabilirliği, Stable base/generation, approval,
publisher credential ve kalıcı audit. Sınırlar: producer → acquisition → policy/
test worker → signing environment → approval → storage gateway → GitHub/Pages/CDN
→ client. Worker/remote checkout/self-reported JSON otomatik trusted değildir.

| Tehdit / aktör | Kontrol | Kalan risk / gate |
| --- | --- | --- |
| Compromised producer aynı asset/tag altında farklı byte sunar. | Exact source/run/release pins, attestation, acceptance manifest, producer/signed digest ayrımı. | İzinli kötü amaçlı kaynak semantic review/testten kaçabilir; package review gerekir. |
| Payload kendine ait public key/fingerprint taşır. | Canonical dış pin, ayrı role exports, actual signature/header/SRPM verification. | Root dağıtımı/rotation bağımsız onay ister; embedded key tek başına güvenilmez. |
| Reviewer veya tek maintainer kötü amaçlı change/onay verir. | Protected env, exact result approval, policy/test evidence, append-only audit. | Self-review bugün engellenmiyor; organizational separation UNVERIFIED. R-05. |
| Workflow artifact'i, claim veya eski approval başka result'a replay edilir. | Artifact/run/attempt digest bağları, profile domain, nonce tüketimi ve previous-state CAS. | PSOP approval verifier ve replay store eksik; production BLOCKED. |
| Beta/Stable/snapshot/manual writer aynı dalı bağımsız değiştirir. | Branch-wide tek admission + custody, whole-tree preservation, expected-head CAS. | Mevcut writer'lar henüz gateway dışında. Yeni PSOP credential açılamaz. |
| Kabul edilmiş CAS geç uygulanır; yanıt kaybolur. | Durable exact intent, UNKNOWN block, target reconciliation; expiry sonrası yeni authority yok. | Provider deadline fence yok. Base HEAD request-drain kanıtı değildir; R-01/R-04. |
| Eski Pages build'i yeni doğrulamadan sonra görünür olur. | Exact identity + complete-byte probes, immutable client view, yerel monotonic state. | Monoton public visibility garanti değil. R-02. |
| CDN bir dosyayı geciktirir, karışık veya eski signed sonuç döndürür. | Bütün inventory hash/signature kontrolü; unavailable transaction başlamaz. | Global freshness/availability yok; yeni client geçerli eski descriptor görebilir. R-03. |
| Root V1 dosyaları veya 404 Stable bootstrap sanılır. | Yalnız signed manifest/verified lineage; explicit genesis approval + historical audit. | Silinmiş/unreachable geçmiş UNVERIFIED; operator incelemesi zorunlu. |
| Symlink/path traversal/ek RPM ile composer'a gizli payload sokulur. | Existing composer/preflight regular paths, tam file inventory ve source guard. | Parser/runtime değişikliklerinde mevcut negatif testler tekrar çalışmalı. |
| Ledger rollback/split-brain/worker restart audit veya replay kaydı kaybettirir. | Durable transaction/outbox, checkpoint, backup/restore ve independent observation. | Üretim persistence/authority/custody kabulü eksik. Timeout ile kilit temizlenmez. |
| Key compromise veya signed malicious package. | Offline primary, role separation, revocation/rotation runbook, review ve exact-byte test. | Secret custody/backup içerikleri bu audit'te okunmadı; public signature geçmesi private custody kanıtı değil. |

Provider, client ağı ve workstation yöneticisinin ele geçirilmesiyle availability
engellenebilir. Fail-closed davranış availability garantisi değildir. Native
aarch64 ve gerçek Plasma/login/installer/boot kabulünün eksikliği R-06 ve activation
gates'te görünür kalır; x86_64 container DNF sonucu bunları karşılamaz.

PR #78'deki delayed CAS, response-loss, iki writer yarışı, out-of-order build,
14 stale/missing member fault ve restart senaryoları incelendi. Bu modelleri burada
yeniden yazmıyoruz veya gerçek provider garantisi saymıyoruz. Main'deki mevcut
V3 adversarial/client/preservation testleri çalışmaya devam eder; #78 merge edilmedi.
