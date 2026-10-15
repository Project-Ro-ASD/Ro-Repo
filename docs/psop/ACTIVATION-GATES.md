# Operator Activation Gates

**PR-A activation vermez.** Aşağıdaki her gate için exact evidence link/digest,
gözlem zamanı, actor ve reviewer kaydı gerekir. Eksik/FAIL/UNVERIFIED/BLOCKED gate
kapalıdır. Bu dosya bir çalıştırma veya dispatch talimatı değildir.

[Implementation contract](IMPLEMENTATION-CONTRACT.md) aşamaları bu production
gate'lerini gevşetmez: PR-B approval/signing, durable ledger/outbox ve ortak gateway
dahil uygulama kodunu yalnız disposable/test publication için geliştirir; PR-C
client descriptor/state, gerçek Fedora 44 DNF5, negatif/fault/HTTPS kabulü, Beta
regresyonları ve operator runbook/readiness raporunu tamamlar. Production gate'leri
kapalıyken bu izole geliştirme ve testler yapılabilir; gerçek production hedefe
erişim yetkisi çıkarılamaz. Writer custody cutover, GitHub ayarları ve canlı Stable
aktivasyonu PR-B/PR-C'nin dışındaki ayrı operatör aşamasıdır; yalnız açık
yetkilendirme ve bütün gate'ler geçtikten sonra yapılabilir.

| Gate | Gerekli kanıt | Şimdiki durum |
| --- | --- | --- |
| G-01 Scope ve yeniden audit | Reviewed PSOP implementation, pinned main/Pages/registry/trust; `source` guard PR-B için bilinçli yeni kontratla değiştirilmiş. | PR-A hazırlık PASS; implementation BLOCKED. |
| G-02 Gerçek writer custody | Snapshot/Beta/rollback/V2 Stable/PSOP/manual/App/PAT envanteri; branch-wide gateway; eski credential/run geçişi; unresolved requests için gerçek drain veya blok. | UNVERIFIED/BLOCKED; dört doğrudan V2 writer mevcut. |
| G-03 Beta eşdeğerliği | Output byte/history/rollback/signing davranışı aynı; geçiş sırasında yarım kayıp ve UNKNOWN etkisi kabul edilmiş. | PR-A byte preservation PASS; gelecekteki gateway migration UNVERIFIED. |
| G-04 Environment ve repository policy | Main-only deploy policy, gerçek reviewer, yetki/bypass/self-review/required checks değerlendirmesi; named approval actor. | Ayarlar okunabildi; self-review mümkün, minimum review 0. Production kabulü BLOCKED. |
| G-05 Signing/trust | Exact public role pins; production signing role izolasyonu, actual RPM/metadata signatures; private custody/backup/rotation için bağımsız operator evidence. | Public byte doğrulaması PASS; private custody UNVERIFIED. |
| G-06 History ve genesis | Bütün signed history korunmuş; gerçek first-public availability/coverage; varsa önceki Stable exact tree; yoksa explicit bound genesis approval. | Reachable tree taraması PASS; trusted history/genesis kabulü BLOCKED. |
| G-07 Candidate ve test authority | Exact group plan, complete selected+retained set, canonical dwell/risk tests, full-set DNF ve authenticated evidence. | 12 Ekim test-only x86_64 11/11 PASS; production candidate/evidence UNVERIFIED. |
| G-08 Risk-class runtime | Gerekli native arch, Plasma/login/VM/boot/reboot/recovery evidence; test-only key sonuçları production imza yerine geçmez. | aarch64/GUI/VM UNVERIFIED; ilgili groups BLOCKED. |
| G-09 Approval ve replay | PSOP-specific authenticated approval exact policy/base/result/evidence/attempt/expiry/nonce; durable consumption ve restore testleri. | API/persistence integration eksik: BLOCKED. |
| G-10 Publishing recovery | Sole writer CAS, full old-tree preservation, durable intent, crash/response-loss reconciliation; UNKNOWN'a successor yok. | V3 disposable testleri var; PSOP production binding UNVERIFIED. |
| G-11 Pages gözlemi | Exact Git/build/deployment/run; descriptor/signature ve bütün public paths byte parity; coverage/time recorded. API success yeterli değil. | PSOP production sonucu yok: UNVERIFIED. |
| G-12 Client kabulü | Preinstalled trust, immutable PSOP URL, fail-closed DNF, local monotonic state, missing/stale/replay rejection ve atomic failure recovery. | PSOP client adapter eksik: BLOCKED. |
| G-13 Risk kabulü | R-01..R-09 disposition; provider sınırları için named signed acceptance; Beta incident etkisi onaylı. | PENDING/BLOCKED. |
| G-14 Ayrı activation yetkisi | Yukarıdaki exact deployment için operator tarafından verilmiş açık production activation talimatı ve review. | Bu görev açıkça yasaklıyor: BLOCKED. |

Strict V3 production lock bu gates tamamlansa bile değişmez. PSOP deployment
approval'ı Strict V3 activation değildir. Gelecekte approval expiry sonrası
uygulanmış CAS görülürse olay reconciliation'a gider; yeni publication/client
authority bu eski approval'dan çıkarılmaz.

Incident sırasında yalnız audit/kanıt toplama ve güvenli yerel hazırlık sürdürülebilir.
Provider UNKNOWN, public-byte mismatch, root mismatch veya history drift olduğunda
yeni Stable/Beta mutation'ı gateway tarafından durdurulur; otomatik force push,
kör retry veya unsigned fallback yoktur. Mevcut V2 Beta davranışı PR-A'da aynıdır;
bu gateway davranışı ancak ayrı geçiş kabulünden sonra yürürlüğe girebilir.
