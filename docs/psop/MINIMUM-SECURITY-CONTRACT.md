# PSOP Minimum Security Contract

Normatif MUST kurallarıdır. **Eksik, FAIL, UNVERIFIED veya BLOCKED gate production
yayınına izin vermez.** Risk kaydı yalnız açıkça belirtilen provider sınırlamalarını
kabul edebilir; bu alt sınırları gevşetemez.

| ID | Zorunlu kontrat | Doğrulama / mevcut sınır |
| --- | --- | --- |
| MSC-01 | PSOP ayrı profile, policy version/digest ve approval/receipt domain'ine sahiptir. V1, V2 veya V3 rehearsal yetkisi aktarılmaz. | PR-A inert profile negatif testleri; production parser/API PR-C'de eksik. |
| MSC-02 | Source repository/tag/commit/release/run/artifact digest ve acceptance provenance exact bağlanır; mutable branch veya `latest` input olamaz. | `ro_repo.verify_accepted_object`, V3 source pins/API audit. |
| MSC-03 | Production RPM ve metadata public roots bağımsız pinlenir; snapshot içindeki key veya manifestte yazan fingerprint tek başına trust oluşturmaz. | Canonical role key SHA256 + exact subkey fingerprint; `_keyring`, RPM preflight. |
| MSC-04 | RPM imzası, gerçek header NEVRA, SRPM linkage, selected/retained package hash ve noarch iki mimari kopyası doğrulanır. | `v3_rpm_preflight.verify`; unsigned/NOKEY/yanlış rol fail closed. |
| MSC-05 | Group/package/arch closure, canonical policy/dwell ve risk sınıfının bütün required testleri exact tam sonuçla bağlanır. Fast-track kanıt veya signing'i atlayamaz. | Planner, policy profile, group validation, full-set DNF; self-reported claim execution authority değildir. |
| MSC-06 | Metadata ve snapshot manifest exact metadata subkey ile imzalanır. RPM ve metadata secret rolleri ayrıdır; primary secret CI'ya girmez. | `FINGERPRINT!`, role-specific public exports, isolated temp signing home; secret değerleri audit dışı. |
| MSC-07 | Snapshot/history/promotion evidence append-only'dir; önceki byte'lar ve unrelated Beta görünümü korunur. | V2 stage/history testleri + whole-tree inventory; CAS tek başına yeterli değil. |
| MSC-08 | Approval profile, policy, source pins, previous Stable (veya explicit genesis), result tree, evidence, workflow/run attempt, actor, issue/expiry ve nonce'a exact bağlanır. | Protected environment + authenticated workload doğrulaması ve replay store PR-C gereği; düz JSON `approved=true` kabul edilmez. |
| MSC-09 | Snapshot/Beta/rollback/V2 Stable/PSOP/manual/App writer'ları tek branch-wide admission realm ve exclusive credential custody altındadır. | Bugün sağlanmıyor: PSOP activation BLOCKED. Scope'ları aynı token'a eklemek çözüm değil. |
| MSC-10 | Non-force expected-head CAS ve durable intent; UNKNOWN varken successor yok; base HEAD/timeout noncommit sayılmaz. | `FencedPublisher`/outbox yeniden kullanım adayı, gerçek custody/drain ayrıca kanıtlanmalı. |
| MSC-11 | Exact build/deployment/run/commit identity + descriptor, signatures ve tam result inventory public HTTPS byte verification gerekir. | API success veya tek `repomd.xml` probe yeterli değil. Timestamp/region/coverage kayıtlı olmalı. |
| MSC-12 | Client yalnız verified immutable URL kullanır; `gpgcheck=1`, `repo_gpgcheck=1`, `sslverify=1`, `skip_if_unavailable=0`; preinstalled roots ve bounded descriptor validity doğrulanır. | PR-C PSOP adapter'ı eksik; V3 client bir referans, doğrudan PSOP discovery consumer değil. |
| MSC-13 | Client local generation/state gerilemez; verification veya transaction preparation hatasında repo/state önceki verified durumda kalır; unsigned/unavailable fallback yok. | V3 client testleri yeniden kullanılır; ilk client'ın global latest bilgisi garanti değil. |
| MSC-14 | Attempt, admitted/requested/observed time, exact before/target Git OID, approval/evidence/result digest ve failure/UNKNOWN olayları kalıcı audit'e yazılır. | Success-only log yeterli değil; crash recovery ve backup/restore kabulü PR-C gate. |
| MSC-15 | Strict V3 entrypoint ve disabled workflow kilitleri korunur. PSOP acceptance hiçbir Strict V3 gate'ini PASS yapamaz. | Mevcut V3 testleri + PR-A cross-profile negative tests ve baseline guard. |

PR-A'da bu kurallar bir production implementation değildir. `psop_audit.py source`
mevcut 234 dosyanın hash/mode korumasını, ek code/workflow entrypoint'lerini ve
public roots pinlerini kontrol eder. Baseline'ın kısaltılması da reddedilir.
Repository'ye yazabilen saldırganın audit kodu ve pinini birlikte değiştirmesine
karşı bağımsız bir güven kökü değildir; PR review ve required CI ayrıca gerekir.

Signing trust zinciri: pinned producer/provenance → acceptance → exact RPM signing
role → signed snapshot + repodata metadata role → immutable descriptor/full-byte
verification → preinstalled public roots ile DNF. Approval ve writer authority bu
kriptografik zincire ek ayrı yetki kontrolleridir. Geçerli imza tek başına güncel,
onaylı veya eksiksiz Stable yayını anlamına gelmez.
