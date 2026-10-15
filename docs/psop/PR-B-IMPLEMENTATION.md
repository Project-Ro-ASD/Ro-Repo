# PR-B implementation — local disposable publisher

Base: `e11ad5160d4dbd53a320562742ad66190d408f6e`. Branch:
`codex/psop-phase2-publisher`. Production activation **BLOCKED**.

Başlangıç audit'i main'i yukarıdaki SHA, Pages'i
`097ba6ba7ab73d87c36f7ec9829b017b083b1883`, #78'i OPEN/DRAFT ve
`7a979ab0dffa4654c32ae8c5c0b1a05940180c3a` olarak yeniden doğruladı.
PR-A'nın 15 MSC, 14 gate ve 9 risk maddesi değiştirilmez.

## Uygulama / yeniden kullanım haritası

| Dosya / API | Gerçek işlev ve kullanılan mevcut bileşen |
| --- | --- |
| `psop_context.Context.create` / `Context(root, pin)` | Kendi private `/tmp/v3-backend-test-*` alanını, fiziksel device/inode kimliğini, repository/ref/origin ve birbirinden ayrı test role key pinlerini bağlar. `v3_backend_trust` key generation, strict JSON, asymmetric verification ve test-root guard'ını kullanır. |
| `psop_inputs.acquire`, `committed_stable` | Frozen input/key byte'ları, exact main/Pages pins, signed snapshot/build evidence, source provenance, dış RPM/metadata roots. V3 `_keyring`, `_signature`, `_provenance`, V2 snapshot/RPM signature verification kullanılır. Mevcut signed PSOP sonucu Git'ten tekrar doğrulanıp sonraki Stable girdisi olabilir. |
| `psop_history.read_archive`, `assess_history` | V3 `signed_archive_bundle(..., legacy_compatibility=True)` orijinal imzaları doğrular. Signed record, API observation, authenticated synthetic availability ve eksik coverage ayrı tutulur. Gerçek production dwell daima BLOCKED. |
| `psop_genesis.verify_genesis` | Exact source/history/base ve ayrı authenticated genesis approval; 404/absence authority değildir. Sadece sentetik/test genesis. |
| `psop_plan.prepare` | V3 planner + `require_complete`, canonical policy/dwell ve exact history candidate bağı, `validate_claim`, composer ve gerçek RPM header/signature/SRPM preflight. Seçili grup + korunmuş Stable kümesi; whole-Beta promotion yok. |
| `psop_result.build_metadata`, `verify_result`, `review_bundle` | `v3_repository_metadata.generate` ile deterministic repodata. Her binary view için actual `rpm --test --upgrade` ile tam kümenin dependency/file-conflict kontrolü; kurulum/scriptlet/DNF çalıştırmaz. Kapalı ReviewBundle şeması, `publishable=false`. |
| `psop_authorization.verify_approval` | Ayrı PSOP domain/context altında gerçek asymmetric signature. Policy/source/base/genesis/result/evidence, metadata key, actor/issuer/run/attempt, expiry/nonce ve expected Git OID bağları. V1/V2/V3 envelope'ları authority olamaz. |
| `psop_signing.MetadataSigner`, `sign_result` | Ephemeral certification-only test primary üretim alanından yalnız signing subkey aktarılır; ceremony alanı silinir. Signer home subkey-only doğrulanır. Exact test metadata subkey ile repomd/result manifest imzalanır, RPM byte'ları değişmez. Production fingerprint'leri reddedilir. |
| `psop_ledger.Ledger` | Mevcut `v3_backend_ledger.Ledger`/`SQLiteAdapter` engine'inin PSOP state/domain adapter'ı. Aynı signed audit chain, synchronous transactions, replay table, integrity/checkpoint ve rollback mekanikleri. İkinci transaction motoru yok. |
| `psop_outbox.Outbox` | PSOP enqueue, approval nonce consumption ile aynı V3 transaction içindedir. V3 Outbox claim/lease/fence/locked guards aynen kullanılır. |
| `psop_storage_gateway.Gateway`, `LocalTransport` | Bütün simulated writer tipleri aynı hardcoded database/realm'den geçer. V3 `FencedPublisher._admit/reconcile` ve Git object/tree engine kullanılır. Exact target/parent/all-blob SHA256 kontrolü, non-force expected-head CAS; UNKNOWN varken successor yok. |
| `psop_receipts.receipt` | Identity, approval/result/evidence/publication digest, before/target OID, created/admitted/requested/observed times ve attempt'e ait sabit signed audit checkpoint. Sonraki publication eski receipt'i değiştirmez. |

Modül dosyaları `tools/` altındadır. Üç yeni kapalı şema `schemas/psop-*-v1.schema.json`
altındadır. Unknown field/domain reddedilir; `production_activation=BLOCKED` ve
`publishable=false` production receipt'e çevrilemez.

## Trust ve test sınırı

Source/provenance, availability ve required-test claim'leri için farklı asymmetric
test issuer'ları vardır. Synthetic BASE test claim'lerinin signature ve tam
candidate/base/arch/policy binding'i doğrulanır; bunlar **gerçek DNF clean-install,
upgrade, application smoke veya GUI testleri çalıştı** demek değildir. Claim'de ve
verified result'ta `production_test_authority=false` kalır. Authenticated synthetic
availability, gerçek production history'ye trusted first-seen/dwell vermez.

Altı gerçek production public signed publication yeni adapter ile salt okunur
kontrol edildi: format/signature compatibility PASS; first availability/coverage
eksikliği BLOCKED. Hiçbir eski signed record yeniden yazılmadı. `store_tree_sha256`
olmayan kayıtta adapter'ın türetilmiş observation alanı `null` olur; bu alan signed
orijinale eklenmez ve trusted coverage sayılmaz.

Committed PSOP Stable adapter'ı approval-pinned metadata key ile orijinal PSOP
manifest/repomd imzalarını, signed inventory'yi, current ledger Stable digest'ini
ve Git ancestor/byte preservation'ı doğrular. Composer için yeni bir **imzasız
iç projection** oluşturur. Projection V2 signature veya production build evidence
taşımaz; V2 publication authority değildir ve orijinal signed PSOP byte'larını
normalize etmez. Yeniden açılan ledger'da yeni promotion önceki exact Stable
digest'ine CAS ile bağlıdır. Sentetik V2-format önceki base import'u da ayrı,
exact-bound `synthetic-test-base-import` issuer onayı ister; boş olmayan ledger'ı
yeniden initialize edemez.

## Fiziksel publication sınırı ve recovery

Yayın API'si caller-selected URL/ref/transport/credential almaz. Tek writable
transport, context'in kendi private alanındaki `storage.git` ve literal
`refs/heads/isolated-storage` ref'idir. Repository `psop-test/<id>`, origin
`https://psop-<id>.invalid` olmak zorundadır. Directory inode/owner/mode, context
pin, role roots ve backend birlikte doğrulanır. Marker veya `test=true` yeterli
değildir. Remote/credential/include config, Git hooks, alternates ve symlink'ler
reddedilir. Git subprocess'ine host HOME/credential environment aktarılmaz.

Worker bir Git credential/remote client almaz; gateway, durable outbox lease/fence
ile işi yürütür. Bu Python API'si V3 gibi trusted application code varsayar;
aynı OS kullanıcısına veya arbitrary Python execution'a karşı process sandbox
iddiası değildir. Production credential custody/worker ingress kabulü yapılmadı.

Approval consumption + enqueue atomiktir. Provider I/O'dan önce exact base/target
intent ve request zamanı durable'dır. Yanıt kaybı/process death IN_FLIGHT/UNKNOWN
bırakır. Base HEAD, timeout veya cancel noncommit kanıtı değildir; CAS kör retry
edilmez. Exact committed target/full tree uzlaştırılır. Expiry sonrası uygulanmış
CAS `COMMITTED_EXPIRED` olur; Stable head ilerlemez, yeni authority çıkarılmaz.

Bağımsız `drain` key'i yalnız yerel transport'un exclusive flock + durable epoch
fence işlemi ve exact base/checkpoint sonrasında noncommit proof üretir. Aktif iş
tamamlanırsa abort reddedilir; eski queued request epoch nedeniyle uygulanamaz.
Bu native **yerel** primitive GitHub request-drain/deadline garantisi değildir.
GitHub deadline fencing, Pages ordering ve global CDN freshness UNVERIFIED kalır.

Normal restart, replay ve pending UNKNOWN korumaları test edildi. Mevcut V3 audit
engine/checkpoint API'si kullanılır; malicious whole-database rollback'e karşı
independent production witness/backup recovery kabulü bu yerel milestone değildir.
Mevcut Git storage yanında kayıp ledger otomatik initialize edilmez.

## Source guard geçişi

Original 234-file SHA256/mode baseline ve `62d32c79…0925f1` manifest pin'i aynıdır.
Yalnız `psop_audit.ADDITIONS` setine 12 PSOP module, üç şema ve dört test/support
dosyası açık adlarıyla eklendi. Wildcard, yeni workflow veya genel `psop_*` izni yok.
Unknown production writer/credential/workflow dosyaları negatif testte reddedilir.
PR-A'nın 11 koruyucu testi değiştirilmedi. Mevcut V2/V3 kod/workflow/key/registry ve
disabled Strict V3 workflow byte'ları korunur. Allowlist'teki yeni kodun doğruluğu
review + güvenlik testlerine tabidir; self-audit bağımsız trust root değildir.

## Yerel tekrar

```bash
python3 tools/psop_audit.py source
python3 -m unittest discover -s tests -v
python3 tests/psop-offline-e2e.py /tmp/psop-e2e.json
```

Son komut Fedora RPM/signing/createrepo araçlarını gerektirir. Bu görevde cached
Fedora test imajı `1af38c532d564f256e338805615599f203d8f22895a07ce7d88d013cfda73105`
ile `--network none`, salt okunur source ve yalnız `/tmp` output mount kullanıldı.
Test fixture'ı yeni sentetik RPM üretir/ilk kez imzalar; PSOP mevcut RPM'leri
rebuild/re-sign etmez. Tam E2E üç gerçek yerel publication akışıdır; CI'nin mevcut
workflow'ları değişmeden kaldığından bu standalone RPM E2E ayrıca yerel koşulur.
Mevcut full-discovery CI yeni unit/GPG/SQLite/Git/process-death testlerini bulur.
