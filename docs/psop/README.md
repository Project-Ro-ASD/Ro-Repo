# Pages Stable Operational Profile — PR-A

15 Ekim 2026. **Hazırlık sözleşmesi; production activation BLOCKED.** Temel:
`3d4b56bd7509988f3715305ab9e2e09394635448`. Bu PR yeni bir publisher kurmaz.

Kısa implementation plan ve değişiklik haritası:

1. Main, Pages, PR #77/#78/#79, Beta run, tarihsel ağaçlar ve public signing
   zincirini yeniden doğrula; GitHub ayarlarını yalnız GET ile gözlemle.
2. [Envanter ve signing denetimi](AUDIT.md) ile gözlem, tarihsel kanıt ve
   production kabulünü ayır.
3. [ADR](ADR-001.md), [minimum güvenlik sözleşmesi](MINIMUM-SECURITY-CONTRACT.md),
   [tehdit modeli](THREAT-MODEL.md), [risk kaydı](RISK-ACCEPTANCE.md) ve
   [Strict V3 karşılaştırması](STRICT-V3-VS-PSOP.md) üzerinde tek profil tanımla.
4. [Operator gates](ACTIVATION-GATES.md) ve [PR-B/PR-C sözleşmesi](IMPLEMENTATION-CONTRACT.md)
   ile sonraki değişikliklerin dosya, API ve kabul sınırlarını sabitle.
5. `tools/psop_audit.py`, `tests/test_psop_contract.py` ve
   [kanıtlar](../evidence/psop-phase1/) ekle; mevcut V2/V3 testlerini çalıştır.

Değişiklikler yalnız bu belgeler, inert `phase-a-profile.json`, kanıtlar ve iki
audit/test dosyasıdır. Mevcut `.github/`, runtime, registry, schema, key ve test
dosyaları korunur. `test.yml` zaten `unittest discover` ile yeni testleri bulur;
yeni workflow veya CI istisnası gerekmez. PR #78'in provider fault testleri bu
branch'e taşınmaz; incelemesi ve yeniden kullanım sınırı AUDIT içinde kayıtlıdır.

```bash
python3 tools/psop_audit.py source
python3 tools/psop_audit.py history --commit 097ba6ba7ab73d87c36f7ec9829b017b083b1883
python3 tools/psop_audit.py github  # yalnız sabit allowlist GET; secret endpointi yok
python3 tools/psop_audit.py signing --pages-root /tmp/psop-pages-input
python3 -m unittest discover -s tests -p 'test_psop_contract.py' -v
python3 -m unittest discover -s tests -v
```

Audit çıktısındaki PASS yalnız belirtilen denetimi ifade eder. Bütün çıktılar
`publishable=false` kalır. Audit çıktısı protected approval veya yayın receipt'i
değildir. Bu PR'ın merge edilmesi bile Stable'ı açmaz. Sonraki aşamaların
[kesin kapsamı](IMPLEMENTATION-CONTRACT.md):

- PR-B: verified inputs/history/genesis, planner/composer, deterministic result,
  PSOP approval/signing, durable ledger/outbox ve ortak gateway uygulaması;
  publication yalnız disposable/test ortamında.
- PR-C: client descriptor/state entegrasyonu, gerçek Fedora 44 DNF5, imza/hash
  negatifleri, provider fault injection, disposable Pages HTTPS, Beta regresyonları
  ve operator runbook/readiness raporu.
- Ayrı operatör aşaması: açık yetkilendirme ve bütün activation gate'leri sonrası
  gerçek writer custody/V2 cutover, GitHub ayarları ve canlı Stable aktivasyonu.

Production writer, secret erişimi/provisioning, V2 cutover ve activation PR-B ve
PR-C boyunca kapalı kalır. Güvenlik mimarisi ve Strict V3 production kilidi korunur.
