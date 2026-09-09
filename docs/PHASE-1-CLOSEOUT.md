# Ro-Repo V2 Phase 1 Closeout

Date: 2026-09-09

Bu belge Ro-Repo V2 Phase 1'in kapanis durumunu kaydeder. Phase 1'in teknik
kapsami local filesystem publication backend'i, producer trust contract'i,
acceptance/signing/snapshot/promotion policy'si, Fedora 44 validation ve gerekli
manuel GitHub guvenlik yapilandirmalaridir. Remote publication backend Phase 2'ye
aittir.

## Tamamlananlar

- Ro-Repo V2 trust-chain implementation `main` dalina PR ve zorunlu CI sonrasinda
  merge edildi.
- Ro-Control, ro-Assist ve Ro-Theme producer repository'leri V2 producer contract'ina
  gecirildi.
- Producer release workflow'lari exact tag/commit/release/workflow binding,
  strict SHA256SUMS, artifact manifest ve GitHub provenance attestations uretir.
- Producer asset setleri architecture/SRPM kurallarina gore fail-closed
  dogrulanir.
- Producer repository'lerinde Immutable Releases etkinlestirildi.
- Dort repository icin `main` ruleset'leri olusturuldu; force-push ve deletion
  engellendi, PR ve repository'ye ozgu required CI checks zorunlu tutuldu.
- `Project-Ro-ASD/release-engineering` takimi olusturuldu ve Ro-Repo icin gerekli
  yetki verildi.
- Ro-Repo'da `repo-beta`, `repo-stable` ve `repo-production-signing` protected
  environment'lari olusturuldu ve release-engineering reviewer olarak tanimlandi.
- Fedora 44 haftalik compatibility workflow'u gercek Fedora package-name listesini
  `dnf repoquery` ile network uzerinden yeniler ve local snapshot E2E validation
  calistirir.
- Production OpenPGP key ceremony tamamlandi:
  - offline certification-only primary,
  - ayri RPM signing subkey,
  - ayri metadata signing subkey,
  - revocation certificate,
  - iki sifreli fiziksel offline backup,
  - SHA-256 copy verification,
  - restore testi,
  - exact-subkey signing testi,
  - role isolation testi,
  - subkey-only CI export testi.
- Production key rotation/revocation ve backup policy'si
  `docs/PRODUCTION-KEY-MANAGEMENT.md` icinde kayda alindi.
- Tek-maintainer yapisi acikca belgelenmistir; teknik rol ayrimi organizational
  separation-of-duties olarak sunulmaz.

## Phase 2'ye gecmeden once canonical public key publication

Production public key materyali secret degildir, ancak ceremony'den sonra local
workstation'da uretilen exact dosyalar repoya kontrollu bir PR ile eklenmelidir:

- `keys/production/ro-asd-public.asc`
- `keys/production/ro-asd-rpm-signing-public.asc`
- `keys/production/ro-asd-metadata-signing-public.asc`
- `keys/production/production-fingerprints.txt`

Bu dosyalar kullanicinin ceremony makinesindeki
`~/Belgeler/ro-asd-public-keys/` klasorunden alinmalidir. Fingerprint veya public
certificate icerigi model, dokumantasyon veya eski test anahtarindan tahmin
edilmez. Public key PR'i production signing workflow'u devreye alinmadan once
merge edilmelidir.

## GitHub UI tarafinda manuel dogrulama gerektiren security ayarlari

2026-09-08 denetiminde Secret scanning, Push protection ve Dependabot security
updates dort repoda kapali gorunmustu. Bu ayarlar repository kodundan guvenli
sekilde acilamaz ve Phase 1 closeout icin GitHub UI uzerinden yeniden kontrol
edilmelidir. Desteklenen plan/repository ayarlarinda su uc koruma etkinlestirilir:

- Secret scanning
- Push protection
- Dependabot security updates

Bu belge bunlarin etkinlestirildigini iddia etmez; UI dogrulamasi yapilmadan bu
madde kapanmis sayilmaz.

## Scope siniri

Phase 1 remote production repository yayinlamaz. Pages tabanli gecici remote
publication endpoint'i, production signing secret provisioning ve remote
snapshot publication Phase 2 kapsamindadir. Cloudflare R2 canonical backend ise
sonraki fazdadir.

Phase 1'in local trust-chain kodu tamamlanmistir. Phase 2 baslangic kapisi,
yukaridaki canonical public key publication ve GitHub UI security toggle
kontrollerinin tamamlanmasidir.
