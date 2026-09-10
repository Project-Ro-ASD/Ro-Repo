# Ro-Repo V2 Phase 1 Closeout

Date: 2026-09-09
Status: CLOSED

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
- Production public key seti canonical olarak `keys/production/` altinda
  yayinlandi:
  - `ro-asd-public.asc`
  - `ro-asd-rpm-signing-public.asc`
  - `ro-asd-metadata-signing-public.asc`
  - `production-fingerprints.txt`
- Ceremony makinesinden gelen exact public dosyalar repo icine kontrollu PR ile
  aktarildi; secret key, revocation certificate veya backup materyali commit
  edilmedi.
- Dort repository'de GitHub Advanced Security ayarlari manuel olarak yeniden
  kontrol edildi ve su korumalar etkinlestirildi:
  - Secret Protection / secret scanning
  - Push protection
  - Dependabot alerts
  - Dependabot security updates
- Tek-maintainer yapisi acikca belgelenmistir; teknik rol ayrimi organizational
  separation-of-duties olarak sunulmaz.

## Production key publication kaydi

Canonical production public trust materyali:

- `keys/production/ro-asd-public.asc`
- `keys/production/ro-asd-rpm-signing-public.asc`
- `keys/production/ro-asd-metadata-signing-public.asc`
- `keys/production/production-fingerprints.txt`

Bu dosyalar public trust materyalidir. Primary private key, signing secret subkey
exportlari, revocation certificate ve encrypted master backup repository disinda
kalir.

## GitHub security kaydi

2026-09-08 denetiminde kapali gorunen Secret scanning, Push protection ve
Dependabot security updates ayarlari 2026-09-09 tarihinde dort repoda GitHub UI
uzerinden etkinlestirildi. Dependabot alerts de aktif olarak dogrulandi.

## Scope siniri

Phase 1 remote production repository yayinlamaz. Pages tabanli gecici remote
publication endpoint'i, production signing secret provisioning ve remote
snapshot publication Phase 2 kapsamindadir. Cloudflare R2 canonical backend ise
sonraki fazdadir.

Phase 1'in local trust-chain kodu, producer contract'lari, manuel GitHub security
yapilandirmalari, production key ceremony kaydi ve canonical public trust
materyali tamamlanmistir.

**Ro-Repo V2 Phase 1: CLOSED. Phase 2 entry gate aciktir.**
