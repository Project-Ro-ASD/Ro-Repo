# Ro-Repo V2

Ro-Repo, Ro-ASD paketlerini kabul eden, merkezi olarak imzalayan ve degismez
repository snapshot'lari (depo anlik goruntuleri) olusturan yayin aracidir.

> **Legacy repository - production degildir. Guvenilir stable repository olarak kullanmayin.**

Kokteki `x86_64/`, `aarch64/`, `noarch/` ve `SRPMS/` dizinleri V1'in donmus
tarihsel kaydidir. Yeni paket veya repodata bu dizinlere ve Git dalina yazilmaz.
Eski nightly workflow kapatilmistir. `gpgcheck=0` kullanan V1 istemci ayari
desteklenmez.

V2 guven zinciri:

```text
sabit producer/tag/commit + manifest/hash + provenance
  -> kabul -> merkezi RPM imzasi -> degismez snapshot
  -> beta/stable yayin gorunumu + kalici kanit
```

Ilk taban Fedora 44'tur. `x86_64` Tier 1 ve release blocker; `aarch64` Tier 2
Technology Preview'dur. Ayri kullanici `noarch` repository'si yoktur: noarch
paketler her iki mimari gorunumune eklenir.

## Yerel kullanim

```bash
tools/ro-repo verify-component --manifest incoming/component-artifact-manifest-v1.json --artifacts incoming
tools/ro-repo accept-package --manifest incoming/component-artifact-manifest-v1.json --artifacts incoming --accepted .work/accepted
tools/ro-repo sign-package --input .work/accepted --output .work/signed --gnupghome /path/to/test-gnupg --key-id KEY_ID
tools/ro-repo build-snapshot --signed .work/signed --manifests .work/accepted --output out --snapshot-id repo-f44-YYYYMMDD-001 --gnupghome /path/to/test-gnupg --metadata-key-id KEY_ID
tools/ro-repo publish-local --output out --snapshot-id repo-f44-YYYYMMDD-001 --channel beta
```

Ayrintilar [docs/OPERATIONS.md](docs/OPERATIONS.md), manuel GitHub ve anahtar
islemleri [docs/MANUAL-SETUP.md](docs/MANUAL-SETUP.md) dosyasindadir. Faz 1
yalniz yerel dosya sistemi backend'ini uygular; domain, Pages, R2 ve production
anahtari kapsam disidir.
