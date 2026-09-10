# Repository Baseline Automation

Status: ACTIVE

Bu belge yeni `Project-Ro-ASD` repository'leri icin tekrar eden GitHub guvenlik
ayarlarini tek bir bootstrap adimina indiren baseline'i tanimlar.

## Tasarim

Tercih edilen katmanlama:

1. Organization seviyesinde `Ro-ASD Baseline - Default Branch` ruleset'i
   kullanilabiliyorsa universal branch kurallari oradan gelir.
2. Bu organization ruleset'i hedef repository'ye uygulanmiyorsa
   `tools/bootstrap-repo.py` ayni universal korumalari repository-level fallback
   ruleset olarak kurar.
3. Required CI check isimleri global ruleset'e konmaz. Her repository kendi
   gercek job adlarini tekrar eden `--check` argumanlariyla verir.
4. Security ayarlari repository API'leri ile uygulanir. Organization security
   configuration zaten bu ayarlari enforce ediyorsa script bunu bozmadan kabul
   eder.
5. Producer ve central-release ekleri opt-in'dir.

Universal branch kurallari:

- default branch hedefi,
- Pull Request zorunlulugu,
- branch deletion block,
- non-fast-forward / force-push block,
- single-maintainer gercegine uygun `required approvals = 0`,
- CODEOWNERS review requirement kapali,
- stale approval dismissal kapali.

## Kullanim

On kosullar:

```bash
gh auth status
```

Normal yeni repository:

```bash
./tools/bootstrap-repo.py Project-Ro-ASD/YENI-REPO
```

Repository-specific CI check'leriyle:

```bash
./tools/bootstrap-repo.py Project-Ro-ASD/YENI-REPO \
  --check "Build & Test" \
  --check "RPM Build Check (Fedora 44)"
```

Producer repository:

```bash
./tools/bootstrap-repo.py Project-Ro-ASD/YENI-PRODUCER \
  --producer \
  --check "Fedora 44 RPM CI"
```

Ro-Repo benzeri merkezi release repository:

```bash
./tools/bootstrap-repo.py Project-Ro-ASD/YENI-CENTRAL-REPO \
  --central-release \
  --check unit-policy \
  --check fedora44-e2e
```

Degisiklikleri gondermeden yazma isteklerini gormek icin:

```bash
./tools/bootstrap-repo.py Project-Ro-ASD/YENI-REPO --dry-run
```

## Organization-level tercih

GitHub plani izin veriyorsa organization owner su yapilandirmayi tercih eder:

- Organization -> Settings -> Repository Rulesets
- name: `Ro-ASD Baseline - Default Branch`
- target: default branch
- Pull Request required
- deletion blocked
- non-fast-forward blocked
- approvals: `0`
- CODEOWNERS requirement: off
- stale approval dismissal: off

Repository targeting icin mumkunse boolean custom property:

```text
roasd_baseline = true
```

kullanilir. Bu ruleset'e repository-specific required status check isimleri
eklenmez.

Organization-level security configuration kullanilabiliyorsa ayri bir
`Ro-ASD Security Baseline` olusturup yeni normal repository'lere default olarak
uygulamak tercih edilir. Hedef ayarlar:

- Secret scanning / Secret Protection: enabled
- Push protection: enabled
- Dependabot alerts: enabled
- Dependabot security updates: enabled

Script bu org-level katmanlar olmasa da repository bazinda ayni minimum baseline'i
uygulayacak fallback'tir.

## Producer extras

`--producer` yalniz package/RPM producer repository'leri icindir ve GitHub
Immutable Releases'i REST API ile etkinlestirir.

Producer V2 contract'in diger release-engineering gereksinimleri yine kod/review
kapsamindadir:

- tag-only canonical release workflow,
- strict artifact set,
- SRPM parity,
- Fedora 44 `.fc44` identity validation,
- strict `SHA256SUMS`,
- component artifact manifest,
- provenance attestations,
- release-critical action pinning,
- tek canonical release publisher.

Bootstrap scripti bunlarin varligini uydurmaz veya release workflow'u otomatik
uretmez.

## Central-release extras

`--central-release` kullanildiginda script su environment'lari olusturmayi veya
guncellemeyi dener:

- `repo-beta`
- `repo-stable`
- `repo-production-signing`

`Project-Ro-ASD/release-engineering` takimi API'den cozulurse reviewer olarak
atanir, self-review engeli single-maintainer deadlock yaratmamak icin kapali
kalir ve yalniz `main` deployment branch policy eklenir.

GitHub environment REST modeli tum UI korumalarini guvenilir bicimde temsil
etmedigi icin script sonunda administrator bypass'in kapali oldugunu UI'da
dogrulama maddesini manuel follow-up olarak birakir.

## Guvenlik sinirlari

Script:

- mevcut, ilgisiz ruleset'leri mutate etmez;
- global ruleset'e repo-specific CI isimleri eklemez;
- default branch `main` degilse otomatik rename yapmaz, fail-closed durur;
- `Project-Ro-ASD` disinda calismayi varsayilan olarak reddeder;
- production signing secret'i, private key'i veya GPG materialini yonetmez;
- branch/ruleset protection'i merge kolaylastirmak icin gevsetmez.

Ikinci guvenilir maintainer geldiginde baseline policy ayrica sertlestirilmelidir:

- required approvals -> 1
- dismiss stale approvals -> on
- CODEOWNERS review -> on
