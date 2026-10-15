# Gerçek sistem, publisher ve production signing denetimi

15 Ekim 2026; [GET gözlem kaydı](../evidence/psop-phase1/github-before.json),
[Git geçmişi](../evidence/psop-phase1/history.json),
[public imza doğrulaması](../evidence/psop-phase1/signing.json) ve
[HTTP gözlemi](../evidence/psop-phase1/http.json). GitHub GET kaydının başlangıcı
13:43:58 Türkiye saati; HTTP örneklemesi 13:51:21–22. Gözlemler tüm CDN PoP'ları
veya gelecekteki provider davranışı hakkında garanti değildir.

## Yeniden doğrulanan referanslar

| Nesne | 15 Ekim gözlemi | Durum |
| --- | --- | --- |
| Main | `3d4b56bd7509988f3715305ab9e2e09394635448` | PASS |
| Pages storage | `097ba6ba7ab73d87c36f7ec9829b017b083b1883`; tree `69fda4e20cf3082631228a5a7eca5b0ee3b2b0b1` | PASS |
| PR #77 | MERGED, 13 Ekim 2026 22:06:45 UTC | PASS |
| PR #78 | OPEN/DRAFT, head `7a979ab0dffa4654c32ae8c5c0b1a05940180c3a`; base exact main | PASS; değiştirilmedi |
| PR #79 | Başlangıç audit GET `/pulls/79`: 404 | UNVERIFIED; o andaki erişimle mevcut olduğu doğrulanmadı |
| Current Beta | `repo-f44-20261009-001`, publication `37935890476`; pinned Git ve HTTPS JSON eşleşiyor | PASS |
| Beta publication run | `publish-remote-beta.yml`, workflow_dispatch, completed/success; source SHA `2a4678c1f97e9caa35bd4ded65675f48c1cd93bb` | PASS |
| Stable current | Pinned tree'de channel/history/promotion yok; publication ve x86_64 repomd HTTPS GET 404 | PASS gözlem; activation kanıtı değil |
| Production public roots | Canonical fingerprint ve role-specific key byte'ları mevcut/doğrulandı | PASS |
| 12 Ekim real acceptance | `released/acceptance.json` 11 case PASS; `publishable=false`, production BLOCKED | PASS tarihsel test kanıtı |
| Strict V3 | `production_publish`/`activate_production` hard deny; disabled workflow bütün job'ları false | BLOCKED, korunuyor |

Bu başlangıç audit'inden sonra oluşturulan tek PSOP PR'ına **#79** tahsis edildi.
Başlangıç 404 kaydı, bu PR açıldıktan sonra #79 mevcut değil iddiası değildir.

Main/Pages ve PR kayıtları GitHub API ile, local object'ler fetch sonrası SHA ile
karşılaştırıldı. Çalışma ilk başta #78 branch'inde açılmıştı; değişiklik yapılmadan
exact main'den `codex/psop-phase1-contract` oluşturuldu. #78 commit'i yalnız read-only
incelendi ve `/tmp` kopyasındaki diagnostic test için kullanıldı; cherry-pick yok.

## Tarihsel Stable araştırması

Shallow olmayan Pages ancestry'sindeki **300 erişilebilir commit'in her tree'si**
`rpm/fedora/44/stable/`, `publications/fedora/44/stable/` ve
`promotions/fedora/44/` payload'ları için tarandı; hiç hit yok. Ayrıca tüm yerel
erişilebilir ref'lerin path history ve Stable mesajları incelendi: bulunan Stable
commit'leri implementation/test/docs değişiklikleridir, production payload değildir.
Mevcut `promote-remote-stable.yml` run API'si `total_count=0` döndürüyor.

Bulunan beş snapshot: `repo-f44-20260920-001`, `repo-f44-20260921-001`,
`repo-f44-20260929-001`, `repo-f44-20261006-001`, `repo-f44-20261009-001`.
Altı signed Beta publication run'ı: `35530066972`, `35586124137`, `35587617947`,
`35599214422`, `36123484599`, `37935890476`. Beta rollback commit'leri `cb3dc72`
ve `919a417` (20–21 Eylül) önceki publication'ı yeniden seçmiş; Stable değildir.

Her reachable parent→child geçişinde snapshot/publication/promotion/rollback
üyelerinin Git blob ve mode korunması ayrıca kontrol edildi: **drift yok, PASS**.
Bu doğrulama CDN availability veya signature verification yerine geçmez.

Sonuç: **gözlenebilen erişilebilir geçmişte Stable yayınına kanıt bulunamadı**.
404 tek başına tarihsel yokluk kanıtı değildir. Silinmiş run/ref, force-push ile
erişilemeyen commit, önceden başka Pages source veya dış storage geçmişi UNVERIFIED.
Bu nedenle ilk Stable için explicit operator genesis kabulü hâlâ gerekir.

## Workflow ve writer yetki matrisi

| Workflow / job | Signing / write authority | Storage değişikliği | Concurrency |
| --- | --- | --- | --- |
| `publish-pages-snapshot.yml` / `publish-pages-storage` | Workflow `contents:write`, `actions:read`; protected environment yok, signing secret yok | Exact candidate artifact/run doğrulaması; `.nojekyll` ve `snapshots/fedora/44/<id>`; normal push `HEAD:pages-storage` | `ro-repo-pages-storage` |
| `publish-remote-beta.yml` / `sign-beta-publication` → `publish-beta` | Signing environment metadata secret; ayrı `repo-beta` job `contents:write`, `actions:read` | Signed Beta view ve immutable publication history; normal push | `ro-repo-remote-beta` |
| `rollback-remote-beta.yml` / `rollback-beta` | `repo-beta`, `contents:write`; signing secret yok | Earlier signed Beta history seçimi; Beta view + rollback evidence; normal push | `ro-repo-remote-beta` |
| `promote-remote-stable.yml` / policy → sign → publish | Metadata signing `repo-production-signing`; ayrı `repo-stable` job `contents:write`, `actions:read` | Exact whole Beta snapshot Stable view/history/promotion evidence; normal push kodu mevcut | `ro-repo-remote-stable` |
| `v3-stable-promotion-disabled.yml` | `contents:read`; bütün jobs unconditional false, write/deploy/secret yok | Production mutation yok | `ro-repo-v3-stable-activation-blocked` |

`accept-component.yml` RPM signing ve `build-candidate-snapshot.yml` metadata
signing artifact üretir; Pages storage writer'ı değildir. Validation/domain/read-only
audit/test workflow'ları storage writer değildir. `update-repo.yml` V1 dispatcher'ı
read-only token ile `exit 1` verir. Bütün workflow dosyalarında contents-write ve
push/deploy komutları tarandı; doğrudan storage push içeren dört workflow yukarıdadır.

V2 CLI'nin local stage/publish/rollback fonksiyonları ve V3 Git provider API kodu
ayrıca potansiyel mutation primitive'leridir; kodun varlığı production custody
kabulü değildir. Manual admin/PAT/App ve workflow dışı credential envanteri
**UNVERIFIED**. Repository write permission path bazlı izolasyon sağlamaz. Normal
non-force Git push çakışan HEAD'i reddedebilir, fakat bütün writer'ları tek
admission realm'e sokmaz veya deadline/Pages ordering sağlamaz. Hiçbir writer bu
PR'da açılmadı, kapatılmadı veya değişmedi.

## GitHub security ayarları — salt okunur

Connector environment endpointini desteklemedi; bu ilk erişim sınırı CLI GET ile
aşıldı. Nihai gözlem `github-before.json` içindedir; secret endpointi çağrılmadı.

| Ayar | Doğrulanmış değer | Yorum |
| --- | --- | --- |
| `repo-beta`, `repo-stable`, `repo-production-signing` | Mevcut; required-reviewers takımı `release-engineering`; `prevent_self_review=false`; custom deployment branch policy yalnız `main` | Reviewer/config varlığı PASS; bağımsız iki kişi veya self-review engeli iddia edilmez. |
| Ruleset `22656730` | Active, default branch; deletion/non-fast-forward yasak; PR gerekli; strict checks `unit-policy`, `fedora44-e2e`; bypass listesi boş | Bu ayarların okunması PASS. |
| Review enforcement | `required_approving_review_count=0`, stale dismissal false, CODEOWNERS review false, last-push approval false | Independent approval eşiği mevcut değil; PSOP security gate için GAP/BLOCKED. |
| `pages-storage` | Branch API `protected=false`; yalnız listelenen ruleset default branch'e uygulanıyor | Exclusive writer/append-only provider enforcement kanıtı yok; BLOCKED. |
| Pages | Branch source `pages-storage:/`, `build_type=legacy`, CNAME `repo.ro-asd.org`, status built, certificate approved, `https_enforced=false` | HTTPS GET çalıştı; HTTP→HTTPS provider enforcement mevcut değil. Client HTTPS zorunlu. |
| `github-pages` environment | Branch policies `main`, `pages-storage` | Public build identity gözlemi, global CDN güvence değil. |
| Secret value, key custody, App/PAT inventory, team membership/person separation, offline backup restore | İncelenmedi / bağımsız kanıt alınmadı | UNVERIFIED; secret değerleri okunmadı/görüntülenmedi. |

## Production signing ve client trust

Primary `9A66A082D96374DA27D7538FB2186A6F2FD84CB3`; RPM subkey
`38CB87F6FBD645309432A6E22E02DEE8828B769B`; metadata subkey
`1715DDA529B9ADB46D47CB389A62B8F9026E75E5`. Public listing certification primary
ve her role export'ta yalnız ilgili signing subkey'i gösterir; combined public
export iki subkey içerir. Bunlar aynı primary altında iki teknik roldür, iki
bağımsız organization/root değildir. Public materyal expiry'leri ceremony
kaydıyla uyumludur (primary 2031, signing subkey'ler 2028).

RPM public key SHA256 `d73e92fcbf1dc9f8900459fa34b5eaa053570f11532ffc8e53373e8289b7ee51`;
metadata public key SHA256 `4eaf0b2903e60442c2f05325a43d85046bba850059b732dfc71e330f5e9e0809`.
Exact pinned Pages public byte'ları `/tmp`'a açılıp disposable GPG/RPMDB ile:

- Beş signed snapshot manifest/build evidence doğrulandı; repomd hash ve metadata
  signature kontrolü `ro_repo.verify_snapshot` üzerinden geçti.
- Beş snapshot'taki toplam **86 physical RPM path** canonical dış RPM role key'iyle
  `verify_signed_rpms` üzerinden doğrulandı (sırasıyla 3, 3, 24, 26, 30).
- Altı archived publication detached signature'ı canonical metadata key'iyle geçti.
- Strict `signed_archive_bundle` gerçek archive için yeniden
  `unexpected signed publication fields` reddi verdi: eski dört publication'da
  `store_tree_sha256` yok. İmzalı kayıtlar değiştirilmedi; sahte field/timestamp eklenmedi.

Current snapshot 23 logical package / 30 physical RPM path taşır. Snapshot'ın
`ro-asd-repos-0.1.1-1.fc44.noarch.rpm` payload'ı disposable dizinde incelendi:
Beta enabled=1, Stable enabled=0, source repo'lar enabled=0; her repo
`gpgcheck=1`, `repo_gpgcheck=1`, `skip_if_unavailable=0` ve HTTPS baseurl kullanır.
`ro-asd-keyring-0.1.0-1.fc44.noarch.rpm` içindeki `/etc/pki/rpm-gpg/` public role
dosyalarının SHA256'ları yukarıdaki canonical key'lerle birebir aynıdır.
Host'a RPM install/import veya DNF transaction yapılmadı.

V3 client ayrıca immutable full inventory, preinstalled root pins, local
generation/checkpoint ve atomic state/config hazırlığı uygular; `sslverify=1`
zorlar. Bu istemci mevcut production PSOP client'ı değildir. Native DNF trust
bootstrap'ta aynı primary altındaki role subkey paketlerini doğru import/merge
etmek gerekir; mevcut V3 E2E bunu kapsar. GPG signature PASS, offline key ceremony
veya bağımsız production approval kanıtı olarak sunulmaz.

## Tarihsel belgelerin farkı

| Tarih / kaynak | Kapsam | Bugünkü doğru yorum |
| --- | --- | --- |
| 8 Eylül `MANUAL-SETUP.md` | O gün ruleset/environment/key ceremony eksiklikleri kaydedilmiş. | Tarihsel setup listesi; eksikler bugün de var diye okunmaz. |
| 9 Eylül `PHASE-1-CLOSEOUT.md` ve key-management kaydı | Local V2 trust chain, public key ceremony/publication ve manuel security kurulumu tamamlandı; remote backend/secret provisioning Phase 2. | Closeout kendi fazını kapatır; o günkü private ceremony iddiası bugün secret açılarak yeniden denetlenmedi. |
| 20 Eylül–9 Ekim gerçek Pages snapshots/Beta runs | Production signing ve remote publication daha sonra kullanılmış. | Production public keys/signatures artık eksik değil; bugün byte doğrulaması PASS. |
| 12 Ekim `V3-REAL-WORLD-ACCEPTANCE-REPORT.md` + released evidence | Gerçek RPM'lerle x86_64 native DNF 11/11; 262 expected HTTPS file parity, beş snapshot/altı signature; test-only preview signing. | Başarılı test kanıtı; aarch64/GUI/VM ve protected production publication kabulü değil. |
| 15 Ekim bu audit | Güncel key/snapshot/signature ve environment/ruleset yeniden gözlemi. | Kurulum var; self-review/minimum review/custody/history/freshness sınırlamaları ayrıca açık. |

## PR #78 testlerinin incelenmesi

Diff yalnız provider testleri ve belgeleri değiştiriyor (runtime/workflow değil).
`test_v3_provider_fault_injection.py` admission sonrası gecikmiş CAS, response-loss,
eski build'in geç görünmesi, 14 stale/missing member fault, uncovered restart I/O
sınırları ve önceki immutable byte korunmasını kapsıyor. Mevcut live-provider race
testi aynı beforeOid'de iki adapter'ın gerçekten yarışmasını güçlendiriyor.
PR-A bunları kopyalamaz; main'deki base tests + yeni PSOP profile/source/legacy/
history/isolation kontratlarını çalıştırır. #78 exact head `/tmp` diagnostic sonucu
[sonuç raporunda](RESULTS.md) ayrı gösterilir; bu PR'ın CI sonucu diye sayılmaz.
