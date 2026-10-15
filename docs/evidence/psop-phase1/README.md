# PSOP phase-1 evidence

Repository `Project-Ro-ASD/Ro-Repo`; 15 Ekim 2026. Bunlar read-only audit/test
kayıtlarıdır; production approval, deployment receipt veya activation değildir.

| Dosya | Kaynak / kapsam |
| --- | --- |
| `github-before.json` | Sabit `psop_audit.GITHUB_GETS` allowlist'i, `gh api --method GET`; endpoint, observation status ve API response. Secret endpointi yok. Başlangıçtaki #79 404 gözlemi PR-A açıldıktan sonraki durum için iddia değildir. |
| `github-after.json` | Feature push/PR öncesi aynı GET setiyle son karşılaştırma; main/Pages/#78 ve security setting drift denetimi. |
| `history.json` | Exact Pages commit'in 300 reachable tree'si; Stable izleri ve immutable parent→child blob/mode drift. |
| `signing.json` | Beş snapshot/86 RPM path/altı publication için public signature kontrolü; public key listings/hashes ve extracted client repo/keyring payload gözlemi. |
| `signing-recheck.json` | Commit edilmiş helper'ın `signing` komutu: external role pins, snapshot/build/run binding, repodata/RPM signatures ve strict-history rejection. |
| `http.json` | Beta publication/repomd ve Stable publication/repomd HTTPS GET; status, observed UTC, hash/size. Tek ağ gözlemi; tüm PoP/future freshness değil. |
| `base-protected-files.json` | Exact main'den 234 existing workflow/runtime/config/key/schema/script/test/legacy file SHA256 ve Git mode. Helper'daki baseline digest ile kısaltma da reddedilir. |
| `source.json` | Phase-A source/profile audit; PASS olsa bile publishable=false, production BLOCKED. |
| `tests.json`, `*.log.gz` | Exact komut, exit/result ve local diagnostic/test logları; sandbox socket hatası ayrı etiketlenir. CI sonucu GitHub PR head'ine ayrıca bağlıdır. |
| `ci.json` | Implementation head `72186d7` için sekiz GitHub CI check'inin SUCCESS kaydı ve job/run bağlantıları. Bu kanıtı ekleyen sonraki commit yalnız belge/CI kaydı değiştirir; son head checks ayrıca izlenir. |

Public inputların tekrar hazırlanması (yalnız yerel disposable dizin):

```bash
mkdir -p /tmp/psop-pages-input
git archive 097ba6ba7ab73d87c36f7ec9829b017b083b1883 | tar -x -C /tmp/psop-pages-input
python3 tools/psop_audit.py signing --pages-root /tmp/psop-pages-input
```

`signing` komutu yalnız public key'leri disposable GPG/RPMDB'ye import eder;
private key/secret veya host RPMDB/GPG home kullanmaz, DNF transaction çalıştırmaz.
İlk audit'teki client incelemesi için signed current snapshot'taki `ro-asd-repos`
ve `ro-asd-keyring` RPM'leri `rpm2cpio | cpio` ile ayrı `/tmp` dizinlerine açıldı.
Keyring payload SHA256'ları canonical public roots ile karşılaştırıldı. Host'a
paket kurulmadı. Bu RPM'ler 86-path public verification setinin içindedir.

`github` tekrarları yeni timestamp ve farklı PR state döndürebilir; freeze edilmiş
başlangıç kaydı üstüne yazmak yerine yeni observation dosyası oluşturulmalıdır.
Geçmiş kayıtlar veya public signatures first-availability witness değildir.
