# Manuel Kurulum ve Guvenlik Ayarlari

Faz 1 production anahtari, domain, Pages veya Cloudflare R2 kurmaz.

GitHub organizasyon yoneticisi sunlari elle tamamlamalidir:

1. Dort repoda `main` ruleset: PR, zorunlu CI, stale approval iptali ve force-push engeli.
2. Ro-Repo icin `repo-beta`, `repo-stable` ve `repo-production-signing` protected environment'lari ve reviewer.
3. `CODEOWNERS` icindeki `Project-Ro-ASD/release-engineering` takimini olusturma veya gercek takimla degistirme.
4. Desteklenen producer'larda Immutable Releases'i etkinlestirme. Yoksa tag, commit, release ID, asset digest kontrolleri zorunlu kalir.
5. Haftalik uyumluluk isine Fedora 44 package-name listesini yenileyecek ag erisimi verme.

2026-09-08 salt okunur API denetiminde dort repoda ruleset bulunmadi;
Ro-Repo'da yalniz `github-pages` environment'i vardi. Immutable Releases alani
API'de etkin bir deger donmedi. Secret scanning, push protection ve Dependabot
security updates da dort repoda kapali gorundu. Bunlar workflow koduyla guvenli
sekilde acilamadigi icin manuel blocker olarak kalir.

Production key ceremony Faz 2'den once elle yapilmalidir: offline primary key,
ayri RPM ve metadata subkey'leri, revocation certificate, iki sifreli offline
backup, kurtarma testi ve yazili rotation/revocation proseduru. CI test anahtari
hicbir zaman production trusted key olarak dagitilamaz.
