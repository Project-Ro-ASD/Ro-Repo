# Tek komutla V2 Beta bileşen yayını

Bu akış yalnızca **Fedora 44 V2 Beta** içindir. Stable terfisi ve V3 geçişi
kapsam dışıdır. Workflow, PR main'e alındıktan sonra kullanılabilir; bu PR'ı
hazırlamak herhangi bir kabul veya yayın başlatmaz.

## Kullanım

GitHub → Project-Ro-ASD/Ro-Repo → Actions → **Publish component to Beta** →
Run workflow → **main** → `component` ve kesin `tag`. Önce yalnızca uygunluğu
kontrol etmek için `preflight_only=true` seçilebilir.

```bash
gh workflow run publish-component-beta.yml \
  -R Project-Ro-ASD/Ro-Repo \
  -f component=ro-theme -f tag=v1.1.10

# Hiçbir alt workflow veya yayın başlatmaz:
gh workflow run publish-component-beta.yml \
  -R Project-Ro-ASD/Ro-Repo \
  -f component=ro-theme -f tag=v1.1.10 -f preflight_only=true
```

`repository`, `commit`, `release_id`, `signing_runs`, `snapshot_id`,
`parent_snapshot`, `candidate_run` ve dahili storage ön koşulu otomatik çözülür.
`ro-widgets` ancak kayıtlı `Project-Ro-ASD/ro-widgets` deposundaki yeni,
**immutable** bir Release ile kullanılabilir; eski mutable Release reddedilir.

## Ön koşullar ve insan onayları

- Bileşen `config/producers-v2.json` içinde tek bir producer'a kayıtlı olmalı.
- Release yayımlanmış, draft olmayan ve GitHub API'de `immutable: true` olmalı.
  Tam tag ref'i commit'e çözülmeli; Release manifestinin bileşen/repo/tag/commit/
  Release ID bilgileri aynı olmalı. Kayıtlı signer workflow ve asset
  attestations dahil mevcut kabul politikası ayrıca eksiksiz çalışır.
- Geçerli Beta'nın imzalı snapshot'ı ve yayın manifesti Pages storage'da
  bulunmalı. İlk depo kurulumu bu orkestratörün görevi değildir.
- Özetin bağladığı alt çalıştırmalarda mevcut **repo-production-signing**
  onaylarını; son yayında ayrıca **repo-beta** onayını normal Actions
  environment review ekranından verin. Yeni orkestrasyon işi signing secret'ı
  kullanmaz. Environment kuralları ve reviewer ayarları değiştirilmez.

Akış sırası: kabul/RPM imzası → incremental candidate → değişmez Pages snapshot
→ imzalı uzak Beta ve bağımsız `verify-remote-beta`. Herhangi bir aşama başarısız,
iptal edilmiş, reddedilmiş veya doğrulanamazsa sonraki aşama başlatılmaz.
Preflight geçişi, sonraki gerçek kabul/imzalama/paket testlerinin geçeceği
anlamına gelmez; preflight üretici testlerini yeniden çalıştırmaz.

## Başarı ve izlenebilirlik

Ana çalıştırmanın Summary ekranı ve `component-beta-state-RUN_ID` artifact'ı;
istek kimliği, Release/commit, parent/yeni snapshot, dört alt run ID'si ve Actions
bağlantılarını gösterir. **SUCCESS** yalnızca son run başarılı ve onun
`verify-remote-beta` işi başarılıysa yazılır. Bu iş uzak ağacı Pages storage ile
bayt bayt karşılaştırır ve yayın imzasını doğrular. `PREFLIGHT PASSED` yayın
başarısı değildir.

## Hata ve güvenli yeniden deneme

1. Summary'deki tamamlanan aşamaları, bloklanan aşamayı ve bağlantıları inceleyin.
2. Bekleyen alt run varsa önce iptal edin ve tamamlandığını doğrulayın.
   Orkestratör bilinen aktif run için iptal ister; zorla iptal/runner kaybında
   bunun gerçekleşmesi garanti değildir. Dispatch yanıtı kaybolduğunda run ID
   bilinmeyebilir: ilgili workflow'da `workflow-adı [request_id]` başlığını
   bulun, sıfır/birden fazla eşleşmeyi çözmeden tekrar başlatmayın. POST isteği
   otomatik tekrarlanmaz. Alt workflow'u **Re-run jobs** ile yeniden oynatmayın.
3. Kabul/candidate hatasında Beta değişmemiştir. Pages aşamasında değişmez
   snapshot depolanmış olabilir, fakat Beta henüz değiştirilmemiştir.
   Remote aşama hatasında/timeout'unda Beta **değişmiş olabilir**; özellikle
   uzak doğrulama hatası geri alma işlemi değildir. Son alt run'ı, güncel
   imzalı publication'ı ve uzak yayını inceleyin. Gerekirse mevcut ayrı,
   onaylı rollback prosedürünü kullanın.
4. Sorunu giderdikten ve artık aktif alt yayın kalmadığını doğruladıktan sonra
   **yeni bir ana çalıştırma** başlatın. Ana run rerun'ı reddedilir. Yeni istek
   güncel parent ve kullanılmamış snapshot numarası çözer. Bileşen zaten
   yayımlanmışsa aynı sürümün yeniden eklenmesi mevcut EVR politikasıyla
   reddedilir; bunu aşmak için korumaları değiştirmeyin.

## Süre ve yarış sınırları

- Ana iş 240 dakika, süreç/API bütçesi 210 dakika; her alt aşama onay bekleme
  dahil en fazla 45 dakika. Run keşfi 120 saniye, her API isteği en fazla
  60 saniye. API timeout/rate limit otomatik POST tekrarına yol açmaz.
- GitHub-hosted alt işler ve mevcut timeout'ları korunur. Onay 45 dakika içinde
  verilemezse akış kesilir; bekleyen alt run'ın iptalini kontrol edin. Ana iş
  runner/kurulum hataları için her zaman state artifact'ı üretemeyebilir.
- Orkestratör kendi concurrency grubunu kullanır; alt Pages/Beta yazıcılarının
  ortak kilidini tutmaz. GitHub concurrency kuyruğu FIFO garantisi vermez ve
  yeni istek bekleyen başka isteği düşürebilir; düşen run başarı sayılmaz.
- Snapshot adı UTC gününe göre `repo-f44-YYYYMMDD-NNN`; o gün depolanmış en büyük
  numaranın bir fazlası kullanılır. Bu numara kalıcı rezervasyon değildir.
  Diğer manuel adaylarla çakışma olursa immutable storage kontrolü ve commit
  ön koşulu durdurur; güncel storage üzerinden yeni istek açın.
- Parent'ın imzası, production trust rolleri, RPM imzaları ve Beta ağaç eşliği
  doğrulanır. Candidate kanıtı aynı parent manifest hash'ine ve kesin signing
  run'a bağlı olmalıdır. Başlangıç storage commit'i Pages yazıcısında; onun
  tek çocuğu olan kesin yayın commit'i Beta yazıcısında kilit altında sınanır.
  Araya giren bağımsız yayın, rollback/ABA veya storage değişikliği reddedilir.
  Mevcut fetch/expected-head/push CAS kontrolü ayrıca korunur.
- `main` süreç içinde değişirse yeni aşama başlatılmaz. Her alt run'ın SHA'sı
  başlangıç main SHA'sıyla aynı olmalı; run attempt 1 olmalıdır.
- Beklenmeyen iptal sonrası otomatik devam/resume yoktur. Belirsiz dış işlemi
  otomatik tekrar etmek yerine operatör uzlaştırması zorunludur.
- Mevcut dört manuel workflow, `request_id` ve `expected_storage_commit`
  verilmeden önceki girişleriyle kullanılabilir. Bu eski manuel yolun parent
  seçim sorumluluğu operatördedir; orkestratörün commit koşulu otomatik yolun
  iki yazıcısı için zorunludur.

GitHub'ın yerleşik token'ı `workflow_dispatch` başlatabilir; orkestratör yalnızca
`contents: read` ve `actions: write` ister. PAT/yeni secret gerektirmez.
Kaynaklar: [workflow tetikleme](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow),
[dispatch API](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event).

Dahili `expected_source_commit` ve `request_deadline` alanları otomatik taşınır.
Her alt iş, environment onayından sonra kaynak SHA/ref/repo/attempt ve süreyi
kontrol eder; iki yazıcı mutasyondan hemen önce süreyi yeniden sınar.
Eski manuel çağrılarda bu isteğe bağlı alanlar boş kalabilir.
