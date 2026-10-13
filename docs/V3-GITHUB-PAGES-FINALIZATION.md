# GitHub Pages V3 yayın yolunun tamamlanması

**NON-PRODUCTION merge önerisi. Üretim aktivasyonu BLOCKED.**
Başlangıç `main`: `691c249a3a9f261ea586092ce85a4c38c4cb9262` (PR #75 sonrası).
Bu PR Pages hosting'i korur. Kaynak dal, domain, environment, production DB/keys,
V2 workflowları ve on bir disabled V3 job değiştirilmez. `pages-storage`'a yazılmaz.

## Gerçek depo üzerinde doğrulanan durum

`tests/v3-pages-readonly-acceptance.py` yalnız GET ve HTTPS okuması yaptı.
[Ham gözlem](evidence/v3-pages-finalization/pages-readonly.json) bağımsız bootstrap
kanıtı veya tam repository deployment kabulü değildir.

| Gözlem | Sonuç |
| --- | --- |
| Pages build tipi / source | `legacy`, `pages-storage`, `/` |
| Git source head | `097ba6ba7ab73d87c36f7ec9829b017b083b1883` |
| Pages build | `1271809147`, aynı commit, `built` |
| Deployment | `6961700285`, aynı commit/ref, `github-pages`, son durum `success` |
| Dinamik Pages run | `37936111310`, `dynamic/pages/pages-build-deployment`, aynı commit, başarılı |
| Domain | `repo.ro-asd.org`; certificate approved; gözlenen `https_enforced=false`; değişiklik yok |
| Mevcut stable dosyaları | Tam güncel Git envanterinde yok; tarihsel boşluk yetkisi çıkarılmaz |
| Beta metadata HTTPS | `publication-v1.json` ve `.asc` byte'ları exact Git blob'larıyla eşleşti |
| Beta'nın tüm RPM/SRPM byte'ları | Bu salt-okunur denetimde UNVERIFIED |

V2 `publish-pages-snapshot`, `publish-remote-beta`, `promote-remote-stable` ve
`rollback-remote-beta` checkout'ın default credential'ını kullanıp source ref'e
push ediyor. Ayrı concurrency grupları aynı storage writer realm'i fence etmez.
Snapshot staging workflow'u Git commit sonrasında Pages deployment'ı kanıtlamıyor;
beta/stable workflowları daha sonra bağımsız HTTPS byte doğrulaması deniyor.

GitHub [branch Pages dokümanı](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
`GITHUB_TOKEN` push'larının Pages build tetiklemediğini açıklar. Checkout default
credential'ı bu token olduğundan, mevcut workflow metni tek başına reliable trigger
sözleşmesi değildir. Başarılı eski build örnekleri mevcut; API'deki bot pusher/commit
author alanından kullanılan token sınıfı veya gelecekteki trigger garantisi çıkarılmaz.

[GitHub Actions trigger dokümanı](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)
App installation token ve PAT ile event tetiklemeyi açıklıyor. Branch Pages için
nominated App'in GraphQL ref CAS'inin exact source commit'i build/deploy ettirdiği
**gerçek disposable kabul** ayrıca gerekir. Verified-email machine-user PAT başka
bir olası push kimliğidir; bu PR onu seçmez. Deploy key ve GITHUB_TOKEN uygun
trigger varsayımı olarak kabul edilmez. Production publisher'a verilen App token
runner'lardan ayrı custody'de olmalıdır; bu PR token üretmez veya kullanmaz.

## Son yayın mekanizması

1. Planner, RPM/SRPM/metadata verification, full-set evidence, OIDC, human approval,
   witness, PostgreSQL ledger ve independent checkpoint mevcut sözleşmeleriyle çalışır.
2. Worker yalnız publisher ingress token'ı ve outbox fence/lease taşır. GitHub
   credential'ı worker'a verilmez. Publisher her yeni isteği mevcut `Outbox.locked`
   transaction'ında owner/fence/lease/authorization ile kontrol eder.
3. Onaylı exact result `v3/views/<digest>/...`, signed publication
   `v3/publications/<attempt>.json` altında append-only Git tree'ye eklenir.
   Tüm eski tree member/blob kimlikleri korunur; normal client seçimi yapılmaz.
4. CAS'den hemen önce exact expected/target Git OID, phase, publication ve approval
   kimliği mevcut signed outbox/audit içinde **IN_FLIGHT** service intent olarak
   commit edilir. Bir outstanding intent bütün storage writer realm'ini durdurur.
   Sonucu belirsiz timeout'ta eski Git head'i görmek, isteğin daha sonra ulaşmayacağı
   anlamına gelmez. Böyle durumda retry/handover yapılmaz.
5. `updateRefs(beforeOid, afterOid, force=false)` branch güncellemesini yapar.
   Native `POST /pages/deployments` veya `POST /pages/builds` kullanılmaz. Branch
   trigger kimliği App olmalıdır ve gerçek kabul edilmelidir.
6. Exact Git commit, build ID, deployment ID, dynamic run ID bağımsız gözlenir.
   Başarılı API cevabı yeterli değildir: independent signed witness ve bütün
   approved HTTPS byte'ları mevcut `verify_remote` üzerinden doğrulanır.
7. DB `PUBLISHED` yalnız intent'tir. İmzalı reklam kaydı
   `v3/advertisements/<authorization_sha256>.json` altında append-only eklenir;
   `v3/stable.json` overwrite edilmez. Reklamın mevcut stable-advertisement imza,
   generation, previous/result/publication, approval ve pre-verified commit bağları korunur.
8. Aynı bağımsız provider/HTTPS kontrolü post aşamada yapılır. Yalnız **POST_VERIFIED**
   current generation için mevcut nonce-bound signed discovery verilir. Client
   bütün immutable byte'ları doğrulamadan DNF transaction veya local state ilerletmez.

Eski Pages build yeni build'den sonra görünürse mutable pointer yarışıyla yanlış
stable seçilmez. Yeni seçilmiş view eksikse client fail closed olur. Bu bir
**bütünlük korumasıdır**, CDN atomiklik/sürekli erişilebilirlik veya provider build
ordering garantisi değildir. Beta/legacy client davranışına müdahale edilmemiştir.

## Tamamlanan kod

- `v3_fenced_publisher.FencedPublisher`: signed ledger/outbox üzerinde gerçek
  transaction'lı worker admission, CAS öncesi yeniden lease kontrolü, durable
  IN_FLIGHT reservation, global successor reddi ve exact-target reconciliation.
  `rehearsal_server` gerçek HTTP ingress'te bearer'ı owner'a bağlar; request body
  owner seçemez. Verified capabilities server registry'dedir; JSON'dan capability
  veya Git credential deserialization yoktur. Daemon yalnız private loopback test
  root'ta çalışır; production TLS ingress açılmamıştır.
- `GitHubStorage._append`: mevcut REST staging/CAS ortak primitive'i; before-CAS
  callback ile independently committed service intent. Eski immutable tree korunur.
  `advertise_immutable` aynı primitive üzerinden exact signed advertisement ekler.
- `ImmutableBranchStore`, `GitReader`, mevcut `Coordinator`: disposable branch
  orchestration için aynı immutable advertisement path'i kullanır. Eski mutable
  rehearsal yolu korunur; production Coordinator guard kaldırılmaz.
- `BranchPagesIdentity`: source settings, exact ref/commit, build/deployment/dynamic
  run ve latest status'un eşleşmesini kontrol eden read-only adapter.
  `BranchPagesDeployment/BranchHTTPSReader`: bağımsız deployment witness kimliğini
  bu tuple'a bağlar, mevcut pre/post verifier'ın signed reklamı immutable path'ten
  okumasını sağlar. Client install yetkisi API başarısından üretilmez.
- `Backend.first_resume_binding/reauthorize_first`: expired first intent için yeni
  exact-result authorization, fresh evidence/preflight ve bağımsız recovery
  observer ile child attempt ekler. Parent, eski proof/envelope ve signed history
  yerinde kalır. Aynı unfinished generation benimsenir; ledger reset ve generation
  rollback yoktur. Yeni approval, witness, JTI ve authorization replay identities
  atomik tüketilir. Bir parent'a ikinci child açılamaz.
- `request/authorization_request/verify_protected` ve closed schema'lar:
  `resume-first` onayı predecessor, exact audit checkpoint, eski authorization/
  publication hash ve pre-verified storage commit bağlarını ayrıca imzalar.
  Normal dwell ve component tests şartları korunur. Ordinary promote/recover
  onayı resume için kullanılamaz; original expiry yenilenmez.
- `Client.update`: eksik immutable public byte artık açık PlanningError verir;
  istemci state/config/transaction ilerlemez. Production client configuration
  değiştirilmez.
- `GitHubStorage.disposable_acceptance` ve cloud acceptance runner: yalnız açık
  operatör yetkisi, `ro-v3-disposable-*` marked repo, seeded `disposable-pages`
  branch ve yalnız o tek test repo'suna erişen App token için hazırlanmış test
  factory. Production constructor'ın guard'ı değişmez. Factory/script bu çalışma
  sırasında çalıştırılmadı; dış repo veya write-capable cloud credential kullanılmadı.

## İlk bootstrap ve expired authorization recovery

Mevcut `observe_empty/authorize_empty/initialize_empty` kullanılmaya devam edilir.
Storage reachable ancestry'de silinmiş stable dahil gerçek history görülürse empty
bootstrap reddedilir. Unreachable/deleted refs, önceki deployments ve gerçek HTTPS
state için iki independent observer, protected bootstrap approval/witness ve writer
exclusivity gerekir. Genel 404 veya güncel boş tree tek başına yetki değildir.

Publication intent oluşmadan onay biterse aynı original capability devam etmez;
yeni attempt ve fresh normal approval/evidence ile normal state machine kullanılır.
Intent oluştuktan sonra eski original'ın PUBLISHED fakat POST_VERIFIED olmadığı
first-stable durumu yeni `resume-first` yolu ile desteklenir:

1. `first_resume_binding(old_attempt)` ile exact current signed audit tip alınır.
2. Fresh evidence ve result preflight tekrar doğrulanır; yeni attempt/run/workload
   ve yeni JTI ile **resume-first** human approval/witness alınır.
3. Ayrı observer `{resume, writers_fenced:true, requests_drained:true}` için fresh
   `restore-observation` imzalar. Gecikmiş provider isteği drain edilmemişse imzalamaz.
4. `reauthorize_first` child'ı atomik ve idempotent ekler. Eski attempt'in bütün
   immutable/proof byte'ları korunur; mevcut head digest/generation/last_verified değişmez.
   Published sonrası FAILED parent ve yeniden expire olmuş unsigned child için de
   yeni bir child zinciri açılabilir; aynı parent ikinci kez tüketilmez.
5. Child signed/staged/pre-verified olur; `publish` mevcut unfinished generation'ı
   benimser. Yeni immutable advertisement ve yeni bağımsız post doğrulama gerekir.
   Child POST_VERIFIED olana kadar discovery reddedilir.

Stale checkpoint, reused JTI, aynı parent'a competing child, expired yeni onay,
aktif original authority, wrong observer root veya `requests_drained=false`
reddedilir. Daha önce POST_VERIFIED stable için bu empty/first yolu kullanılamaz;
mevcut authenticated recovery/import sözleşmeleri geçerlidir. Beta dwell observer'ın
ilk gerçek gözlem zamanından başlar; geçmiş beta credit üretilmez. Fixture timestamp
ve test signers production acceptance kanıtı değildir.

## Sağlayıcı garantisi ve hâlâ BLOCKED olan koşullar

**Tam uçtan uca GitHub Pages güvenli yayın tasarımı henüz kanıtlanmadı.**
Git ref CAS güvenli expected-head primitive'idir ([GitHub GraphQL Git](https://docs.github.com/en/graphql/reference/git)).
Incoming expired/stale worker yeni intent kabul ettiremez; local/disposable testte
bu fencing gerçekten uygulanmıştır. Kabul edilmiş service intent worker lease'inden
ayrı durable bir iştir; sonradan worker lease'in bitmesi onu otomatik geri almaz.
Bu ayrım açık protokol semantiğidir; provider'da lease-expiry garantisi diye sunulmaz.

Kesin kalan koşullar:

- Approval/authority deadline'dan önce GitHub'a kabul edilmiş bir CAS isteği
  deadline'dan **sonra** uygulanabilir. GitHub provider mutation sınırında deadline
  veya service epoch token'ı doğrulamıyor. Strict "authority bittiği anda hiçbir
  production mutation" garantisi hâlâ incompatibility/BLOCKED'dır. Admission
  kontrolünü bu garantiyle eşitlemek veya onay penceresini uzatmak çözüm değildir.
- Eski Pages build'in yeni POST_VERIFIED build'den sonra görünmeyeceğine dair
  provider garantisi doğrulanmadı. Branch trigger ve immutable append-only tree
  bunu tek başına sağlamaz. Client yanlış/missing byte'ta reddeder; erişilebilirlik
  ve legacy beta'nın en yeni build'de kalması garanti edilemez.
- `FencedPublisher`'ın global intent gate'i yalnız **aynı ledger/writer authority**
  içindeki çağrıları kapsar. Mevcut V2 writer/başka App/PAT doğrudan source ref'e
  yazabiliyorsa exclusive publisher değildir. Beta/stable bütün writers ortak
  boundary'ye alınmadan ve bypass credential yolları kapatılmadan production açılmaz.
- Sonucu belirsiz request için head hâlâ base ise native API noncommit/drain kanıtı
  sağlamıyor. Successor otomatik açılmaz. Bağımsız observer gerçek drain'i
  kanıtlayamazsa fresh reauthorization dahil recovery BLOCKED kalır.

Kalan code wiring: production TLS/mTLS publisher daemon ve identity ingress;
GitHub branch adapter ile bütün pre/intent/advertisement/post aşamalarını bağlayan
production controller; beta writer cutover adapter'ı; independently proven
noncommit için UNKNOWN intent abort transition. Sonuncusu henüz yoktur:
`FencedPublisher` yalnız exact target gözlenince CONFIRMED yapar. Recovery
observer'ın drained kanıtı Backend child oluşturmayı yetkilendirir ama eski
IN_FLIGHT gate'ini otomatik temizlemez. Target gözlenmiyorsa yayın devamı BLOCKED
kalır; signed drain claim'i tek başına native provider deadline garantisi yapmaz.

Production DB/backend/coordinator/client/schema guards, live import guard ve native
Pages POST guard korunur. Mevcut production constructor hiçbir live mutation yapmaz.

## Operatörün bir sonraki somut adımları

1. [Mevcut servis/role/pin sözleşmelerini](V3-LIVE-PROVIDER-HANDOFF.md) provision edin:
   restricted TLS PostgreSQL 18, independent checkpoint/history/recovery observer,
   ayrı approval/witness/publication/audit/deployment/discovery roots ve OIDC lifecycle.
   New `resume-first` request ve drained/fenced observation sözleşmesini bu servislerin
   policy validator'larına ekleyin. HSM/KMS custody ve actual reviewer authorization
   bu repo tarafından oluşturulmaz.
2. Bağımsız publisher için sole Git credential custody, mTLS/owner-bound ingress,
   durable service lifecycle ve UNKNOWN intent recovery prosedürünü kurun. Worker'a
   GitHub token vermeyin. Production daemon/identity packaging ve production
   coordinator wiring hâlâ ayrı code/cutover işidir; loopback server production
   deployment gibi açılmamalıdır.
3. **Ayrı açık operatör yetkisiyle** önceden disposable repo oluşturun; ad
   `<owner>/ro-v3-disposable-<name>`, description tam olarak
   `RO V3 DISPOSABLE PROVIDER ACCEPTANCE ONLY`. `disposable-pages` ref'ini `.nojekyll`
   ve korunacak test beta/history dosyalarıyla seed edin; Pages source'ını o test
   dalının `/` köküne ayarlayın. Gerçek `pages-storage` veya production domain kullanılmaz.
4. Yalnız test repo ID'si için seçilmiş GitHub App installation token provision edin:
   `Contents:write`, `Metadata:read`, `Pages:read`, `Actions:read`; build/deployment
   identity için `Deployments:read`. `Pages:write` gerekmez. Token/expiry operator'ın
   process environment'ında `RO_V3_DISPOSABLE_APP_TOKEN` ve
   `RO_V3_DISPOSABLE_APP_TOKEN_EXPIRY` olarak verilir; dosyaya veya log'a yazılmaz.
   [Token repository scope sözleşmesi](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
   uygulanır; runner `/installation/repositories` ile yalnız bir test repo kontrolü yapar.
5. Test repo numeric ID/node ID ve HTTPS origin'i bağımsız doğrulayın; ardından,
   yalnız yetkilendirilmiş disposable ortamda hazırlanan komutu çalıştırın:

   ```bash
   python3 tests/v3-pages-disposable-acceptance.py --operator-authorized \
     --repository '<owner>/ro-v3-disposable-<name>' --repository-id '<id>' \
     --node-id '<node-id>' --origin 'https://<test-pages-host>' --output cloud-test.json
   ```

   Runner repo/setting/credential oluşturmaz. App CAS sonrası exact commit/build/
   deployment/run ve synthetic immutable public byte'larını arar. Pozitif sonucuyla
   deadline fencing, build ordering veya real RPM/application acceptance PASS olmaz.
6. Bağımsız fault-injection staging kabulünde iki publisher, late expired request,
   lost response, changed head, old/new deployment reordering ve CDN gecikmesini
   uygulayın. Parent-expiry sonrası fresh child recovery'yi gerçek DB/checkpoint/
   witness/publication services üzerinden çalıştırın. UNKNOWN intent'i kanıtsız
   temizlemeyin. Strict provider deadline/order koşulları gösterilemiyorsa aktivasyon
   kararı BLOCKED kalmalıdır; başka hosting'e geçiş önerilmez.
7. Ancak gerçek dış kabul ve incompatibility çözümü sonrası V2 whole-storage writer
   cutover, branch writer protections, production schema/adapter/coordinator activation
   ve immutable client rollout için ayrı protected activation PR hazırlayın.
   Bu PR bu işlemlerin hiçbirini uygulamaz.

## Mühendislik ve dış staging hazırlığının sınırı

Yerel HTTP + gerçek Git object/ref, signed ledger, client ve fresh first recovery
pozitif/negatif testleri; gerçek PostgreSQL TLS restricted writer recovery ve Fedora
44/V2 regresyonları vardır. CI mevcut discovery ile yeni testleri çalıştırır;
production job açılmaz. [Kanıt dizini](evidence/v3-pages-finalization/) logları,
source hash'lerini, gerçek read-only provider gözlemini ve CI bağlantılarını taşır.

İlk immutable publication ve expired first recovery kodu **disposable testte
uygulanabilir**; operatör için gerçek App/branch pozitif dış staging runner'ı
hazırlanmıştır. Tam ilk stable uçtan uca external staging acceptance **tamamlanmadı**:
servisler provision edilmedi, cloud write testi çalıştırılmadı ve strict deadline/
Pages ordering koşulları gösterilmedi. Production ilk stable yayın hazır değildir.
