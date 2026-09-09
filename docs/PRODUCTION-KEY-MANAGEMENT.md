# Production Key Management

Bu belge Ro-Repo production OpenPGP anahtarlarinin yasam dongusunu, yedekleme
politikasini, CI'ya aktarim kurallarini ve rotation/revocation prosedurunu tanimlar.
Secret key materyali, parola veya revocation certificate bu repoya commit edilmez.

## Mimari

Production trust root tek bir offline primary key'dir. Primary key yalniz
certification yetkisine sahiptir ve normal paket/repository imzalamada kullanilmaz.
Iki ayri signing subkey vardir:

- RPM signing subkey: yalniz RPM paket imzalari icin.
- Metadata signing subkey: yalniz repository metadata ve snapshot metadata
  imzalari icin.

Ro-Repo production islemlerinde primary key ID kullanmak yasaktir. Her rol exact
40-hex subkey fingerprint'i ile ve GnuPG tarafinda `FINGERPRINT!` biciminde
secilir. Role-specific public export yalniz primary public certificate ile ilgili
tek signing subkey'i icermelidir.

Secure Boot anahtarlari bu guven zincirinin parcasi degildir ve ayri yonetilir.

## 2026-09-09 production key ceremony kaydi

Production key ceremony internet baglantisi kapali bir ortamda tamamlandi.
Olusturulan yapi:

- RSA4096 certification-only offline primary key, expiry: 2031-09-08.
- RSA4096 RPM signing subkey, signing-only, expiry: 2028-09-08.
- RSA4096 metadata signing subkey, signing-only, expiry: 2028-09-08.
- Primary revocation certificate olusturuldu.
- Tam secret key setini ve revocation materyalini iceren sifreli master backup
  olusturuldu.
- Ayni sifreli backup iki ayri fiziksel USB ortamina kopyalandi ve SHA-256
  degerleri source backup ile birebir dogrulandi.
- Backup bos bir GNUPGHOME'a restore edilerek primary + iki signing subkey'in
  kurtarilabildigi dogrulandi.
- RPM ve metadata signing subkey'leriyle exact-fingerprint imza testi yapildi.
- Role-specific public certificate'lerin yalniz kendi signing subkey'lerini
  dogrulayabildigi, diger rolun imzasini dogrulayamadigi test edildi.
- CI icin subkey-only secret export'lar gecici ortamda test edildi; exportlarda
  primary secret key bulunmadigi `sec#` + tek `ssb` gorunumu ile dogrulandi.
- Ceremony sonunda gecici secret materyal RAM tabanli calisma alanindan silindi
  ve GPG agent cache kapatildi.

Ceremony sirasinda uretilen secret materyalin hicbiri GitHub'a, cloud storage'a
veya normal workstation depolamasina aktarilmadi.

## Public key publication

Public keyler gizli degildir ve Ro-ASD istemcilerinin imzalari dogrulamasi icin
yayinlanir. Production signing Phase 2'de devreye alinmadan once canonical public
key seti repoda ve daha sonra `ro-asd-repos` paketinde yayinlanmalidir.

Beklenen canonical dosyalar:

- `keys/production/ro-asd-public.asc`
- `keys/production/ro-asd-rpm-signing-public.asc`
- `keys/production/ro-asd-metadata-signing-public.asc`
- `keys/production/production-fingerprints.txt`

`production-fingerprints.txt` primary, RPM signing ve metadata signing exact
40-hex fingerprint'lerini isimleriyle tasimalidir. Public key dosyalari
commit edilmeden once import-options show-only ile incelenmeli ve role-specific
exportlarda tam olarak bir `pub` ve beklenen tek `sub` bulunmalidir.

Repoda `secret`, `private`, `revocation`, `backup`, `export-secret` veya benzeri
secret key materyali tutulmaz.

## Offline backup politikasi

En az iki sifreli offline master backup tutulur. Iki kopya ayni fiziksel yerde
saklanmamalidir. Backup parolasi USB medyanin uzerinde veya ayni yerde tutulmaz.

Asagidaki olaylardan sonra restore testi zorunludur:

1. Primary veya subkey degisikligi.
2. Yeni backup medyasi olusturulmasi.
3. Backup formatinin veya sifreleme yonteminin degistirilmesi.

Bunlara ek olarak en az yilda bir kez offline restore testi yapilmalidir. Bir
backup medyasi bozulursa kalan tek kopyayla uzun sure devam edilmez; yeni ikinci
kopya olusturulur ve tekrar dogrulanir.

Workstation formatlandiginda master secret key geri yuklenmez. Normal gelistirme
icin yalniz public keyler gerekir. Offline primary ancak rotation, revocation,
yeni signing subkey olusturma veya disaster recovery icin gecici offline ortama
restore edilir.

## CI secret provisioning

Primary secret key CI'ya, GitHub Actions'a veya herhangi bir online signer'a
aktarilmaz.

Production signing devreye alinirken her rol icin yalniz ilgili subkey'i iceren
subkey-only secret export uretilir ve ilgili protected environment secret'ina
aktarilir:

- RPM signing secret yalniz RPM signing job'ina.
- Metadata signing secret yalniz metadata signing job'ina.

Iki role ait secret export ayni generic secret olarak kullanilmaz. Workflow her
zaman exact subkey fingerprint + `!` ile anahtari secer. Wrong-role signature
Ro-Repo tarafinda fail-closed reddedilir.

Secret provisioning offline master backup'tan yapilacaksa workstation once
offline edilir, gecici GNUPGHOME kullanilir, gerekli subkey-only export uretilir,
provisioning tamamlandiktan sonra gecici secret dosya ve GPG agent cache silinir.

## Normal subkey rotation

Signing subkey'ler expiry tarihinden en gec 90 gun once rotate edilmelidir.
Normal rotation sirasi:

1. Publication freeze penceresi belirle.
2. Offline primary'yi sifreli backup'tan gecici offline GNUPGHOME'a restore et.
3. Yalniz gerekli rol icin yeni signing-only subkey olustur.
4. Yeni exact fingerprint'i kaydet ve role-specific public export'u uret.
5. Master backup'i yeni key state ile yeniden olustur, iki offline kopyaya yaz,
   SHA-256 kontrolu ve restore testi yap.
6. Yeni role-specific secret subkey'i ilgili protected environment'a provision et.
7. Ro-Repo trusted fingerprint/config ve public key paketini PR ile guncelle.
8. Canary imza ve dogrulama testi yap. Wrong-role testinin hala fail ettigini
   dogrula.
9. Yeni public trust materyalini istemcilere eski key henuz gecerliyken dagit.
10. Yeni key ile production signing'e gec. Eski key'i overlap suresi boyunca
    yalniz rollback/dogrulama amaciyla tut; yeni artifact imzalamada kullanma.
11. Rotation kanitini ve effective transition zamanini kaydet.
12. Gecici offline secret materyali sil ve GPG agent'i kapat.

Normal rotation immutable snapshot'lari yeniden imzalamaz veya gecmisi yeniden
yazmaz.

## Signing subkey compromise / revocation

RPM veya metadata signing subkey'lerinden birinin kompromize oldugundan
suphelenilirse:

1. Ilgili production signing job ve environment deployment'larini durdur.
2. Kompromize role ait CI secret'i devre disi birak veya sil.
3. Pending promotion/release islemlerini durdur; kompromiz zamanindan sonra
   uretilen imzalari guvenilir kabul etme.
4. Offline primary ile kompromize signing subkey'i revoke et.
5. Ayni rol icin yeni signing-only subkey olustur.
6. Yeni public certificate/fingerprint ve revocation bilgisini canonical trust
   kaynaklarinda yayinla.
7. Yeni role-specific secret subkey'i provision et ve canary testlerini calistir.
8. Ro-Repo policy/config'i yeni exact fingerprint'e gecir.
9. Olay kaydi, etkilenen zaman araligi ve etkilenen snapshot/release kimliklerini
   belgeleyerek incele.

Diger signing rolunun kompromize olduguna dair kanit yoksa gereksiz yere onun
secret key'i rotate edilmez; ancak olay analizi iki rolun izolasyonunun gercekten
korundugunu dogrulamalidir.

## Primary key compromise

Primary secret key'in kompromize oldugundan suphelenilmesi trust-root olayi
sayilir:

1. Tum production signing ve promotion islemlerini durdur.
2. Primary revocation certificate ve/veya offline kalan guvenilir materyal ile
   primary key'i revoke et.
3. Mevcut RPM ve metadata signing subkey'lerini de artik yeni production
   artifact imzalamada kullanma.
4. Yeni offline primary ve yeni role-specific signing subkey'lerle yeni trust
   root olustur.
5. Yeni public trust root'u bagimsiz resmi kanallarda yayinla ve istemci trust
   paketini kontrollu migration ile guncelle.
6. Kompromiz zaman araligini belirle, o araliktaki release/snapshot kanitlarini
   incele ve gerekirse promotion'i geri cek.
7. Immutable historical evidence silinmez veya yeniden yazilmaz; olay kaydi ile
   birlikte korunur.

Primary revocation certificate emergency kullanimi icindir ve public repository
icinde normal dosya olarak tutulmaz.

## Ayrilik ve tek-maintainer gercegi

Ro-ASD bugun tek-maintainer projedir. `acceptance`, `signing` ve `promotion`
rolleri teknik ve policy seviyesinde ayridir, fakat bu gercek bir organizasyonel
separation-of-duties iddiasi degildir. Ikinci guvenilir maintainer eklendiginde
production environment reviewer ve PR approval kurallari yeniden sertlestirilir.
