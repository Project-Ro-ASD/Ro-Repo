# Ro-Repo V2 Faz 1 Operasyonlari

Her girdi release; repository, tag, tam commit SHA, release ID, workflow run,
manifest ve artifact SHA-256 degerleriyle sabitlenir. `latest` yasaktir. Release
asset'i degisebilir kabul edilir ve indirilen baytlar yeniden dogrulanir.

Kabul, imzalama ve yayin ayri yetki alanlaridir. Producer ozel anahtar veya
stable yayin yetkisi almaz. Producer hash'i ile imza sonrasi yayin hash'i ayri
alanlarda tutulur.

Snapshot degismez icerik kimligidir. `beta` ve `stable` degisebilir yayin
gorunumleridir; `candidate` DNF kanali yoktur. Promotion manifesti lifecycle
bilgisini tasir, snapshot manifestine yazilmaz. `publish-local` agaci gecici
dizinde kurar ve `repomd.xml` dosyasini son adimda gorunur kilar.
`rollback-publication` kanali onceki gorunumle atomik olarak degistirir.

Normal uygulama ve kritik masaustu paketleri en az 7, kritik sistem paketleri
14 gun beta'da kalir. Sure kanit yerine gecmez. Acil terfi bos olmayan gerekce
ve `emergency=true` ister.

Bir stable Fedora tabani ve sonraki taban icin gecis testi desteklenir. Fedora
44 stable iken Fedora 45 yalniz migration testing'dir. Faz 1'de remote stable
backend yoktur; haftalik is yalniz deterministic local snapshot fixture uzerinde
gercek `dnf` dependency solve/install/upgrade ve `rpmlint` yolunu calistirir.
Remote stable snapshot uyumluluk testi Faz 2 publication backend'ine baglanir.

Publication rollback yalniz stable gorunumunu geri alir; istemciyi otomatik
downgrade etmez. Client rollback ve boot/kernel/installer system recovery ayri
islemlerdir.

Final snapshot kalici; son uc stable zorunlu; failed RC ve beta 90 gun; scratch
14-30 gun tutulur. Aktif manifestin referans verdigi nesne silinemez.

Secure Boot, RPM repository imzasindan farklidir. Kernel producer eklenince
shim, GRUB, kernel PE, modul imzasi ve gercek Secure Boot testleri ayri blocker
olacaktir.
