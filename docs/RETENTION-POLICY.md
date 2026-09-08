# Saklama Politikasi (Retention Policy)

## Snapshot ve artifact saklama sureleri

| Tur                          | Saklama Suresi     |
|------------------------------|--------------------|
| Final release snapshot       | Kalici / uzun sure |
| Son 3 stable snapshot        | Zorunlu            |
| Failed RC snapshot           | 90 gun             |
| Beta snapshot                | 90 gun             |
| CI scratch                   | 14-30 gun          |

Aktif publication veya release manifest tarafindan referans verilen hicbir
nesne silinemez.

## Fedora lifecycle

Ro-ASD ayni anda cok sayida Fedora major release desteklemez.

```text
1 stable Fedora tabani  (su an: Fedora 44)
+
1 sonraki Fedora tabani  (migration testing)
```

Ornek: Fedora 44 stable iken Fedora 45 yalniz migration testing'dir.
Fedora 45 stable olunca Fedora 44 maintenance/EOL surecine girer.

## Secure Boot

Repo V2 RPM imzasi ile UEFI Secure Boot imzasi ayni problem degildir.

V2'yi Secure Boot altyapisi nedeniyle bloke etme. Ancak kernel producer
Ro-Repo V2'ye eklendiginde asagidaki konular ayri release-engineering
blocker olacaktir:

- shim
- GRUB
- kernel PE signing
- kernel module signing
- Secure Boot dogrulama

Bu acik bicimde roadmap'e yazilmistir.
