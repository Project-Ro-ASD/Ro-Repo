# Ro-Repo

Ro-Repo, Ro-ASD Linux dağıtımı için RPM paketlerini ve Ro Store katalog verilerini yayımlayan resmi paket deposudur.

Paketler GitHub Releases üzerinden otomatik olarak alınır, mimarilerine göre ayrılır ve DNF tarafından kullanılabilecek repository metadata dosyaları oluşturulur.

## Desteklenen mimariler

- `x86_64`
- `aarch64`
- `noarch`
- Mevcut olduğunda kaynak RPM paketleri (`SRPMS`)

## Depoyu Fedora’ya ekleme

Aşağıdaki komutu terminalde çalıştırın:

```bash
sudo tee /etc/yum.repos.d/ro-repo.repo >/dev/null <<'EOF'
[ro-repo]
name=Ro-ASD Repository
baseurl=https://project-ro-asd.github.io/Ro-Repo/$basearch/
enabled=1
gpgcheck=0

[ro-repo-noarch]
name=Ro-ASD Repository - Noarch
baseurl=https://project-ro-asd.github.io/Ro-Repo/noarch/
enabled=1
gpgcheck=0
EOF
```

Ardından repository önbelleğini yenileyin:

```bash
sudo dnf makecache --refresh
```

## Paketleri listeleme

```bash
dnf repoquery --available --repo=ro-repo --repo=ro-repo-noarch
```

## Paket kurulumu

```bash
sudo dnf install ro-control
sudo dnf install ro-assist
sudo dnf install ro-theme
```

## Repository yapısı

```text
Ro-Repo/
├── x86_64/       # x86_64 RPM paketleri
├── aarch64/      # ARM64 RPM paketleri
├── noarch/       # Mimariden bağımsız RPM paketleri
├── SRPMS/        # Kaynak RPM paketleri
├── store/        # Ro Store katalog ve ikon dosyaları
└── .github/      # Repository güncelleme otomasyonu
```

## Otomatik güncelleme

GitHub Actions workflow’u:

1. ro-Control, ro-Assist ve Ro-Theme projelerinin son Release RPM’lerini indirir.
2. Paketleri mimarilerine göre ayırır.
3. RPM değişikliği olup olmadığını kontrol eder.
4. Değişiklik varsa repository metadata dosyalarını yeniden oluşturur.
5. Oluşan değişiklikleri otomatik olarak repoya gönderir.

Workflow her gün `00:00 UTC` saatinde ve gerektiğinde manuel olarak çalıştırılabilir.

## GitHub Pages

Kurulum sayfası:

https://project-ro-asd.github.io/Ro-Repo/

## Güvenlik notu

RPM paket imzalama sistemi henüz etkin olmadığı için repository yapılandırmasında geçici olarak `gpgcheck=0` kullanılmaktadır. GPG imzalama etkinleştirildiğinde bu ayar güncellenecektir.

## Lisans

Bu proje GNU General Public License v3 kapsamında yayımlanmaktadır.

---

Project Ro-ASD tarafından geliştirilmektedir.
