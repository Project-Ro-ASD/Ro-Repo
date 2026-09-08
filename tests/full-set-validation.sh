#!/usr/bin/env bash
set -euo pipefail
repo_root="${1:?usage: full-set-validation.sh SNAPSHOT_ROOT ARCH}"
arch="${2:-x86_64}"
repo_dir="$repo_root/rpm/$arch"
public_key="$repo_root/keys/RPM-GPG-KEY-ro-asd-TEST-ONLY"
test -f "$repo_dir/repodata/repomd.xml"
test -f "$public_key"
dnf -y --repofrompath "ro-snapshot,file://$repo_dir" --repo ro-snapshot --setopt=ro-snapshot.gpgcheck=1 --setopt=ro-snapshot.repo_gpgcheck=1 --setopt="ro-snapshot.gpgkey=file://$public_key" makecache
dnf -y --assumeno --repo ro-snapshot install ro-control ro-assist ro-theme || status=$?
test "${status:-1}" -eq 1
rpm_files=("$repo_dir"/*.rpm)
rpmlint "${rpm_files[@]}"
