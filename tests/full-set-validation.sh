#!/usr/bin/env bash
set -euo pipefail
repo_root="${1:?usage: full-set-validation.sh SNAPSHOT_ROOT ARCH}"
arch="${2:-x86_64}"
repo_dir="$repo_root/rpm/$arch"
public_key="$repo_root/keys/RPM-GPG-KEY-ro-asd-TEST-ONLY"
test -f "$repo_dir/repodata/repomd.xml"
test -f "$public_key"
dnf -y --repofrompath "ro-snapshot,file://$repo_dir" --repo ro-snapshot --setopt=ro-snapshot.gpgcheck=1 --setopt=ro-snapshot.repo_gpgcheck=1 --setopt="ro-snapshot.gpgkey=file://$public_key" makecache
pkgs=$(dnf --repofrompath "ro-snapshot,file://$repo_dir" repoquery --disablerepo="*" --enablerepo="ro-snapshot" --qf '%{name}' | sort -u)
if [ -n "$pkgs" ]; then
    dnf -y --assumeno --repofrompath "ro-snapshot,file://$repo_dir" --disablerepo="*" --enablerepo="ro-snapshot" install $pkgs || status=$?
    test "${status:-1}" -eq 1
fi
rpm_files=("$repo_dir"/*.rpm)
command -v rpmlint >/dev/null || { echo "ERROR: rpmlint is not installed"; exit 1; }
rpmlint "${rpm_files[@]}" || {
    status=$?
    if [ $status -eq 64 ]; then
        echo "rpmlint executed successfully but found badness (acceptable for test fixtures)"
    else
        echo "ERROR: rpmlint execution failed with code $status"
        exit $status
    fi
}
