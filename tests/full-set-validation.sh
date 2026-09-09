#!/usr/bin/env bash
set -euo pipefail
script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="${1:?usage: full-set-validation.sh SNAPSHOT_ROOT ARCH}"
arch="${2:-x86_64}"
baseline_dir="${3:-}"
repo_dir="$repo_root/rpm/$arch"
public_key="$repo_root/keys/RPM-GPG-KEY-ro-asd-TEST-ONLY"
test -f "$repo_dir/repodata/repomd.xml"
test -f "$public_key"
repo_args=(
    --repofrompath "ro-snapshot,file://$repo_dir"
    --setopt=ro-snapshot.gpgcheck=1
    --setopt=ro-snapshot.repo_gpgcheck=1
    --setopt="ro-snapshot.gpgkey=file://$public_key"
)

run_assumeno_transaction() {
    local output
    set +e
    output="$(dnf --assumeno "${repo_args[@]}" "$@" 2>&1)"
    local status=$?
    set -e
    printf '%s\n' "$output"
    if printf '%s\n' "$output" | grep -Eq 'Operation aborted|Transaction Summary'; then
        return 0
    fi
    return "$status"
}

dnf -y "${repo_args[@]}" --repo ro-snapshot makecache
pkgs=$(dnf "${repo_args[@]}" repoquery --disablerepo="*" --enablerepo="ro-snapshot" --qf '%{name}' | sort -u)
if [ -n "$pkgs" ]; then
    run_assumeno_transaction install $pkgs
    if [ -z "$baseline_dir" ]; then
        echo "ERROR: upgrade simulation requires a baseline RPM directory" >&2
        exit 1
    fi
    installroot="$(mktemp -d)"
    trap 'rm -rf "$installroot"' EXIT
    rpmdb="$installroot/usr/lib/sysimage/rpm"
    mkdir -p "$rpmdb"
    rpm --dbpath "$rpmdb" --initdb
    rpm --dbpath "$rpmdb" --justdb --nodeps -Uvh "$baseline_dir"/*.rpm
    dnf -y "${repo_args[@]}" --installroot "$installroot" --releasever=44 --use-host-config --repo ro-snapshot makecache
    run_assumeno_transaction --installroot "$installroot" --releasever=44 --use-host-config upgrade $pkgs
fi
rpm_files=("$repo_dir"/*.rpm)
command -v rpmlint >/dev/null || { echo "ERROR: rpmlint is not installed"; exit 1; }
python3 - "${rpm_files[@]}" <<'PY'
import pathlib
import subprocess
import sys

owners = {}
conflicts = []
for rpm in map(pathlib.Path, sys.argv[1:]):
    files = subprocess.check_output(["rpm", "-qpl", str(rpm)], text=True).splitlines()
    for item in files:
        if item.endswith("/"):
            continue
        if item in owners and owners[item] != rpm.name:
            conflicts.append(f"{item}: {owners[item]} and {rpm.name}")
        owners[item] = rpm.name
if conflicts:
    print("ERROR: file conflicts detected")
    print("\n".join(conflicts))
    raise SystemExit(1)
PY

rpmkeys --import "$public_key"

rpmlint_args=(-c "$script_root/tests/rpmlint-tests.toml")
rpmlint "${rpmlint_args[@]}" "${rpm_files[@]}"
