#!/usr/bin/env bash
set -euo pipefail
script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="${1:?usage: full-set-validation.sh SNAPSHOT_ROOT ARCH}"
arch="${2:-x86_64}"
baseline_dir="${3:-}"
repo_dir="$repo_root/rpm/$arch"
public_key="$repo_root/keys/RPM-GPG-KEY-ro-asd-TEST-ONLY"
metadata_key="$repo_root/keys/REPODATA-GPG-KEY-ro-asd-TEST-ONLY"
validation_root="$(mktemp -d)"
cleanup() {
    rm -rf "$validation_root"
}
trap cleanup EXIT
test -f "$repo_dir/repodata/repomd.xml"
test -f "$public_key"
test -f "$metadata_key"
repo_args=(
    --repofrompath "ro-snapshot,file://$repo_dir"
    --setopt=ro-snapshot.gpgcheck=1
    --setopt=ro-snapshot.repo_gpgcheck=1
    --setopt="ro-snapshot.gpgkey=file://$public_key file://$metadata_key"
    --setopt="cachedir=$validation_root/dnf-cache"
    --setopt="persistdir=$validation_root/dnf-persist"
)
solve_repos=(
    --disablerepo="*"
    --enablerepo="fedora"
    --enablerepo="updates"
    --enablerepo="ro-snapshot"
)
snapshot_repo_only=(
    --disablerepo="*"
    --enablerepo="ro-snapshot"
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

dnf -y "${repo_args[@]}" --installroot "$validation_root/query-root" --releasever=44 --use-host-config "${snapshot_repo_only[@]}" makecache
pkgs=$(dnf "${repo_args[@]}" --installroot "$validation_root/query-root" --releasever=44 --use-host-config repoquery "${snapshot_repo_only[@]}" --qf '%{name}' | sort -u)
if [ -n "$pkgs" ]; then
    run_assumeno_transaction --installroot "$validation_root/clean-root" --releasever=44 --use-host-config "${solve_repos[@]}" install $pkgs
    if [ -z "$baseline_dir" ]; then
        echo "ERROR: upgrade simulation requires a baseline RPM directory" >&2
        exit 1
    fi
    installroot="$validation_root/upgrade-root"
    rpmdb="$installroot/usr/lib/sysimage/rpm"
    mkdir -p "$rpmdb"
    rpm --dbpath "$rpmdb" --initdb
    rpmkeys --dbpath "$rpmdb" --import "$public_key"
    rpm --dbpath "$rpmdb" --justdb --nodeps -Uvh "$baseline_dir"/*.rpm
    dnf -y "${repo_args[@]}" --installroot "$installroot" --releasever=44 --use-host-config "${snapshot_repo_only[@]}" makecache
    run_assumeno_transaction --installroot "$installroot" --releasever=44 --use-host-config "${solve_repos[@]}" upgrade $pkgs
fi
rpm_files=("$repo_dir"/*.rpm)
command -v rpmlint >/dev/null || { echo "ERROR: rpmlint is not installed"; exit 1; }
filecheck_rpmdb="$validation_root/filecheck-rpmdb"
mkdir -p "$filecheck_rpmdb"
rpm --dbpath "$filecheck_rpmdb" --initdb
rpmkeys --dbpath "$filecheck_rpmdb" --import "$public_key"
python3 - "$filecheck_rpmdb" "${rpm_files[@]}" <<'PY'
import pathlib
import subprocess
import sys

rpmdb = sys.argv[1]
owners = {}
conflicts = []
for rpm in map(pathlib.Path, sys.argv[2:]):
    files = subprocess.check_output(["rpm", "--dbpath", rpmdb, "-qpl", str(rpm)], text=True).splitlines()
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

rpmlint_args=(-c "$script_root/tests/rpmlint-tests.toml")
rpmlint_rpmdb="$validation_root/rpmlint-rpmdb"
rpmlint_keyring="$rpmlint_rpmdb/pubkeys"
rpmlint_home="$validation_root/rpmlint-home"
rpmlint_bin="$validation_root/rpmlint-bin"
mkdir -p "$rpmlint_rpmdb" "$rpmlint_keyring" "$rpmlint_home/.config/rpm" "$rpmlint_bin"
rpm --dbpath "$rpmlint_rpmdb" --initdb
rpmkeys --dbpath "$rpmlint_rpmdb" --import "$public_key"
{
    printf '%%_dbpath %s\n' "$rpmlint_rpmdb"
    printf '%%_keyringpath %s\n' "$rpmlint_keyring"
} > "$rpmlint_home/.config/rpm/macros"
printf '#!/usr/bin/env bash\nexec /usr/bin/rpm --define %q --define %q "$@"\n' "_dbpath $rpmlint_rpmdb" "_keyringpath $rpmlint_keyring" > "$rpmlint_bin/rpm"
chmod +x "$rpmlint_bin/rpm"
HOME="$rpmlint_home" PATH="$rpmlint_bin:$PATH" rpmlint "${rpmlint_args[@]}" "${rpm_files[@]}"
