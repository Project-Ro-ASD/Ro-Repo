#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
site_root="${1:?usage: remote-promotion-validation.sh SITE_ROOT EVIDENCE_OUT}"
evidence_out="${2:?usage: remote-promotion-validation.sh SITE_ROOT EVIDENCE_OUT}"

beta_root="$site_root/rpm/fedora/44/beta"
publication="$beta_root/publication-v1.json"
test -f "$publication"

snapshot_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["snapshot_id"])' "$publication")"
beta_run="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["publication_run"])' "$publication")"
beta_started_at="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["published_at"])' "$publication")"
validation_run="${GITHUB_RUN_ID:?GITHUB_RUN_ID is required for exact evidence binding}"

snapshot="$site_root/snapshots/fedora/44/$snapshot_id"
manifest="$snapshot/repository-snapshot-v1.json"
test -f "$manifest"

expected_snapshot="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["snapshot_id"])' "$manifest")"
test "$expected_snapshot" = "$snapshot_id"

target_rpm_rel="$(python3 - "$manifest" <<'PY'
import json, sys
data=json.load(open(sys.argv[1]))
matches=[p for p in data["packages"] if p["architecture"]=="x86_64" and p["nevra"].startswith("ro-assist-")]
if len(matches)!=1:
    raise SystemExit(f"expected exactly one ro-assist x86_64 package, got {len(matches)}")
print("rpm/x86_64/" + matches[0]["filename"])
PY
)"
target_rpm="$snapshot/$target_rpm_rel"
test -f "$target_rpm"
target_name="$(rpm -qp --qf '%{NAME}' "$target_rpm")"
target_version="$(rpm -qp --qf '%{VERSION}' "$target_rpm")"
target_release="$(rpm -qp --qf '%{RELEASE}' "$target_rpm")"
target_arch="$(rpm -qp --qf '%{ARCH}' "$target_rpm")"
test "$target_name" = "ro-assist"
test "$target_arch" = "x86_64"
target_nvr="$target_name $target_version-$target_release"

remote_base="https://repo.ro-asd.org/rpm/fedora/44/beta/x86_64"
rpm_key="$(realpath "$snapshot/keys/RPM-GPG-KEY-ro-asd")"
metadata_key="$(realpath "$snapshot/keys/REPODATA-GPG-KEY-ro-asd")"
test -f "$rpm_key"
test -f "$metadata_key"

work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

baseline_cfg="$root/config/promotion-baselines-v1.json"
baseline_repo="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["baselines"]["ro-assist"]["x86_64"]["repository"])' "$baseline_cfg")"
baseline_tag="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["baselines"]["ro-assist"]["x86_64"]["release_tag"])' "$baseline_cfg")"
baseline_file="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["baselines"]["ro-assist"]["x86_64"]["filename"])' "$baseline_cfg")"
baseline_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["baselines"]["ro-assist"]["x86_64"]["sha256"])' "$baseline_cfg")"
baseline_url="https://github.com/$baseline_repo/releases/download/$baseline_tag/$baseline_file"

curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error   "$baseline_url" -o "$work/$baseline_file"
printf '%s  %s\n' "$baseline_sha" "$work/$baseline_file" | sha256sum --check --strict

reposdir="$work/repos"
mkdir -p "$reposdir"
cat > "$reposdir/ro-beta.repo" <<EOF
[ro-beta]
name=Ro-ASD remote beta promotion validation
baseurl=$remote_base
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file://$metadata_key
       file://$rpm_key
metadata_expire=0
skip_if_unavailable=0
EOF

common=(
  --setopt="reposdir=$reposdir"
  --setopt="cachedir=$work/dnf-cache"
  --setopt="persistdir=$work/dnf-persist"
  --releasever=44
)
# Copy host Fedora repositories into the isolated reposdir while keeping
# ro-beta as a normal repo file. This models the client-side configuration.
for repo_file in /etc/yum.repos.d/*.repo; do
  cp "$repo_file" "$reposdir/"
done

# Trust bootstrap: CI is non-interactive. Accept only the exact public keys
# pinned in the immutable snapshot, then verify signed repository metadata.
dnf -y "${common[@]}" --refresh --repo=ro-beta makecache

# Preflight: prove DNF5 loads primary metadata from the exact remote beta repo
# before any transaction test.
repoquery_output="$(dnf "${common[@]}" --refresh --repo=ro-beta repoquery ro-assist \
  --qf '%{name} %{version}-%{release} %{arch}')"
printf '%s\n' "$repoquery_output"
grep -Fx "$target_nvr $target_arch" <<<"$repoquery_output" >/dev/null

# 1) dependency-solve
set +e
solve_output="$(dnf "${common[@]}" --refresh --assumeno \
  --repo=ro-beta --repo=fedora --repo=updates install ro-assist 2>&1)"
solve_status=$?
set -e
if ! grep -Eq 'Operation aborted|Transaction Summary' <<<"$solve_output"; then
  printf '%s\n' "$solve_output" >&2
  exit "${solve_status:-1}"
fi

# 2) clean-install
clean_root="$work/clean-root"
dnf -y "${common[@]}" --refresh --installroot "$clean_root" \
  --repo=ro-beta --repo=fedora --repo=updates install ro-assist
rpm --root "$clean_root" -q ro-assist >/dev/null

# 3) upgrade from pinned earlier release
upgrade_root="$work/upgrade-root"
rpmdb="$upgrade_root/usr/lib/sysimage/rpm"
mkdir -p "$rpmdb"
rpm --dbpath "$rpmdb" --initdb
rpm --dbpath "$rpmdb" --justdb --nodeps -Uvh "$work/$baseline_file"
set +e
upgrade_output="$(dnf "${common[@]}" --refresh --assumeno --installroot "$upgrade_root" \
  --repo=ro-beta --repo=fedora --repo=updates upgrade ro-assist 2>&1)"
upgrade_status=$?
set -e
if ! grep -Eq 'Operation aborted|Transaction Summary' <<<"$upgrade_output"; then
  printf '%s\n' "$upgrade_output" >&2
  exit "${upgrade_status:-1}"
fi
grep -F "$target_version" <<<"$upgrade_output" >/dev/null

# Local exact snapshot bytes are already bound to the remote beta by publication-v1.
rpm_files=("$snapshot/rpm/x86_64"/*.rpm)
test -e "${rpm_files[0]}"

# 4) file-conflict
python3 - "${rpm_files[@]}" <<'PY'
import pathlib, subprocess, sys
owners = {}
conflicts = []
for rpm in map(pathlib.Path, sys.argv[1:]):
    for item in subprocess.check_output(["rpm", "-qpl", str(rpm)], text=True).splitlines():
        if item.endswith("/"):
            continue
        previous = owners.get(item)
        if previous and previous != rpm.name:
            conflicts.append(f"{item}: {previous} and {rpm.name}")
        owners[item] = rpm.name
if conflicts:
    raise SystemExit("file conflicts detected:\n" + "\n".join(conflicts))
PY

# 5) rpmlint with the production RPM public key trusted only in a temporary rpmdb.
rpmlint_rpmdb="$work/rpmlint-rpmdb"
rpmlint_keyring="$rpmlint_rpmdb/pubkeys"
rpmlint_home="$work/rpmlint-home"
rpmlint_bin="$work/rpmlint-bin"
mkdir -p "$rpmlint_rpmdb" "$rpmlint_keyring" "$rpmlint_home/.config/rpm" "$rpmlint_bin"
rpm --dbpath "$rpmlint_rpmdb" --initdb
rpmkeys --dbpath "$rpmlint_rpmdb" --import "$rpm_key"
{
  printf '%%_dbpath %s\n' "$rpmlint_rpmdb"
  printf '%%_keyringpath %s\n' "$rpmlint_keyring"
} > "$rpmlint_home/.config/rpm/macros"
printf '#!/usr/bin/env bash\nexec /usr/bin/rpm --define %q --define %q "$@"\n'   "_dbpath $rpmlint_rpmdb" "_keyringpath $rpmlint_keyring" > "$rpmlint_bin/rpm"
chmod +x "$rpmlint_bin/rpm"
HOME="$rpmlint_home" PATH="$rpmlint_bin:$PATH"   rpmlint -c "$root/tests/rpmlint-tests.toml" "${rpm_files[@]}"

# 6) smoke: clean install contains exact expected package version and payload.
installed="$(rpm --root "$clean_root" -q --qf '%{NAME} %{VERSION}-%{RELEASE}\n' ro-assist)"
grep -Fx "$target_nvr" <<<"$installed" >/dev/null
rpm --root "$clean_root" -ql ro-assist | grep -Eq '/usr/(bin|libexec)/|/usr/share/applications/' 

python3 - "$evidence_out" "$snapshot_id" "$validation_run" "$beta_run" "$beta_started_at" \
  "$remote_base" "$baseline_repo" "$baseline_tag" "$baseline_file" "$baseline_sha" <<'PY'
import datetime as dt
import json
import os
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
snapshot_id, validation_run, beta_run, beta_started_at, remote_base = sys.argv[2:7]
baseline_repo, baseline_tag, baseline_file, baseline_sha = sys.argv[7:11]
payload = {
    "schema_version": 1,
    "scope": "remote-beta-promotion",
    "snapshot_id": snapshot_id,
    "validation_run": validation_run,
    "beta_publication_run": beta_run,
    "beta_started_at": beta_started_at,
    "tested_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "architecture": "x86_64",
    "remote_base": remote_base,
    "result": "pass",
    "tests": [
        {"name": "dependency-solve", "result": "pass"},
        {"name": "clean-install", "result": "pass"},
        {"name": "upgrade", "result": "pass"},
        {"name": "file-conflict", "result": "pass"},
        {"name": "rpmlint", "result": "pass"},
        {"name": "smoke", "result": "pass"}
    ],
    "baseline": {
        "repository": baseline_repo,
        "release_tag": baseline_tag,
        "filename": baseline_file,
        "sha256": baseline_sha
    }
}
out.parent.mkdir(parents=True, exist_ok=True)
tmp = out.with_name(out.name + ".tmp")
tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(tmp, out)
PY

python3 "$root/tools/ro-repo" validate-json   --schema promotion-validation-v1   --input "$evidence_out"

echo "remote beta promotion validation passed: $snapshot_id / beta run $beta_run"
