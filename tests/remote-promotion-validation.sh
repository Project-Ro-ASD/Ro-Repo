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

remote_base="https://repo.ro-asd.org/rpm/fedora/44/beta/x86_64"
rpm_key="$snapshot/keys/RPM-GPG-KEY-ro-asd"
metadata_key="$snapshot/keys/REPODATA-GPG-KEY-ro-asd"
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

repos="$work/repos"
mkdir -p "$repos"
cat > "$repos/ro-beta.repo" <<EOF
[ro-beta]
name=Ro-ASD remote beta promotion validation
baseurl=$remote_base
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file://$metadata_key file://$rpm_key
EOF

common=(
  --setopt="reposdir=$repos"
  --setopt="cachedir=$work/dnf-cache"
  --setopt="persistdir=$work/dnf-persist"
  --releasever=44
)

# 1) dependency-solve
set +e
solve_output="$(dnf "${common[@]}" --assumeno --enablerepo=fedora --enablerepo=updates --enablerepo=ro-beta install ro-assist 2>&1)"
solve_status=$?
set -e
if ! grep -Eq 'Operation aborted|Transaction Summary' <<<"$solve_output"; then
  printf '%s\n' "$solve_output" >&2
  exit "${solve_status:-1}"
fi

# 2) clean-install
clean_root="$work/clean-root"
dnf -y "${common[@]}" --installroot "$clean_root"   --enablerepo=fedora --enablerepo=updates --enablerepo=ro-beta install ro-assist
rpm --root "$clean_root" -q ro-assist >/dev/null

# 3) upgrade from pinned earlier release
upgrade_root="$work/upgrade-root"
rpmdb="$upgrade_root/usr/lib/sysimage/rpm"
mkdir -p "$rpmdb"
rpm --dbpath "$rpmdb" --initdb
rpm --dbpath "$rpmdb" --justdb --nodeps -Uvh "$work/$baseline_file"
set +e
upgrade_output="$(dnf "${common[@]}" --assumeno --installroot "$upgrade_root"   --enablerepo=fedora --enablerepo=updates --enablerepo=ro-beta upgrade ro-assist 2>&1)"
upgrade_status=$?
set -e
if ! grep -Eq 'Operation aborted|Transaction Summary' <<<"$upgrade_output"; then
  printf '%s\n' "$upgrade_output" >&2
  exit "${upgrade_status:-1}"
fi
grep -F '0.2.4' <<<"$upgrade_output" >/dev/null

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

# 5) rpmlint
rpmlint -c "$root/tests/rpmlint-tests.toml" "${rpm_files[@]}"

# 6) smoke: clean install contains exact expected package version and payload.
installed="$(rpm --root "$clean_root" -q --qf '%{NAME} %{VERSION}-%{RELEASE}\n' ro-assist)"
grep -Fx 'ro-assist 0.2.4-1.fc44' <<<"$installed" >/dev/null
rpm --root "$clean_root" -ql ro-assist | grep -Eq '/usr/(bin|libexec)/|/usr/share/applications/' 

python3 - "$evidence_out" "$snapshot_id" "$beta_run" "$beta_started_at"   "$remote_base" "$baseline_repo" "$baseline_tag" "$baseline_file" "$baseline_sha" <<'PY'
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
