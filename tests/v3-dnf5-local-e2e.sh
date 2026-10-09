#!/usr/bin/env bash
# Fedora 44 ONLY. Real DNF5 installs and upgrades an ephemeral, signed V3
# candidate. No production release keys, published channels or approval.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
snapshot="${1:?usage: v3-dnf5-local-e2e.sh SIGNED_SNAPSHOT OLD_BINARY_RPM_DIR EPHEMERAL_PUBLIC_KEY}"
baseline_dir="${2:?baseline RPM directory required}"
rpm_key="${3:?ephemeral RPM public key required}"

for executable in dnf rpm rpmkeys createrepo_c python3; do
  command -v "$executable" >/dev/null
done
test -f "$rpm_key"
test -f "$snapshot/repository-snapshot-v1.json"

work="$(mktemp -d -t v3-dnf5-real-XXXXXXXX)"
trap 'rm -rf "$work"' EXIT

# Stage only the approved GROUP from this synthetic signed snapshot. The
# V3 composer remains explicitly offline/untrusted, not publication-ready.
python3 "$root/tools/v3_stable_composer.py" \
  --beta-snapshot "$snapshot" \
  --registry "$root/config/producers-v2.json" \
  --promotion-group ro-control \
  --output "$work/stable-candidate" > "$work/composition-output.json"

# Validate genuine signed RPM bytes + headers before generating any metadata.
key_sha="$(sha256sum "$rpm_key" | cut -d ' ' -f1)"
python3 "$root/tools/v3_rpm_preflight.py" \
  --candidate-dir "$work/stable-candidate" \
  --rpm-public-key "$rpm_key" \
  --expected-key-sha256 "$key_sha" \
  --output "$work/preflight.json"

# Derive the precise candidate group transaction matrix from V3 metadata.
# This fixture still exercises ro-control only; other groups must later get
# their own actual DNF transactions and desktop/system risk-gated tests.
python3 "$root/tools/v3_dnf_group_matrix.py" \
  --plan "$work/stable-candidate/promotion-plan-v3.json" \
  --registry "$root/config/producers-v2.json" \
  --arch x86_64 \
  --output "$work/dnf-group-matrix.json"
python3 - "$work/dnf-group-matrix.json" <<'PY'
import json,sys
item=json.load(open(sys.argv[1]))
assert item["scope"] == "offline-v3-dnf-matrix-untrusted"
assert item["promotion_group"] == "ro-control"
assert [p["nevra"] for p in item["binary_packages"]] == ["ro-control-0:9.9.9-1.fc44.x86_64"]
assert item["dnf_executed"] is False and item["publishable"] is False
PY

python3 - "$work/stable-candidate/promotion-plan-v3.json" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
assert data["promotion_group"] == "ro-control"
assert data["publishable"] is False
items=data["resulting_stable_packages"]
assert sorted(p["architecture"] for p in items) == ["src","x86_64"]
assert any(p["nevra"] == "ro-control-0:9.9.9-1.fc44.x86_64" for p in items)
PY

# Test-only repodata: cannot be mistaken for a production signed snapshot.
candidate_repo="$work/stable-candidate/rpm/x86_64"
createrepo_c --quiet "$candidate_repo"
test -f "$candidate_repo/repodata/repomd.xml"

old_packages=( "$baseline_dir"/ro-control-9.9.8-*.x86_64.rpm )
test "${#old_packages[@]}" -eq 1
test -f "${old_packages[0]}"
old_repo="$work/old-fixture"
mkdir -p "$old_repo"
cp "${old_packages[0]}" "$old_repo/"
createrepo_c --quiet "$old_repo"

repos="$work/repos"
mkdir -p "$repos"
for file in /etc/yum.repos.d/*.repo; do
  test -f "$file" || continue
  cp "$file" "$repos/"
done
# The only real signed candidate: RPM gpgcheck stays ENFORCED.
# This fixture's repodata is unsigned and intentionally never published.
cat > "$repos/v3-candidate.repo" <<EOF
[v3-candidate]
name=V3 signed RPM test-only candidate
baseurl=file://$candidate_repo
enabled=0
gpgcheck=1
repo_gpgcheck=0
gpgkey=file://$rpm_key
skip_if_unavailable=0
EOF
# Existing 9.9.8 is built LOCALLY as a disposable test-only baseline and
# is unsigned. Only THIS isolated historical-fixture repo has gpgcheck=0.
# The candidate upgrade is always fetched from v3-candidate with gpgcheck=1.
cat > "$repos/v3-baseline.repo" <<EOF
[v3-baseline]
name=V3 unsigned disposable baseline fixture
baseurl=file://$old_repo
enabled=0
gpgcheck=0
repo_gpgcheck=0
skip_if_unavailable=0
EOF
common=(
  --use-host-config
  --releasever=44
  --setopt="reposdir=$repos"
  --setopt="cachedir=$work/dnf-cache"
  --setopt="persistdir=$work/dnf-persist"
  --setopt="install_weak_deps=False"
)

# Only fedora+updates may resolve external package dependencies. Never enable
# the other Ro-ASD channel or arbitrary host third-party repositories.
dnf -y "${common[@]}" --installroot "$work/clean-root" \
  --repo=v3-candidate --repo=fedora --repo=updates \
  install ro-control-9.9.9-1.fc44.x86_64 > "$work/clean-install.log" 2>&1 || {
    tail -120 "$work/clean-install.log" >&2; exit 1;
  }
installed="$(rpm --root "$work/clean-root" -q --qf '%{VERSION}-%{RELEASE}' ro-control)"
test "$installed" = "9.9.9-1.fc44" || {
  echo "clean install: unexpected installed version '$installed'" >&2; exit 1;
}
test -x "$work/clean-root/usr/bin/ro-control"
echo "V3 DNF5 actual clean-install PASS: ro-control $installed"

# Real DNF initial INSTALL, NOT rpm --justdb/--nodeps and NOT --assumeno.
# This old fixture is unsigned only because it is generated during local CI.
dnf -y "${common[@]}" --installroot "$work/upgrade-root" \
  --repo=v3-baseline --repo=fedora --repo=updates \
  install ro-control-9.9.8-1.fc44.x86_64 > "$work/baseline-install.log" 2>&1 || {
    tail -120 "$work/baseline-install.log" >&2; exit 1;
  }
before="$(rpm --root "$work/upgrade-root" -q --qf '%{VERSION}-%{RELEASE}' ro-control)"
test "$before" = "9.9.8-1.fc44" || {
  echo "baseline: unexpected installed version '$before'" >&2; exit 1;
}
test -x "$work/upgrade-root/usr/bin/ro-control"
echo "V3 DNF5 actual baseline install PASS: ro-control $before"

# The baseline repository is DISABLED here; the candidate's RPM signature is
# checked by DNF on the real upgrade transaction.
dnf -y "${common[@]}" --installroot "$work/upgrade-root" \
  --repo=v3-candidate --repo=fedora --repo=updates \
  upgrade ro-control > "$work/upgrade.log" 2>&1 || {
    tail -120 "$work/upgrade.log" >&2; exit 1;
  }
after="$(rpm --root "$work/upgrade-root" -q --qf '%{VERSION}-%{RELEASE}' ro-control)"
test "$after" = "9.9.9-1.fc44" || {
  echo "upgrade: unexpected installed version '$after'" >&2; exit 1;
}
test -x "$work/upgrade-root/usr/bin/ro-control"
echo "V3 DNF5 actual upgrade PASS: ro-control $before -> $after"

# This test log is NOT V3 group-validation-v3 evidence, and cannot authorize a
# stable release. Multiarch, Plasma, QEMU, signed repodata and provenance gates
# must be provided by subsequent workflows.
echo "V3 TEST-ONLY SIGNED RPM + DNF5 INSTALL/UPGRADE PASSED; publishable=false"
