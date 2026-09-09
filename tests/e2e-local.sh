#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
evidence_out="${RO_REPO_E2E_EVIDENCE:-}"
if ! command -v rpmsign >/dev/null 2>&1; then
  rpm_sign_package="$(find /tmp -maxdepth 1 -type f -name 'rpm-sign-*.rpm' -print -quit)"
  test -n "$rpm_sign_package"
  mkdir -p "$work/rpm-sign"
  (cd "$work/rpm-sign" && rpm2cpio "$rpm_sign_package" | cpio -idm >/dev/null 2>&1)
  export RO_RPMSIGN="$work/rpm-sign/usr/bin/rpmsign"
fi
expect_failure() {
  local expected="$1"
  shift
  local output
  if output="$("$@" 2>&1)"; then
    echo "expected command to fail but it succeeded: $*" >&2
    exit 1
  fi
  if ! grep -Eq "$expected" <<<"$output"; then
    echo "expected failure matching '$expected' from: $*" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}
top="$work/rpmbuild"
mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} "$work/incoming" "$work/rpm-tmp"
mkdir -p "$work/source/ro-control-9.9.9"
printf '#include <stdio.h>\nint main(){printf("test\\n");return 0;}\n' > "$work/source/ro-control-9.9.9/ro-control.c"
printf 'all: ro-control\nro-control: ro-control.c\n\tgcc -O2 -g $(CFLAGS) -o ro-control ro-control.c\n' > "$work/source/ro-control-9.9.9/Makefile"
tar -C "$work/source" -czf "$top/SOURCES/ro-control-9.9.9.tar.gz" ro-control-9.9.9
sed "s|@SOURCE@|$top/SOURCES/ro-control-9.9.9.tar.gz|" "$root/fixtures/ro-control-test.spec.in" > "$top/SPECS/ro-control.spec"
rpmbuild -ba --define "_topdir $top" --define "_tmppath $work/rpm-tmp" --define "dist .fc44" "$top/SPECS/ro-control.spec" > "$work/rpmbuild.log" 2>&1 || {
  tail -200 "$work/rpmbuild.log" >&2
  exit 1
}
mkdir -p "$work/source/ro-control-9.9.8" "$work/baseline"
cp "$work/source/ro-control-9.9.9/ro-control.c" "$work/source/ro-control-9.9.9/Makefile" "$work/source/ro-control-9.9.8/"
tar -C "$work/source" -czf "$top/SOURCES/ro-control-9.9.8.tar.gz" ro-control-9.9.8
sed -e "s|@SOURCE@|$top/SOURCES/ro-control-9.9.8.tar.gz|" -e "s|Version: 9.9.9|Version: 9.9.8|" "$root/fixtures/ro-control-test.spec.in" > "$top/SPECS/ro-control-old.spec"
rpmbuild -bb --define "_topdir $top" --define "_tmppath $work/rpm-tmp" --define "dist .fc44" "$top/SPECS/ro-control-old.spec" > "$work/rpmbuild-old.log" 2>&1 || {
  tail -200 "$work/rpmbuild-old.log" >&2
  exit 1
}
find "$top/RPMS" -type f -name 'ro-control-9.9.8-*.rpm' -exec cp {} "$work/baseline/" \;
find "$top/RPMS" -type f -name 'ro-control-9.9.9-*.rpm' -exec cp {} "$work/incoming/" \;
find "$top/SRPMS" -type f -name 'ro-control-9.9.9-*.rpm' -exec cp {} "$work/incoming/" \;
python3 "$root/fixtures/make-test-manifest.py" "$work/incoming" "$work/incoming/component-artifact-manifest-v1.json"
(
  cd "$work/incoming"
  sha256sum *.rpm > SHA256SUMS
)
printf 'bash\ncoreutils\n' > "$work/fedora-44-package-names.txt"
mkdir -m 700 "$work/gnupg"
GNUPGHOME="$work/gnupg" gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'Ro-Repo TEST ONLY <test@invalid>' rsa2048 cert 1d >/dev/null 2>&1
primary_fpr="$(GNUPGHOME="$work/gnupg" gpg --batch --with-colons --list-keys | awk -F: '/^fpr/ {print $10}' | head -n1)"
GNUPGHOME="$work/gnupg" gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$primary_fpr" rsa2048 sign 1d >/dev/null 2>&1
GNUPGHOME="$work/gnupg" gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$primary_fpr" rsa2048 sign 1d >/dev/null 2>&1

fprs=($(GNUPGHOME="$work/gnupg" gpg --batch --with-colons --list-keys | awk -F: '/^fpr/ {print $10}'))
rpm_key="${fprs[1]}"
meta_key="${fprs[2]}"

"$root/tools/ro-repo" verify-component --manifest "$work/incoming/component-artifact-manifest-v1.json" --artifacts "$work/incoming" --fedora-names "$work/fedora-44-package-names.txt"
"$root/tools/ro-repo" accept-package --manifest "$work/incoming/component-artifact-manifest-v1.json" --artifacts "$work/incoming" --accepted "$work/accepted" --fedora-names "$work/fedora-44-package-names.txt" --test-only-allow-unattested
"$root/tools/ro-repo" sign-package --input "$work/accepted" --output "$work/signed" --gnupghome "$work/gnupg" --key-id "$rpm_key"
"$root/tools/ro-repo" sign-package --input "$work/accepted" --output "$work/wrong-rpm-role-signed" --gnupghome "$work/gnupg" --key-id "$meta_key"
expect_failure "unsigned or invalid signature on RPM" "$root/tools/ro-repo" build-snapshot --signed "$work/wrong-rpm-role-signed" --manifests "$work/accepted" --output "$work/wrong-rpm-role-out" --snapshot-id repo-f44-20260908-010 --gnupghome "$work/gnupg" --metadata-key-id "$meta_key" --rpm-key-id "$rpm_key" --test-only-allow-unattested-acceptance
"$root/tools/ro-repo" build-snapshot --signed "$work/signed" --manifests "$work/accepted" --output "$work/out" --snapshot-id repo-f44-20260908-001 --gnupghome "$work/gnupg" --metadata-key-id "$meta_key" --rpm-key-id "$rpm_key" --test-only-allow-unattested-acceptance

# Verify fingerprints are different
python3 - "$work/out/snapshots/fedora/44/repo-f44-20260908-001/repository-snapshot-v1.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
if data["rpm_signing_fingerprint"] == data["metadata_signing_fingerprint"]:
    raise SystemExit("Error: rpm and metadata fingerprints are the same!")
PY
python3 - "$work/out/snapshots/fedora/44/repo-f44-20260908-001/keys/RPM-GPG-KEY-ro-asd-TEST-ONLY" "$work/out/snapshots/fedora/44/repo-f44-20260908-001/keys/REPODATA-GPG-KEY-ro-asd-TEST-ONLY" "$primary_fpr" "$rpm_key" "$meta_key" "$work" <<'PY'
import os, pathlib, shutil, subprocess, sys

rpm_key_path, meta_key_path, primary_fpr, rpm_key, meta_key, work = sys.argv[1:]

def imported_fingerprints(key_path, name):
    home = pathlib.Path(work) / f"{name}-import-home"
    home.mkdir(mode=0o700)
    env = os.environ.copy()
    env["GNUPGHOME"] = str(home)
    subprocess.check_call(["gpg", "--batch", "--import", key_path], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    output = subprocess.check_output(["gpg", "--batch", "--with-colons", "--list-keys"], env=env, text=True)
    return [line.split(":")[9] for line in output.splitlines() if line.startswith("fpr:")]

rpm_export = imported_fingerprints(rpm_key_path, "rpm-role")
meta_export = imported_fingerprints(meta_key_path, "metadata-role")
print("RPM role export fingerprints: " + ",".join(rpm_export))
print("Metadata role export fingerprints: " + ",".join(meta_export))
if rpm_export != [primary_fpr, rpm_key]:
    raise SystemExit(f"RPM role export is not isolated: {rpm_export}")
if meta_export != [primary_fpr, meta_key]:
    raise SystemExit(f"Metadata role export is not isolated: {meta_export}")
PY
"$root/tools/ro-repo" verify-snapshot --snapshot "$work/out/snapshots/fedora/44/repo-f44-20260908-001" --gnupghome "$work/gnupg"
mkdir -p "$work/wrong-metadata-role-root"
cp -a "$work/out/snapshots/fedora/44/repo-f44-20260908-001" "$work/wrong-metadata-role-root/repo-f44-20260908-001"
GNUPGHOME="$work/gnupg" gpg --batch --yes --armor --local-user "$rpm_key!" --detach-sign --output "$work/wrong-metadata-role-root/repo-f44-20260908-001/repository-snapshot-v1.json.asc" "$work/wrong-metadata-role-root/repo-f44-20260908-001/repository-snapshot-v1.json"
expect_failure "GPG signature verification error: wrong key used" "$root/tools/ro-repo" verify-snapshot --snapshot "$work/wrong-metadata-role-root/repo-f44-20260908-001" --gnupghome "$work/gnupg"
"$root/tools/ro-repo" publish-local --output "$work/out" --snapshot-id repo-f44-20260908-001 --channel beta --gnupghome "$work/gnupg"
"$root/tools/ro-repo" publish-local --output "$work/out" --snapshot-id repo-f44-20260908-001 --channel beta --gnupghome "$work/gnupg"
"$root/tools/ro-repo" rollback-publication --output "$work/out" --channel beta
"$root/tools/ro-repo" generate-catalog --snapshot "$work/out/snapshots/fedora/44/repo-f44-20260908-001" --editorial "$root/store/editorial.json" --output "$work/catalog.json" --gnupghome "$work/gnupg"
test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["snapshotId"])' "$work/catalog.json")" = repo-f44-20260908-001
test -f "$work/out/publication/rpm/fedora/44/beta/x86_64/repodata/repomd.xml.asc"
test ! -e "$work/out/snapshots/fedora/44/repo-f44-20260908-001/rpmdb"
test ! -e "$work/out/snapshots/fedora/44/repo-f44-20260908-001/test-public-key.asc"
cp -a "$work/accepted" "$work/mutated-manifests"
python3 - "$work/mutated-manifests" <<'PY'
import json, pathlib, sys
path=next(pathlib.Path(sys.argv[1]).rglob('component-artifact-manifest-v1.json'))
data=json.loads(path.read_text()); data['artifacts'][0]['producer_artifact_sha256']='c'*64
path.write_text(json.dumps(data))
PY
expect_failure "acceptance evidence manifest digest mismatch" "$root/tools/ro-repo" build-snapshot --signed "$work/signed" --manifests "$work/mutated-manifests" --output "$work/out" --snapshot-id repo-f44-20260908-002 --gnupghome "$work/gnupg" --metadata-key-id "$meta_key" --rpm-key-id "$rpm_key" --test-only-allow-unattested-acceptance
cp -a "$work/accepted" "$work/mutated-evidence"
python3 - "$work/mutated-evidence" <<'PY'
import json, pathlib, sys
path=next(pathlib.Path(sys.argv[1]).rglob('acceptance-evidence-v1.json'))
data=json.loads(path.read_text()); data['source_commit']='b'*40
path.write_text(json.dumps(data))
PY
expect_failure "acceptance evidence identity mismatch" "$root/tools/ro-repo" build-snapshot --signed "$work/signed" --manifests "$work/mutated-evidence" --output "$work/out" --snapshot-id repo-f44-20260908-011 --gnupghome "$work/gnupg" --metadata-key-id "$meta_key" --rpm-key-id "$rpm_key" --test-only-allow-unattested-acceptance

printf '#include <stdio.h>\nint main(){printf("changed\\n");return 0;}\n' > "$work/source/ro-control-9.9.9/ro-control.c"
tar -C "$work/source" -czf "$top/SOURCES/ro-control-9.9.9.tar.gz" ro-control-9.9.9
rpmbuild -ba --define "_topdir $top" --define "_tmppath $work/rpm-tmp" --define "dist .fc44" "$top/SPECS/ro-control.spec" > "$work/rpmbuild-reuse.log" 2>&1 || {
  tail -200 "$work/rpmbuild-reuse.log" >&2
  exit 1
}
mkdir -p "$work/reused-incoming"
find "$top/RPMS" -type f -name 'ro-control-9.9.9-*.rpm' -exec cp {} "$work/reused-incoming/" \;
find "$top/SRPMS" -type f -name 'ro-control-9.9.9-*.rpm' -exec cp {} "$work/reused-incoming/" \;
python3 "$root/fixtures/make-test-manifest.py" "$work/reused-incoming" "$work/reused-incoming/component-artifact-manifest-v1.json"
(
  cd "$work/reused-incoming"
  sha256sum *.rpm > SHA256SUMS
)
"$root/tools/ro-repo" accept-package --manifest "$work/reused-incoming/component-artifact-manifest-v1.json" --artifacts "$work/reused-incoming" --accepted "$work/reused-accepted" --fedora-names "$work/fedora-44-package-names.txt" --test-only-allow-unattested
"$root/tools/ro-repo" sign-package --input "$work/reused-accepted" --output "$work/reused-signed" --gnupghome "$work/gnupg" --key-id "$rpm_key"
expect_failure "historical NEVRA reuse with different content" "$root/tools/ro-repo" build-snapshot --signed "$work/reused-signed" --manifests "$work/reused-accepted" --output "$work/out" --snapshot-id repo-f44-20260908-003 --gnupghome "$work/gnupg" --metadata-key-id "$meta_key" --rpm-key-id "$rpm_key" --test-only-allow-unattested-acceptance

echo "Running full-set-validation..."
"$root/tests/full-set-validation.sh" "$work/out/snapshots/fedora/44/repo-f44-20260908-001" x86_64 "$work/baseline"

if [ -n "$evidence_out" ]; then
  python3 - "$work/out/snapshots/fedora/44/repo-f44-20260908-001" "$evidence_out" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import sys
import os

snapshot = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
manifest = snapshot / "repository-snapshot-v1.json"
digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
out.parent.mkdir(parents=True, exist_ok=True)
tmp_out = out.with_name(out.name + ".tmp")
tmp_out.write_text(json.dumps({
    "schema_version": 1,
    "scope": "phase1-local-fixture",
    "snapshot_id": snapshot.name,
    "result": "pass",
    "tests": [
        {"name": "dependency-solve", "result": "pass"},
        {"name": "clean-install", "result": "pass"},
        {"name": "upgrade", "result": "pass"},
        {"name": "file-conflict", "result": "pass"},
        {"name": "rpmlint", "result": "pass"},
        {"name": "smoke", "result": "pass"}
    ],
    "reference": str(manifest.relative_to(out.parent.parent)),
    "digest": digest,
    "timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(tmp_out, out)
PY
fi
