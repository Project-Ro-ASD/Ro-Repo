#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
if ! command -v rpmsign >/dev/null 2>&1; then
  rpm_sign_package="$(find /tmp -maxdepth 1 -type f -name 'rpm-sign-*.rpm' -print -quit)"
  test -n "$rpm_sign_package"
  mkdir -p "$work/rpm-sign"
  (cd "$work/rpm-sign" && rpm2cpio "$rpm_sign_package" | cpio -idm >/dev/null 2>&1)
  export RO_RPMSIGN="$work/rpm-sign/usr/bin/rpmsign"
fi
top="$work/rpmbuild"
mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} "$work/incoming" "$work/rpm-tmp"
mkdir -p "$work/source/ro-control-9.9.9"
printf '#include <stdio.h>\nint main(){printf("test\\n");return 0;}\n' > "$work/source/ro-control-9.9.9/ro-control.c"
printf 'all: ro-control\nro-control: ro-control.c\n\tgcc -O2 -g $(CFLAGS) -o ro-control ro-control.c\n' > "$work/source/ro-control-9.9.9/Makefile"
tar -C "$work/source" -czf "$top/SOURCES/ro-control-9.9.9.tar.gz" ro-control-9.9.9
sed "s|@SOURCE@|$top/SOURCES/ro-control-9.9.9.tar.gz|" "$root/fixtures/ro-control-test.spec.in" > "$top/SPECS/ro-control.spec"
rpmbuild -ba --define "_topdir $top" --define "_tmppath $work/rpm-tmp" --define "dist .fc44" "$top/SPECS/ro-control.spec" >/dev/null
find "$top/RPMS" "$top/SRPMS" -type f -name '*.rpm' -exec cp {} "$work/incoming/" \;
python3 "$root/fixtures/make-test-manifest.py" "$work/incoming" "$work/incoming/component-artifact-manifest-v1.json"
mkdir -m 700 "$work/gnupg"
GNUPGHOME="$work/gnupg" gpg --batch --passphrase '' --quick-generate-key 'Ro-Repo TEST ONLY <test@invalid>' rsa2048 sign 1d >/dev/null 2>&1
key="$(GNUPGHOME="$work/gnupg" gpg --batch --with-colons --list-secret-keys | awk -F: '$1=="sec" {print $5; exit}')"
"$root/tools/ro-repo" verify-component --manifest "$work/incoming/component-artifact-manifest-v1.json" --artifacts "$work/incoming"
"$root/tools/ro-repo" accept-package --manifest "$work/incoming/component-artifact-manifest-v1.json" --artifacts "$work/incoming" --accepted "$work/accepted"
"$root/tools/ro-repo" sign-package --input "$work/accepted" --output "$work/signed" --gnupghome "$work/gnupg" --key-id "$key"
"$root/tools/ro-repo" build-snapshot --signed "$work/signed" --manifests "$work/accepted" --output "$work/out" --snapshot-id repo-f44-20260908-001 --gnupghome "$work/gnupg" --metadata-key-id "$key"
"$root/tools/ro-repo" verify-snapshot --snapshot "$work/out/snapshots/fedora/44/repo-f44-20260908-001" --gnupghome "$work/gnupg"
"$root/tools/ro-repo" publish-local --output "$work/out" --snapshot-id repo-f44-20260908-001 --channel beta --gnupghome "$work/gnupg"
"$root/tools/ro-repo" publish-local --output "$work/out" --snapshot-id repo-f44-20260908-001 --channel beta --gnupghome "$work/gnupg"
"$root/tools/ro-repo" rollback-publication --output "$work/out" --channel beta
"$root/tools/ro-repo" generate-catalog --snapshot "$work/out/snapshots/fedora/44/repo-f44-20260908-001" --editorial "$root/store/editorial.json" --output "$work/catalog.json" --gnupghome "$work/gnupg"
test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["snapshotId"])' "$work/catalog.json")" = repo-f44-20260908-001
test -f "$work/out/publication/rpm/fedora/44/beta/x86_64/repodata/repomd.xml.asc"
cp -a "$work/accepted" "$work/mutated-manifests"
python3 - "$work/mutated-manifests" <<'PY'
import json, pathlib, sys
path=next(pathlib.Path(sys.argv[1]).rglob('component-artifact-manifest-v1.json'))
data=json.loads(path.read_text()); data['artifacts'][0]['producer_artifact_sha256']='c'*64
path.write_text(json.dumps(data))
PY
if "$root/tools/ro-repo" build-snapshot --signed "$work/signed" --manifests "$work/mutated-manifests" --output "$work/out" --snapshot-id repo-f44-20260908-002 --gnupghome "$work/gnupg" --metadata-key-id "$key"; then
  echo "same NEVRA with different producer hash was accepted" >&2
  exit 1
fi

echo "Running full-set-validation..."
"$root/tests/full-set-validation.sh" "$work/out/snapshots/fedora/44/repo-f44-20260908-001" x86_64
