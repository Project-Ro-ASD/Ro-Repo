#!/usr/bin/env bash
# Disposable Fedora 44 two-subpackage signed DNF transaction fixture.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="${1:?work directory required}"
top="${2:?rpmbuild tree required}"
gnupg="${3:?test signing GNUPGHOME required}"
sign_key="${4:?test RPM signing subkey required}"
pubkey="${5:?test public key required}"
mkdir -p "$work/atomic-sources" "$work/atomic-baseline" "$work/atomic-unsigned" "$top/SPECS"
cat > "$top/SPECS/ro-atomic-fixture.spec" <<'SPEC'
# The fixture installs text payloads only. RPM 6 otherwise generates an
# empty debugsourcefiles.list and Fedora 44 rpmbuild fails the test build.
%global debug_package %{nil}
Name: ro-atomic-fixture
Version: 2.0
Release: 1%{?dist}
Summary: Disposable multi-package test fixture
License: MIT
BuildArch: x86_64
Source0: atomic-fixture-%{version}.tar.gz
Requires: ro-atomic-fixture-libs = %{version}-%{release}
%description
Disposable integration-only package.
%package libs
Summary: Disposable companion package
%description libs
Disposable integration-only companion.
%prep
%setup -q -n atomic-fixture-%{version}
%build
:
%install
install -Dm0644 payload %{buildroot}%{_datadir}/ro-atomic-fixture/main
install -Dm0644 library %{buildroot}%{_datadir}/ro-atomic-fixture/library
%files
%{_datadir}/ro-atomic-fixture/main
%files libs
%{_datadir}/ro-atomic-fixture/library
SPEC
for version in 1.0 2.0; do
  mkdir -p "$work/atomic-sources/atomic-fixture-$version"
  printf '%s\n' "main-$version" > "$work/atomic-sources/atomic-fixture-$version/payload"
  printf '%s\n' "libs-$version" > "$work/atomic-sources/atomic-fixture-$version/library"
  tar -C "$work/atomic-sources" -czf "$top/SOURCES/atomic-fixture-$version.tar.gz" "atomic-fixture-$version"
  sed "s/^Version: 2.0$/Version: $version/" "$top/SPECS/ro-atomic-fixture.spec" > "$top/SPECS/ro-atomic-$version.spec"
  rpmbuild -ba --define "_topdir $top" --define "_tmppath $work/rpm-tmp" --define "dist .fc44" "$top/SPECS/ro-atomic-$version.spec" > "$work/atomic-build-$version.log" 2>&1 || {
    tail -120 "$work/atomic-build-$version.log" >&2; exit 1;
  }
done
cp "$top/RPMS/x86_64"/ro-atomic-fixture*1.0-1.fc44.x86_64.rpm "$work/atomic-baseline/"
cp "$top/RPMS/x86_64"/ro-atomic-fixture*2.0-1.fc44.x86_64.rpm "$work/atomic-unsigned/"
cp "$top/SRPMS/ro-atomic-fixture-2.0-1.fc44.src.rpm" "$work/atomic-unsigned/"
"$root/tools/ro-repo" sign-package --input "$work/atomic-unsigned" \
  --output "$work/atomic-signed" --gnupghome "$gnupg" --key-id "$sign_key"
python3 - "$work/atomic-signed" "$work/atomic-snapshot" <<'PY'
import hashlib,json,pathlib,shutil,subprocess,sys
signed=pathlib.Path(sys.argv[1])
snapshot=pathlib.Path(sys.argv[2])/"repo-f44-20261009-099"
snapshot.mkdir(parents=True)
entries=[]
producer="e"*64
for package in sorted(signed.glob("*.rpm")):
    # RPM 6 may report build architecture even in source RPM headers.
    # Require both the source package marker AND filename extension, then
    # normalize the manifest's source architecture to src.
    fields=subprocess.check_output(["rpm","-qp","--qf","%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCEPACKAGE}\n",str(package)],text=True).strip().split("\t")
    if len(fields)!=6:
        raise SystemExit(f"malformed RPM header: {package.name}: {fields!r}")
    name,epoch,ver,rel,header_arch,source_flag=fields
    is_source=package.name.endswith(".src.rpm")
    if is_source != (source_flag=="1"):
        raise SystemExit(f"RPM source marker/filename mismatch: {package.name}: {source_flag!r}")
    if is_source:
        arch="src"
        directory="source"
    else:
        if source_flag!="0" or header_arch!="x86_64":
            raise SystemExit(f"unexpected binary RPM architecture: {package.name}: {header_arch!r}")
        arch=header_arch
        directory=arch
    if package.name != f"{name}-{ver}-{rel}.{arch}.rpm":
        raise SystemExit(f"RPM filename/NEVRA mismatch: {package.name}")
    print(f"V3 synthetic fixture: {package.name} (source={is_source}, arch={arch}, header_arch={header_arch})")
    target=snapshot/"rpm"/directory/package.name
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(package,target)
    digest=hashlib.sha256(target.read_bytes()).hexdigest()
    entries.append({"nevra":f"{name}-{epoch}:{ver}-{rel}.{arch}",
                    "architecture":arch,"filename":package.name,
                    "producer_artifact_sha256":digest,"producer_manifest_digest":producer,
                    "published_signed_artifact_sha256":digest})
assert len(entries)==3,entries
(snapshot/"repository-snapshot-v1.json").write_text(json.dumps({
    "snapshot_id":snapshot.name,"fedora_release":44,"packages":entries},indent=2)+"\n")
PY
cat > "$work/atomic-registry.json" <<'JSON'
{"producers":[{"components":[{
  "component":"ro-atomic-fixture",
  "promotion_group":"ro-atomic-fixture",
  "package_names":["ro-atomic-fixture","ro-atomic-fixture-libs"],
  "architectures":["x86_64"],"risk_class":"normal-app",
  "require_complete_architecture_set":true,
  "required_tests":["dependency-solve","clean-install","upgrade","file-conflict","rpmlint","smoke"]
}]}]}
JSON
bash "$root/tests/v3-dnf5-local-e2e.sh" \
  "$work/atomic-snapshot/repo-f44-20261009-099" \
  "$work/atomic-baseline" "$pubkey" \
  ro-atomic-fixture "$work/atomic-registry.json"
echo "V3 signed multi-subpackage real DNF5 E2E passed (no promotion authority)"
