#!/usr/bin/env bash
# Native Fedora 44; use only candidate Stable plus official Fedora repositories.
set -euo pipefail
candidate="$(realpath "$1")"
baseline="${2:-}"
work="$(mktemp -d)"
trap 'GNUPGHOME="$work/gnupg" gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
arch="$(rpm --eval '%{_arch}')"
mkdir -p "$work/repos"
mkdir -m 700 "$work/gnupg"
# Both production roles share one primary key. Merge both public subkeys before
# DNF imports them, otherwise its first primary-key match can omit the other role.
GNUPGHOME="$work/gnupg" gpg --batch --import "$candidate/keys/RPM-GPG-KEY-ro-asd" "$candidate/keys/REPODATA-GPG-KEY-ro-asd"
GNUPGHOME="$work/gnupg" gpg --batch --armor --export > "$work/combined-public.asc"
cp /etc/yum.repos.d/fedora.repo /etc/yum.repos.d/fedora-updates.repo "$work/repos/"
cat > "$work/repos/selected.repo" <<EOF
[selected-stable]
name=Selected Stable candidate
baseurl=file://$candidate/rpm/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file://$work/combined-public.asc
EOF
mapfile -t packages < <(python3 - "$candidate" "$arch" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]+'/repository-snapshot-v1.json'))
for p in m['packages']:
    if p['architecture'] in (sys.argv[2], 'noarch'): print(p['nevra'])
PY
)
# Keep candidate package names out of official repos so equal NEVRAs cannot
# accidentally validate Fedora bytes instead of the selected signed RPMs.
owned_names="$(python3 - "$candidate" "$baseline" <<'PYCODE'
import json,pathlib,sys
names=set()
for root in sys.argv[1:]:
    if root:
        for p in json.load(open(pathlib.Path(root)/'repository-snapshot-v1.json'))['packages']:
            if p['architecture'] not in ('src','nosrc'):
                names.add(p['nevra'].rsplit('-',2)[0])
print(','.join(sorted(names)))
PYCODE
)"
# Empty architecture is still a valid repository; its metadata must load.
common=(--releasever=44 --use-host-config --setopt="reposdir=$work/repos" --setopt=install_weak_deps=False --setopt=keepcache=False --disable-repo='*' --enable-repo=fedora --enable-repo=updates --enable-repo=selected-stable)
common+=(--setopt="fedora.excludepkgs=$owned_names" --setopt="updates.excludepkgs=$owned_names")
verify_nevras() {
  local phase="$1" installroot="$2" package name actual
  shift 2
  for package in "$@"; do
    name="${package%-*}"
    name="${name%-*}"
    actual="$(rpm --root "$installroot" -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' "$name" || true)"
    if [[ "$actual" != "$package" ]]; then
      printf 'NEVRA mismatch (%s): expected %s; installed %s\n' "$phase" "$package" "$actual" >&2
      return 1
    fi
    printf 'VERIFIED %s: %s\n' "$phase" "$package"
  done
}
dnf5 -y --installroot="$work/clean" "${common[@]}" makecache
if ((${#packages[@]})); then
  dnf5 -y --installroot="$work/clean" "${common[@]}" install "${packages[@]}"
  verify_nevras clean "$work/clean" "${packages[@]}"
fi
if [[ -n "$baseline" && -d "$baseline" ]]; then
  # Install the entire previous Stable using the same independent dependency sources.
  sed -i "s|baseurl=file://.*|baseurl=file://$(realpath "$baseline")/rpm/\$basearch|" "$work/repos/selected.repo"
  mapfile -t old < <(python3 - "$baseline" "$arch" <<'PY'
import json,sys
for p in json.load(open(sys.argv[1]+'/repository-snapshot-v1.json'))['packages']:
    if p['architecture'] in (sys.argv[2], 'noarch'): print(p['nevra'])
PY
)
  if ((${#old[@]})); then
    dnf5 -y --installroot="$work/upgrade" "${common[@]}" install "${old[@]}"
    verify_nevras baseline "$work/upgrade" "${old[@]}"
  fi
  sed -i "s|baseurl=file://.*|baseurl=file://$candidate/rpm/\$basearch|" "$work/repos/selected.repo"
  dnf5 -y --installroot="$work/upgrade" "${common[@]}" clean all
  # DNF5 upgrade does not install newly introduced groups. Classify targets
  # against the installed baseline before performing either transaction.
  installed=()
  added=()
  for package in "${packages[@]}"; do
    name="${package%-*}"
    name="${name%-*}"
    if rpm --root "$work/upgrade" -q "$name" >/dev/null 2>&1; then
      installed+=("$package")
    else
      added+=("$package")
    fi
  done
  if ((${#installed[@]})); then
    dnf5 -y --installroot="$work/upgrade" "${common[@]}" upgrade --no-allow-downgrade "${installed[@]}"
    # An explicit older NEVRA may be ignored by upgrade. Reject it here before
    # install can accept that NEVRA as a request to downgrade an existing name.
    verify_nevras upgraded "$work/upgrade" "${installed[@]}"
  fi
  if ((${#added[@]})); then
    dnf5 -y --installroot="$work/upgrade" "${common[@]}" install --no-allow-downgrade "${added[@]}"
  fi
  verify_nevras transition "$work/upgrade" "${packages[@]}"
fi
