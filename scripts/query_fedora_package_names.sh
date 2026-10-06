#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 1 ]]; then
  echo "usage: $0 OUTPUT [PACKAGE ...]" >&2
  exit 2
fi

output="$1"
shift
mkdir -p "$(dirname "${output}")"
raw="$(mktemp "${output}.raw.XXXXXX")"
sorted="$(mktemp "${output}.sorted.XXXXXX")"
cleanup() {
  rm -f -- "${raw}" "${sorted}"
}
trap cleanup EXIT

args=(repoquery --available --qf '%{name}\n')
if [[ "$#" -gt 0 ]]; then
  args+=("$@")
fi

dnf "${args[@]}" > "${raw}"
test -s "${raw}"

python3 - "${raw}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
if not lines:
    raise SystemExit("Fedora package query returned no names")
for line in lines:
    if not line or line != line.strip() or any(ch.isspace() for ch in line):
        raise SystemExit(f"malformed Fedora package name line: {line!r}")
PY

LC_ALL=C sort -u "${raw}" > "${sorted}"
test -s "${sorted}"
mv "${sorted}" "${output}"
