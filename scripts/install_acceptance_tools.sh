#!/usr/bin/env bash
set -euo pipefail

dnf -y install \
  gh \
  python3 \
  python3-yaml \
  python3-jsonschema \
  rpm \
  dnf-plugins-core

for command_name in gh python3 rpm dnf bash sort awk base64 sha256sum; do
  command -v "${command_name}" >/dev/null
done

python3 - <<'PY'
import jsonschema
import yaml
PY

dnf repoquery --help >/dev/null
