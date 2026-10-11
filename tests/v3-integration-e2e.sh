#!/usr/bin/env bash
# Disposable Fedora 44 fixture acceptance only. No real producer applications,
# production keys, GitHub workflows, Pages channels or Ro-Store are written.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$root/tests/v3-integration-fedora-e2e.py" "${1:?new immutable evidence output directory required}"
