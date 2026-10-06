#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 5 ]]; then
  echo "usage: $0 REPOSITORY TAG COMMIT RELEASE_ID OUTPUT" >&2
  exit 2
fi

repository="$1"
tag="$2"
commit="$3"
release_id="$4"
output="$5"

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "${value}"
}

mkdir -p "$(dirname "${output}")"
tmp="${output}.tmp.$$"
trap 'rm -f -- "${tmp}"' EXIT

timestamp="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "result": "rejected",\n'
  printf '  "timestamp": "%s",\n' "$(json_escape "${timestamp}")"
  printf '  "producer_repository": "%s",\n' "$(json_escape "${repository}")"
  printf '  "release_tag": "%s",\n' "$(json_escape "${tag}")"
  printf '  "source_commit": "%s",\n' "$(json_escape "${commit}")"
  printf '  "release_id": "%s",\n' "$(json_escape "${release_id}")"
  printf '  "workflow_run": null,\n'
  printf '  "failed_stage": "acceptance-orchestration",\n'
  printf '  "error_code": "ACCEPTANCE_ORCHESTRATION_FAILED",\n'
  printf '  "error_message": "acceptance orchestration did not complete",\n'
  printf '  "expected": null,\n'
  printf '  "received": null,\n'
  printf '  "remediation_hint": "Inspect the acceptance job logs and retry the same immutable release after correcting the consumer-side runtime or infrastructure failure."\n'
  printf '}\n'
} > "${tmp}"

mv "${tmp}" "${output}"
trap - EXIT
