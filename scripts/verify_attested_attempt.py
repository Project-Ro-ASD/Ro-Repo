#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import ro_repo


def validate_attempt(data, *, producer, tag, commit, workflow_path, run_id, attempt):
    expected_path = workflow_path
    prefix = producer + "/"
    if expected_path.startswith(prefix):
        expected_path = expected_path[len(prefix):]

    checks = (
        ("id", run_id),
        ("run_attempt", attempt),
        ("status", "completed"),
        ("conclusion", "success"),
        ("event", "push"),
        ("head_sha", commit),
        ("head_branch", tag),
        ("path", expected_path),
    )
    for field, expected in checks:
        received = data.get(field)
        if received != expected:
            raise ro_repo.ContractError(
                f"workflow attempt {field} mismatch",
                code="PROVENANCE_MISMATCH",
                stage="provenance",
                expected=expected,
                received=received,
                hint="Accept only the exact successful workflow attempt bound by the verified attestation.",
            )

    for field in ("repository", "head_repository"):
        obj = data.get(field)
        received = obj.get("full_name") if isinstance(obj, dict) else None
        if received != producer:
            raise ro_repo.ContractError(
                f"workflow attempt {field} mismatch",
                code="PROVENANCE_MISMATCH",
                stage="provenance",
                expected=producer,
                received=received,
                hint="Accept only an attempt from the exact allowlisted producer repository.",
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--producer", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--invocation", type=pathlib.Path, required=True)
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    identity = ro_repo.normalize_acceptance_identity(manifest)

    try:
        invocation = json.loads(args.invocation.read_text(encoding="utf-8"))
        run_id = ro_repo._normalize_numeric_identity(invocation.get("run_id"))
        attempt = ro_repo._normalize_numeric_identity(invocation.get("attempt"))
        if run_id is None or attempt is None:
            raise ro_repo.ContractError(
                "invalid attested workflow invocation identity",
                code="PROVENANCE_MISMATCH",
                stage="provenance",
                expected="positive numeric run_id and attempt",
                received=invocation,
            )
        raw = subprocess.check_output(
            [
                "gh",
                "api",
                f"repos/{args.producer}/actions/runs/{run_id}/attempts/{attempt}",
            ],
            text=True,
        )
        data = json.loads(raw)
        validate_attempt(
            data,
            producer=args.producer,
            tag=args.tag,
            commit=args.commit,
            workflow_path=args.workflow,
            run_id=run_id,
            attempt=attempt,
        )
    except ro_repo.ContractError as error:
        ro_repo.write_acceptance_report(args.report, "rejected", identity, error)
        raise
    except Exception as error:
        internal = ro_repo.ContractError(
            f"workflow attempt verification failed: {type(error).__name__}",
            code="ACCEPTANCE_INFRASTRUCTURE_ERROR",
            stage="provenance",
            hint="Inspect GitHub API/tooling connectivity and retry the same immutable release after the consumer-side failure is corrected.",
        )
        ro_repo.write_acceptance_report(args.report, "rejected", identity, internal)
        raise

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
