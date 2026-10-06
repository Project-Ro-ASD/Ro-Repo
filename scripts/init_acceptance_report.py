#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import ro_repo


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    identity = {
        "source_repository": args.repository,
        "release_tag": args.tag,
        "source_commit": args.commit,
        "release_id": args.release_id,
        "workflow_run": None,
    }
    error = ro_repo.ContractError(
        "acceptance orchestration did not complete",
        code="ACCEPTANCE_ORCHESTRATION_FAILED",
        stage="acceptance-orchestration",
        hint="Inspect the acceptance job logs. Retry the same immutable release after correcting the consumer-side runtime or infrastructure failure.",
    )
    ro_repo.write_acceptance_report(args.output, "rejected", identity, error)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
