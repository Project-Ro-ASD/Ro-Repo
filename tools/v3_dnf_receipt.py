"""Record checkable *test-only* receipts from real Fedora 44 DNF transactions.

Does not authenticate GitHub Actions, pin a runner image, attest logs or grant
promotion authority. Only the caller actually executes DNF; this code checks
RPMDB state and hashes the logs/inputs that were produced.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

from v3_promotion_planner import PlanningError
from v3_group_validation import stable_set_digest

DIGEST = re.compile(r"^[0-9a-f]{64}$")
NAMES = re.compile(r"^[A-Za-z0-9_+.-]+$")
LOG_FILES = ("clean-install.log", "baseline-install.log", "upgrade.log")
INPUT_FILES = ("promotion-plan-v3.json", "dnf-group-matrix.json",
               "transaction-inputs.json", "preflight.json", "baseline-checkpoint.json")


def _load(path):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file():
        raise PlanningError("receipt input missing or symlinked")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise PlanningError("receipt JSON invalid") from exc


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _rpmdb(root, names):
    root = pathlib.Path(root)
    if root.is_symlink() or not root.is_dir():
        raise PlanningError("missing or unsafe transaction installroot")
    observed = {}
    for name in names:
        if not isinstance(name, str) or not NAMES.fullmatch(name):
            raise PlanningError("unsafe package name in transaction")
        try:
            result = subprocess.run(
                ["rpm", "--root", str(root), "-q", "--qf",
                 "%{EPOCHNUM}:%{VERSION}-%{RELEASE}", name],
                capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PlanningError("RPMDB query failed") from exc
        if result.returncode != 0 or not result.stdout.strip():
            raise PlanningError("RPMDB package absent: " + name)
        observed[name] = result.stdout.strip()
    return observed


def _validate_tx(tx):
    if not isinstance(tx, dict) or tx.get("scope") != "offline-v3-transaction-inputs" or tx.get("publishable") is not False:
        raise PlanningError("invalid transaction inputs")
    names = tx.get("names")
    if not isinstance(names, list) or not names or len(names) != len(set(names)) or not all(isinstance(x, str) and NAMES.fullmatch(x) for x in names):
        raise PlanningError("invalid transaction package names")
    for key in ("expected_candidate_evr", "expected_baseline_evr"):
        expected = tx.get(key)
        if not isinstance(expected, dict) or set(expected) != set(names) or not all(isinstance(x, str) and x for x in expected.values()):
            raise PlanningError("invalid expected package EVRs")
    if tx.get("target_arch") not in ("x86_64", "aarch64") or not isinstance(tx.get("group"), str) or not tx["group"]:
        raise PlanningError("invalid transaction identity")
    return names


def _assert_installed(root, names, expected):
    actual = _rpmdb(root, names)
    if actual != expected:
        raise PlanningError("RPMDB EVR mismatch: expected " + repr(expected) + ", got " + repr(actual))
    return actual


def capture_baseline(tx, root):
    """Capture an RPMDB checkpoint *before* the runner performs its upgrade."""
    names = _validate_tx(tx)
    return {
        "scope": "v3-baseline-rpmdb-checkpoint-test-only",
        "group": tx["group"],
        "target_arch": tx["target_arch"],
        "installed_evrs": _assert_installed(root, names, tx["expected_baseline_evr"]),
        "transaction_inputs_sha256": _sha(_canonical(tx)),
        "publishable": False,
    }


def make_receipt(plan, matrix, tx, preflight, baseline, clean_root, upgraded_root, logs_dir):
    """Verify installed RPMDB states and bind the exact input + log bytes."""
    names = _validate_tx(tx)
    if (not isinstance(plan, dict) or plan.get("publishable") is not False
            or not isinstance(matrix, dict) or matrix.get("scope") != "offline-v3-dnf-matrix-untrusted"
            or matrix.get("publishable") is not False or matrix.get("dnf_executed") is not False
            or matrix.get("promotion_group") != tx["group"]
            or matrix.get("target_arch") != tx["target_arch"]):
        raise PlanningError("mismatched DNF plan and matrix")
    if (plan.get("promotion_group") != tx["group"]
            or plan.get("candidate_sha256") != matrix.get("candidate_sha256")
            or not isinstance(plan.get("candidate_sha256"), str)
            or not DIGEST.fullmatch(plan["candidate_sha256"])):
        raise PlanningError("wrong candidate identity")
    from v3_dnf_group_matrix import matrix as expected_matrix
    # Confirm the targets have not changed since derivation. The real registry
    # is not trusted here; the publication workflow revalidates policy later.
    matrix_names = matrix.get("binary_packages")
    if not isinstance(matrix_names, list) or {x.get("name") for x in matrix_names if isinstance(x, dict)} != set(names) or len(matrix_names) != len(names):
        raise PlanningError("matrix group membership mismatch")
    if (tx.get("candidate_targets") != [x["nevra"] for x in matrix_names]
            or not isinstance(preflight, dict)
            or preflight.get("publishable") is not False
            or preflight.get("local_header_checks_passed") is not True
            or preflight.get("local_rpm_signature_checks_passed") is not True
            or preflight.get("promotion_group") != tx["group"]
            or preflight.get("candidate_sha256") != plan["candidate_sha256"]):
        raise PlanningError("unsigned or mismatched RPM preflight/targets")
    if (not isinstance(baseline, dict)
            or set(baseline) != {"scope", "group", "target_arch", "installed_evrs", "transaction_inputs_sha256", "publishable"}
            or baseline["scope"] != "v3-baseline-rpmdb-checkpoint-test-only"
            or baseline["publishable"] is not False
            or baseline["group"] != tx["group"]
            or baseline["target_arch"] != tx["target_arch"]
            or baseline["installed_evrs"] != tx["expected_baseline_evr"]
            or baseline["transaction_inputs_sha256"] != _sha(_canonical(tx))):
        raise PlanningError("stale or forged baseline checkpoint identity")
    actual_clean = _assert_installed(clean_root, names, tx["expected_candidate_evr"])
    actual_upgraded = _assert_installed(upgraded_root, names, tx["expected_candidate_evr"])
    logs_dir = pathlib.Path(logs_dir)
    if logs_dir.is_symlink() or not logs_dir.is_dir():
        raise PlanningError("missing or unsafe transaction logs")
    logs = {}
    for filename in LOG_FILES:
        path = logs_dir / filename
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise PlanningError("missing or empty DNF log: " + filename)
        logs[filename] = _sha(path.read_bytes())
    return {
        "schema_version": 1, "scope": "v3-dnf-test-receipt-untrusted",
        "promotion_group": tx["group"], "architecture": tx["target_arch"],
        "candidate_sha256": plan["candidate_sha256"],
        "stable_set_sha256": stable_set_digest(plan),
        "beta_snapshot_id": plan.get("candidate_snapshot_id"),
        "stable_base_snapshot_id": plan.get("stable_base_snapshot_id"),
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "ci_claims_unverified": {
            "github_repository": os.getenv("GITHUB_REPOSITORY"),
            "github_run_id": os.getenv("GITHUB_RUN_ID"),
            "github_sha": os.getenv("GITHUB_SHA"),
            "github_workflow_ref": os.getenv("GITHUB_WORKFLOW_REF"),
            "runner_image_digest": None,
        },
        "rpmdb": {
            "baseline_before_upgrade": baseline["installed_evrs"],
            "clean_install": actual_clean,
            "after_upgrade": actual_upgraded,
        },
        "log_sha256": logs,
        "preflight_sha256": _sha(_canonical(preflight)),
        "transaction_inputs_sha256": _sha(_canonical(tx)),
        "checks_observed": ["clean-install", "upgrade"],
        "dependency_solve_observed_as_part_of_dnf": True,
        "file_conflict_test_executed": False,
        "rpmlint_test_executed": False,
        "plasma_test_executed": False,
        "qemu_test_executed": False,
        "ci_identity_authenticated": False,
        "test_logs_authenticated": False,
        "publishable": False,
    }


def _save_new(path, result):
    path = pathlib.Path(path)
    if path.exists() or path.is_symlink():
        raise PlanningError("receipt output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("wb", prefix=".v3-evidence-", dir=path.parent, delete=False) as f:
            tmp = pathlib.Path(f.name)
            f.write(_canonical(result) + b"\n")
        os.rename(tmp, path)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Create untrusted but verifiable DNF test receipt")
    parser.add_argument("--phase", choices=("baseline", "final"), required=True)
    parser.add_argument("--transaction-inputs", required=True)
    parser.add_argument("--root")
    parser.add_argument("--plan")
    parser.add_argument("--matrix")
    parser.add_argument("--preflight")
    parser.add_argument("--baseline-checkpoint")
    parser.add_argument("--clean-root")
    parser.add_argument("--upgrade-root")
    parser.add_argument("--logs-dir")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    tx = _load(args.transaction_inputs)
    if args.phase == "baseline":
        if not args.root:
            parser.error("--root required for baseline")
        result = capture_baseline(tx, args.root)
    else:
        needed = ("plan", "matrix", "preflight", "baseline_checkpoint", "clean_root", "upgrade_root", "logs_dir")
        if any(not getattr(args, key) for key in needed):
            parser.error("all final receipt inputs are required")
        result = make_receipt(_load(args.plan), _load(args.matrix), tx,
                              _load(args.preflight), _load(args.baseline_checkpoint),
                              args.clean_root, args.upgrade_root, args.logs_dir)
    _save_new(args.output, result)
    print(json.dumps({"scope": result["scope"], "publishable": False, "output": args.output}))


if __name__ == "__main__":
    main()
