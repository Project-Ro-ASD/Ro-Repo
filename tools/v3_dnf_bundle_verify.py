"""Independently recheck the bytes and identities of untrusted V3 DNF receipts.

This is a LOCAL INTEGRITY CHECK only. A claimant who controls the receipt and
all logs can still rewrite them together. Authentic GitHub Actions provenance
and approved signing roles must be verified in a *separate* trust gate.
"""
import argparse
import hashlib
import json
import pathlib
import re

from v3_group_validation import stable_set_digest
from v3_promotion_planner import PlanningError

SHA = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RUN = re.compile(r"^[1-9][0-9]*$")
GROUP = re.compile(r"^[a-z0-9][a-z0-9-]*$")
FILES = {
    "dnf-receipt.json", "promotion-plan-v3.json", "dnf-group-matrix.json",
    "transaction-inputs.json", "preflight.json", "baseline-checkpoint.json",
    "clean-install.log", "baseline-install.log", "upgrade.log",
}
LOGS = ("clean-install.log", "baseline-install.log", "upgrade.log")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _safe_file(group_dir, name):
    path = group_dir / name
    if path.is_symlink() or not path.is_file() or not path.stat().st_size:
        raise PlanningError("missing, empty or symlinked evidence: " + name)
    return path.read_bytes()


def _parse_json(group_dir, name):
    try:
        return json.loads(_safe_file(group_dir, name))
    except (UnicodeError, ValueError) as exc:
        raise PlanningError("invalid evidence JSON: " + name) from exc


def _assert_digest(value, label):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise PlanningError("invalid SHA-256: " + label)


def verify_group(group_dir, *, repository, run_id, commit, workflow_ref):
    """Check receipt against its independent file bytes and *caller* CI context.

    Expected context must come from a separately trusted caller. Even then,
    this only establishes internal consistency, NOT GitHub run authenticity.
    """
    group_dir = pathlib.Path(group_dir)
    if group_dir.is_symlink() or not group_dir.is_dir() or not GROUP.fullmatch(group_dir.name):
        raise PlanningError("unsafe/invalid evidence group directory")
    children = list(group_dir.iterdir())
    if any(p.is_symlink() or not p.is_file() for p in children) or {p.name for p in children} != FILES:
        raise PlanningError("evidence files missing, extra, or unsafe")
    receipt = _parse_json(group_dir, "dnf-receipt.json")
    plan = _parse_json(group_dir, "promotion-plan-v3.json")
    matrix = _parse_json(group_dir, "dnf-group-matrix.json")
    tx = _parse_json(group_dir, "transaction-inputs.json")
    preflight = _parse_json(group_dir, "preflight.json")
    baseline = _parse_json(group_dir, "baseline-checkpoint.json")
    if not isinstance(receipt, dict) or receipt.get("scope") != "v3-dnf-test-receipt-untrusted" or receipt.get("publishable") is not False:
        raise PlanningError("invalid/non-test-only receipt")
    if receipt.get("schema_version") != 1 or receipt.get("promotion_group") != group_dir.name:
        raise PlanningError("receipt group mismatch")
    if not isinstance(plan, dict) or plan.get("publishable") is not False:
        raise PlanningError("invalid plan")
    if not isinstance(matrix, dict) or matrix.get("publishable") is not False or matrix.get("dnf_executed") is not False or matrix.get("scope") != "offline-v3-dnf-matrix-untrusted":
        raise PlanningError("invalid DNF matrix")
    if not isinstance(tx, dict) or tx.get("publishable") is not False or tx.get("scope") != "offline-v3-transaction-inputs":
        raise PlanningError("invalid DNF transaction inputs")
    for label, val in {
        "plan": plan.get("promotion_group"),
        "matrix": matrix.get("promotion_group"),
        "transaction": tx.get("group"),
        "preflight": preflight.get("promotion_group") if isinstance(preflight, dict) else None,
        "baseline": baseline.get("group") if isinstance(baseline, dict) else None,
    }.items():
        if val != group_dir.name:
            raise PlanningError("wrong promotion group in " + label)
    sha = plan.get("candidate_sha256")
    _assert_digest(sha, "candidate")
    for label, val in {
        "receipt": receipt.get("candidate_sha256"),
        "matrix": matrix.get("candidate_sha256"),
        "preflight": preflight.get("candidate_sha256"),
    }.items():
        if val != sha:
            raise PlanningError("candidate SHA-256 mismatch: " + label)
    if stable_set_digest(plan) != receipt.get("stable_set_sha256"):
        raise PlanningError("resulting stable set hash mismatch")
    if receipt.get("beta_snapshot_id") != plan.get("candidate_snapshot_id") or receipt.get("stable_base_snapshot_id") != plan.get("stable_base_snapshot_id"):
        raise PlanningError("snapshot identities do not match")
    arch = tx.get("target_arch")
    if arch not in {"x86_64", "aarch64"} or arch != receipt.get("architecture") or arch != matrix.get("target_arch") or arch != baseline.get("target_arch"):
        raise PlanningError("architecture mismatch")
    if not isinstance(preflight, dict) or preflight.get("publishable") is not False or preflight.get("local_header_checks_passed") is not True or preflight.get("local_rpm_signature_checks_passed") is not True:
        raise PlanningError("RPM preflight does not claim real checks")
    if _sha(_canonical(preflight)) != receipt.get("preflight_sha256"):
        raise PlanningError("preflight digest mismatch")
    if _sha(_canonical(tx)) != receipt.get("transaction_inputs_sha256") or receipt.get("transaction_inputs_sha256") != baseline.get("transaction_inputs_sha256"):
        raise PlanningError("transaction inputs hash mismatch")
    if baseline.get("scope") != "v3-baseline-rpmdb-checkpoint-test-only" or baseline.get("publishable") is not False:
        raise PlanningError("invalid baseline checkpoint")
    names = tx.get("names")
    if not isinstance(names, list) or not names or len(set(names)) != len(names) or not all(isinstance(n, str) and n for n in names):
        raise PlanningError("invalid transaction package names")
    candidate = tx.get("expected_candidate_evr")
    previous = tx.get("expected_baseline_evr")
    if not isinstance(candidate, dict) or not isinstance(previous, dict) or set(candidate) != set(names) or set(previous) != set(names):
        raise PlanningError("incomplete DNF RPMDB targets")
    if receipt.get("rpmdb") != {
        "baseline_before_upgrade": previous, "clean_install": candidate, "after_upgrade": candidate,
    } or baseline.get("installed_evrs") != previous:
        raise PlanningError("recorded RPMDB EVR mismatch")
    targets = matrix.get("binary_packages")
    if not isinstance(targets, list) or len(targets) != len(names) or {p.get("name") for p in targets if isinstance(p, dict)} != set(names):
        raise PlanningError("unexpected DNF package group targets")
    if tx.get("candidate_targets") != [p["nevra"] for p in targets]:
        raise PlanningError("candidate targets do not match DNF matrix")
    hashes = receipt.get("log_sha256")
    if not isinstance(hashes, dict) or set(hashes) != set(LOGS):
        raise PlanningError("missing or unexpected DNF logs")
    for name in LOGS:
        _assert_digest(hashes[name], "DNF log " + name)
        if _sha(_safe_file(group_dir, name)) != hashes[name]:
            raise PlanningError("DNF log was changed: " + name)
    claims = receipt.get("ci_claims_unverified")
    if not isinstance(claims, dict) or any(claims.get(k) != val for k, val in {
        "github_repository": repository, "github_run_id": run_id,
        "github_sha": commit, "github_workflow_ref": workflow_ref,
        "runner_image_digest": None,
    }.items()):
        raise PlanningError("CI claims do not match expected caller context")
    if (receipt.get("ci_identity_authenticated") is not False
            or receipt.get("test_logs_authenticated") is not False
            or receipt.get("checks_observed") != ["clean-install", "upgrade"]
            or receipt.get("file_conflict_test_executed") is not False
            or receipt.get("rpmlint_test_executed") is not False
            or receipt.get("plasma_test_executed") is not False
            or receipt.get("qemu_test_executed") is not False):
        raise PlanningError("receipt attempts to overstate test coverage")
    return {"group": group_dir.name, "candidate_sha256": sha,
            "receipt_sha256": _sha(_safe_file(group_dir, "dnf-receipt.json")),
            "local_integrity_passed": True, "ci_authenticity_verified": False,
            "publishable": False}


def verify_bundle(root, groups, *, repository, run_id, commit, workflow_ref):
    root = pathlib.Path(root)
    if root.is_symlink() or not root.is_dir():
        raise PlanningError("missing/unsafe evidence bundle")
    if not isinstance(groups, list) or not groups or len(set(groups)) != len(groups) or any(not GROUP.fullmatch(g) for g in groups):
        raise PlanningError("invalid expected groups")
    if not isinstance(run_id, str) or not RUN.fullmatch(run_id) or not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise PlanningError("missing/invalid CI run or SHA")
    if not isinstance(repository, str) or not repository.strip() or not isinstance(workflow_ref, str) or not workflow_ref.strip():
        raise PlanningError("missing CI context")
    contents = list(root.iterdir())
    if any(p.is_symlink() or not p.is_dir() for p in contents) or {p.name for p in contents} != set(groups):
        raise PlanningError("evidence group set mismatch")
    results = [verify_group(root/g, repository=repository, run_id=run_id, commit=commit, workflow_ref=workflow_ref) for g in sorted(groups)]
    return {"scope": "v3-local-evidence-integrity-only", "groups": results,
            "ci_authenticity_verified": False, "publishable": False}


def main():
    p = argparse.ArgumentParser(description="Recheck untrusted DNF artifact files; not publication approval")
    p.add_argument("--root", required=True)
    p.add_argument("--expected-groups", nargs="+", required=True)
    p.add_argument("--expected-repository", required=True)
    p.add_argument("--expected-run-id", required=True)
    p.add_argument("--expected-commit", required=True)
    p.add_argument("--expected-workflow-ref", required=True)
    args = p.parse_args()
    out = verify_bundle(args.root, args.expected_groups, repository=args.expected_repository,
                        run_id=args.expected_run_id, commit=args.expected_commit,
                        workflow_ref=args.expected_workflow_ref)
    print(json.dumps(out, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
