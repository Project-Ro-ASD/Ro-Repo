"""Fail-closed, offline V3 component test-evidence contract validator.

Validates self-consistency of *claims*. Does NOT execute tests, authenticate
workflow runs or trust artifact/log digests. A publication gate must independently
verify evidence authenticity, run provenance, signatures and test logs.
"""
import hashlib
import json
import re

from v3_promotion_planner import PlanningError, _policies

SHA = re.compile(r"^[0-9a-f]{64}$")
RUN = re.compile(r"^[1-9][0-9]*$")
SNAP = re.compile(r"^repo-f44-[0-9]{8}-[0-9]{3}$")
BASE = {"dependency-solve", "clean-install", "upgrade", "file-conflict", "rpmlint", "smoke"}
DESKTOP = {"plasma-integration", "login-session"}
SYSTEM = {"boot", "reboot", "recovery", "qemu"}
ARCH = {"x86_64", "aarch64"}

def stable_set_digest(plan):
    if not isinstance(plan, dict) or not isinstance(plan.get("resulting_stable_packages"), list):
        raise PlanningError("malformed stable plan")
    content = json.dumps(plan["resulting_stable_packages"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(content).hexdigest()

def validate_claim(plan, registry, claim):
    """Return an explicitly non-authoritative policy assessment."""
    if not isinstance(plan, dict) or plan.get("publishable") is not False:
        raise PlanningError("plan is missing or wrongly marked publishable")
    groups, _ = _policies(registry)
    group = plan.get("promotion_group")
    if group not in groups:
        raise PlanningError("unknown promotion group")
    policy = None
    for producer in registry["producers"]:
        for component in producer["components"]:
            if component["promotion_group"] == group:
                policy = component
    if policy is None:
        raise PlanningError("missing group policy")
    required = set(policy.get("required_tests", [])) | BASE
    risk = policy.get("risk_class")
    if risk not in {"normal-app", "critical-desktop", "critical-system"}:
        raise PlanningError("invalid risk class")
    if risk == "critical-desktop":
        required |= DESKTOP
    if risk == "critical-system":
        required |= SYSTEM
    if not isinstance(claim, dict):
        raise PlanningError("missing validation claim")
    expected_fields = {"schema_version", "scope", "promotion_group", "candidate_sha256",
                       "beta_snapshot_id", "stable_base_snapshot_id", "stable_set_sha256",
                       "validation_run", "workflow_identity", "tested_at", "baselines", "checks"}
    if set(claim) != expected_fields or claim["schema_version"] != 3 or claim["scope"] != "v3-group-validation-claim":
        raise PlanningError("invalid evidence contract")
    expected_set = stable_set_digest(plan)
    for key, expected in (
        ("promotion_group", group), ("candidate_sha256", plan.get("candidate_sha256")),
        ("beta_snapshot_id", plan.get("candidate_snapshot_id")),
        ("stable_base_snapshot_id", plan.get("stable_base_snapshot_id")),
        ("stable_set_sha256", expected_set),
    ):
        if claim[key] != expected:
            raise PlanningError("test evidence identity mismatch: " + key)
    if not isinstance(claim["candidate_sha256"], str) or not SHA.fullmatch(claim["candidate_sha256"]):
        raise PlanningError("bad candidate digest")
    if not isinstance(claim["beta_snapshot_id"], str) or not SNAP.fullmatch(claim["beta_snapshot_id"]):
        raise PlanningError("bad beta snapshot ID")
    if not isinstance(claim["validation_run"], str) or not RUN.fullmatch(claim["validation_run"]):
        raise PlanningError("bad validation run")
    if not isinstance(claim["workflow_identity"], str) or not claim["workflow_identity"].strip():
        raise PlanningError("missing workflow identity")
    if not isinstance(claim["tested_at"], str) or not claim["tested_at"].endswith("Z"):
        raise PlanningError("missing UTC validation timestamp")
    from datetime import datetime
    try:
        datetime.fromisoformat(claim["tested_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlanningError("bad tested_at") from exc

    source_arches = {p["architecture"] for p in plan.get("selected_group_packages", []) if p.get("architecture") in ARCH}
    # noarch RPMs are available to both binary architectures.
    if any(p.get("architecture") == "noarch" for p in plan.get("selected_group_packages", [])):
        source_arches |= ARCH
    if not source_arches:
        raise PlanningError("candidate has no binary architecture")
    baselines = claim["baselines"]
    if not isinstance(baselines, list) or len(baselines) != len(source_arches):
        raise PlanningError("missing or duplicate architecture baseline")
    baseline_arches = set()
    for item in baselines:
        if not isinstance(item, dict) or set(item) != {"architecture", "source", "package_set_sha256"}:
            raise PlanningError("malformed baseline")
        a = item["architecture"]
        if a not in source_arches or a in baseline_arches:
            raise PlanningError("unexpected baseline architecture")
        baseline_arches.add(a)
        if not isinstance(item["source"], str) or not item["source"].strip() or not isinstance(item["package_set_sha256"], str) or not SHA.fullmatch(item["package_set_sha256"]):
            raise PlanningError("missing pinned baseline source/digest")
    checks = claim["checks"]
    if not isinstance(checks, list) or not checks:
        raise PlanningError("missing tests")
    seen = set()
    allowed = BASE | DESKTOP | SYSTEM | set(policy.get("required_tests", []))
    for item in checks:
        fields = {"architecture", "name", "result", "candidate_sha256",
                  "stable_set_sha256", "runner_image_digest", "log_sha256"}
        if not isinstance(item, dict) or set(item) != fields:
            raise PlanningError("malformed test evidence")
        a, name = item["architecture"], item["name"]
        if a not in source_arches or name not in allowed or (a, name) in seen:
            raise PlanningError("unexpected or duplicate test evidence")
        seen.add((a, name))
        if item["result"] != "pass" or item["candidate_sha256"] != claim["candidate_sha256"] or item["stable_set_sha256"] != expected_set:
            raise PlanningError("failed or mismatched test evidence")
        if not isinstance(item["runner_image_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", item["runner_image_digest"]):
            raise PlanningError("unpinned test environment")
        if not isinstance(item["log_sha256"], str) or not SHA.fullmatch(item["log_sha256"]):
            raise PlanningError("missing test-log hash")
    missing = {(a, test) for a in source_arches for test in required} - seen
    if missing:
        raise PlanningError("required architecture tests missing: " + repr(sorted(missing)))
    return {
        "scope": "offline-v3-untrusted-validation-assessment",
        "promotion_group": group,
        "candidate_sha256": claim["candidate_sha256"],
        "stable_set_sha256": expected_set,
        "required_tests": sorted(required),
        "architectures": sorted(source_arches),
        "claim_consistent": True,
        "evidence_authenticity_verified": False,
        "tests_executed_by_validator": False,
        "approval_granted": False,
        "publishable": False,
    }
