"""Manifest-driven exact released-artifact acceptance, no producer writes."""
import pathlib
import platform

from v3_backend_trust import require_attestation
from v3_full_set_dnf import validate
from v3_integration import tree_inventory
from v3_policy_profile import sha, require_complete
from v3_promotion_planner import PlanningError


def execute(spec, *, snapshot, baseline, beta, plan, registry, upstream, input_attestation,
            rpm_key, rpm_key_sha256, metadata_key, metadata_key_sha256, output, now):
    """Run real DNF5 only after immutable acquisition and upstream verification.

    The output authenticates neither applications nor runner identity. A trusted
    executor must independently attest these logs and combine actual smoke/GUI
    evidence before v3_backend_evidence accepts production approval inputs.
    """
    from ro_repo import validate_schema
    validate_schema(spec, "real-acceptance-v3")
    policy = require_complete(plan, registry)
    if spec["promotion_group"] != policy["promotion_group"] or spec["architecture"] != platform.machine():
        raise PlanningError("real acceptance requires exact group/native architecture")
    if not upstream:
        raise PlanningError("real application acceptance requires independently pinned Fedora upstream")
    expected = {"spec_sha256": sha(spec), "plan_sha256": sha(plan), "registry_sha256": sha(registry),
                "snapshot_tree_sha256": sha(tree_inventory(snapshot)), "beta_tree_sha256": sha(tree_inventory(beta)),
                "baseline_tree_sha256": None if baseline is None else sha(tree_inventory(baseline)),
                "rpm_key_sha256": rpm_key_sha256, "metadata_key_sha256": metadata_key_sha256,
                "upstream_manifest_sha256": {repo.manifest["repo_id"]: sha(repo.manifest) for repo in upstream}}
    payload = require_attestation(input_attestation, "acceptance-inputs")
    if payload.get("inputs") != expected or not payload["issued_at"] <= now < payload["expires_at"]:
        raise PlanningError("released immutable inputs lack authenticated acquisition")
    for name in ("snapshot_tree_sha256", "beta_tree_sha256", "baseline_tree_sha256", "plan_sha256", "registry_sha256"):
        if spec[name] != expected[name]:
            raise PlanningError("released artifact substitution: " + name)
    observation = validate(snapshot, baseline, beta, plan, spec["architecture"], output,
                           rpm_key=rpm_key, rpm_key_sha256=rpm_key_sha256, metadata_key=metadata_key,
                           metadata_key_sha256=metadata_key_sha256, config_paths=spec["config_paths"], upstream=upstream)
    return {"scope": "v3-real-artifact-transaction-observation", "publishable": False,
            "input_attestation_sha256": input_attestation.sha256, "dnf_receipt_sha256": sha(observation),
            "transactions": "PASS", "application_smoke": "UNVERIFIED", "protected_runner": "UNVERIFIED",
            "production_activation": "BLOCKED"}
