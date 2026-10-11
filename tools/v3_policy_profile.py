"""Versioned V3 policy derived exclusively from the producer registry.

Risk floors are the V3 contract, not a second editable producer allowlist.
V2 acceptance policy is intentionally unaffected.
"""
import hashlib
import json

from v3_promotion_planner import PlanningError, _policies, _parse

VERSION = "ro-repo-v3-policy-1"
BASE = {"dependency-solve", "clean-install", "upgrade", "file-conflict", "rpmlint", "smoke"}
DESKTOP = {"plasma-integration", "login-session"}
SYSTEM = {"boot", "reboot", "recovery", "qemu"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def profile(registry, group, *, expected=None):
    groups, _ = _policies(registry)
    if registry.get("fedora_release", 44) != 44 or group not in groups:
        raise PlanningError("unsupported registry or promotion group")
    producer, policy = next((p, c) for p in registry["producers"]
                            for c in p["components"] if c["promotion_group"] == group)
    risk = policy.get("risk_class")
    if risk not in {"normal-app", "critical-desktop", "critical-system"}:
        raise PlanningError("invalid risk class")
    tests = policy.get("required_tests")
    if (not isinstance(tests, list) or not tests or
            any(not isinstance(t, str) or not t.strip() for t in tests) or
            len(set(tests)) != len(tests)):
        raise PlanningError("invalid canonical required-test profile")
    required = set(tests) | BASE
    required |= DESKTOP if risk == "critical-desktop" else SYSTEM if risk == "critical-system" else set()
    result = {
        "version": VERSION, "registry_sha256": sha(registry), "promotion_group": group,
        "repository": producer.get("repository"), "component": policy["component"],
        "trusted_signer_workflow": policy.get("trusted_signer_workflow"),
        "fedora_release": 44, "architectures": sorted(policy["architectures"]),
        "package_names": sorted(policy["package_names"]), "risk_class": risk,
        "minimum_beta_days": 14 if risk == "critical-system" else 7,
        "required_tests": sorted(required), "srpm_required": True,
    }
    if expected is not None and expected != result:
        raise PlanningError("policy divergence from canonical producer registry")
    return result


def require_complete(plan, registry):
    """Require registered architecture closure for selected and retained groups."""
    group = plan["promotion_group"]
    p = profile(registry, group)
    _, owners = _policies(registry)
    packages = plan["resulting_stable_packages"]
    groups = {owners[_parse(rpm)[0]] for rpm in packages}
    for selected_group in sorted(groups | {group}):
        policy = profile(registry, selected_group)
        members = [rpm for rpm in packages if owners[_parse(rpm)[0]] == selected_group]
        for arch in policy["architectures"]:
            names = {_parse(rpm)[0] for rpm in members if rpm["architecture"] == arch}
            if names != set(policy["package_names"]):
                raise PlanningError("incomplete registered architecture set: " + selected_group + "/" + arch)
    return p
