import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_group_validation import validate_claim, stable_set_digest
from v3_promotion_planner import PlanningError

H = "a" * 64
B = "b" * 64
ARCH = ("x86_64", "aarch64")
BASE = {"dependency-solve", "clean-install", "upgrade", "file-conflict", "rpmlint", "smoke"}
REGISTRY = {"producers": [{"components": [
    {"component": "ro-assist", "promotion_group": "ro-assist", "package_names": ["ro-assist"],
     "architectures": list(ARCH), "risk_class": "normal-app", "required_tests": sorted(BASE)},
    {"component": "dolphin", "promotion_group": "ro-kde-dolphin", "package_names": ["dolphin"],
     "architectures": ["x86_64"], "risk_class": "critical-desktop",
     "required_tests": sorted(BASE | {"plasma-integration", "login-session"})},
    {"component": "installer", "promotion_group": "ro-installer", "package_names": ["ro-installer"],
     "architectures": ["x86_64"], "risk_class": "critical-system", "required_tests": sorted(BASE)}
]}]}

def mkplan(group="ro-assist", arches=ARCH):
    return {"publishable": False, "promotion_group": group,
            "candidate_sha256": H, "candidate_snapshot_id": "repo-f44-20261009-001",
            "stable_base_snapshot_id": None,
            "selected_group_packages": [{"architecture": a} for a in arches],
            "resulting_stable_packages": [{"nevra": "rpm-0:1-1." + a, "architecture": a} for a in arches]}

def mkclaim(plan, tests):
    digest = stable_set_digest(plan)
    arches = [p["architecture"] for p in plan["selected_group_packages"]]
    return {"schema_version": 3, "scope": "v3-group-validation-claim",
            "promotion_group": plan["promotion_group"], "candidate_sha256": H,
            "beta_snapshot_id": plan["candidate_snapshot_id"], "stable_base_snapshot_id": None,
            "stable_set_sha256": digest, "validation_run": "1000",
            "workflow_identity": "Project-Ro-ASD/Ro-Repo/.github/workflows/v3-validate.yml@abc",
            "tested_at": "2026-10-09T18:00:00Z",
            "baselines": [{"architecture": a, "source": "Fedora 44 snapshot sha256", "package_set_sha256": B} for a in arches],
            "checks": [{"architecture": a, "name": t, "result": "pass",
                        "candidate_sha256": H, "stable_set_sha256": digest,
                        "runner_image_digest": "sha256:" + B, "log_sha256": B}
                       for a in arches for t in sorted(tests)]}

class ValidationTests(unittest.TestCase):
    def test_normal_group_passes_claim_check_without_granting_publish(self):
        p = mkplan()
        result = validate_claim(p, REGISTRY, mkclaim(p, BASE))
        self.assertTrue(result["claim_consistent"])
        self.assertFalse(result["publishable"])
        self.assertFalse(result["evidence_authenticity_verified"])
    def test_dolphin_needs_plasma_session(self):
        p = mkplan("ro-kde-dolphin", ("x86_64",))
        with self.assertRaisesRegex(PlanningError, "required architecture tests missing"):
            validate_claim(p, REGISTRY, mkclaim(p, BASE))
        validate_claim(p, REGISTRY, mkclaim(p, BASE | {"plasma-integration", "login-session"}))
    def test_system_needs_real_boot_tests(self):
        p = mkplan("ro-installer", ("x86_64",))
        with self.assertRaisesRegex(PlanningError, "required architecture tests missing"):
            validate_claim(p, REGISTRY, mkclaim(p, BASE))
        validate_claim(p, REGISTRY, mkclaim(p, BASE | {"boot", "reboot", "recovery", "qemu"}))
    def test_wrong_group_rejected(self):
        p = mkplan()
        c = mkclaim(p, BASE)
        c["promotion_group"] = "ro-kde-dolphin"
        with self.assertRaises(PlanningError):
            validate_claim(p, REGISTRY, c)
    def test_wrong_stable_base_and_content_rejected(self):
        p = mkplan()
        c = mkclaim(p, BASE)
        c["stable_base_snapshot_id"] = "repo-f44-20261001-001"
        with self.assertRaises(PlanningError):
            validate_claim(p, REGISTRY, c)
        c = mkclaim(p, BASE)
        p["resulting_stable_packages"].append({"nevra": "different", "architecture": "x86_64"})
        with self.assertRaises(PlanningError):
            validate_claim(p, REGISTRY, c)
    def test_missing_architecture_evidence_rejected(self):
        p = mkplan()
        c = mkclaim(p, BASE)
        c["checks"] = [t for t in c["checks"] if t["architecture"] == "x86_64"]
        with self.assertRaises(PlanningError):
            validate_claim(p, REGISTRY, c)
    def test_replayed_candidate_digest_rejected(self):
        p = mkplan()
        c = mkclaim(p, BASE)
        c["candidate_sha256"] = B
        with self.assertRaises(PlanningError):
            validate_claim(p, REGISTRY, c)
    def test_duplicate_failure_and_unpinned_env_rejected(self):
        p = mkplan()
        for change in ("dup", "fail", "env"):
            c = mkclaim(p, BASE)
            if change == "dup":
                c["checks"].append(copy.deepcopy(c["checks"][0]))
            if change == "fail":
                c["checks"][0]["result"] = "fail"
            if change == "env":
                c["checks"][0]["runner_image_digest"] = "fedora:44"
            with self.assertRaises(PlanningError):
                validate_claim(p, REGISTRY, c)
    def test_non_publishable_plan_required(self):
        p = mkplan()
        p["publishable"] = True
        with self.assertRaises(PlanningError):
            validate_claim(p, REGISTRY, mkclaim(p, BASE))

if __name__ == "__main__":
    unittest.main()
