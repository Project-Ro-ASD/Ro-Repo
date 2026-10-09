import copy
import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_promotion_planner import PlanningError, plan

D = "a" * 64
E = "b" * 64
F = "c" * 64
REGISTRY = {"producers": [
    {"components": [{"component": "ro-assist", "promotion_group": "ro-assist",
                      "package_names": ["ro-assist"], "architectures": ["x86_64", "aarch64"]}]},
    {"components": [{"component": "dolphin", "promotion_group": "ro-kde-dolphin",
                      "package_names": ["dolphin", "dolphin-libs", "dolphin-devel"],
                      "architectures": ["x86_64"], "require_complete_architecture_set": True}]},
]}


def rpm(name, version, arch, manifest=D, signed=E, source_name=None):
    src_name = source_name or name
    filename = f"{name}-{version}-1.fc44.{arch}.rpm"
    return {"nevra": f"{name}-0:{version}-1.fc44.{arch}", "filename": filename,
            "architecture": arch, "producer_manifest_digest": manifest,
            "producer_artifact_sha256": F, "published_signed_artifact_sha256": signed}


def snapshot(identifier, packages):
    return {"snapshot_id": identifier, "fedora_release": 44, "packages": packages}


def assist(version="0.2.5"):
    return [rpm("ro-assist", version, arch) for arch in ["src", "x86_64", "aarch64"]]


def dolphin():
    return [rpm(n, "26.08.1") for n in ["dolphin", "dolphin-libs", "dolphin-devel"]] + [rpm("dolphin", "26.08.1", "src")]


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.beta = snapshot("repo-f44-20261009-001", assist() + dolphin())

    def test_assist_bootstrap_excludes_unapproved_dolphin(self):
        out = plan(self.beta, None, REGISTRY, "ro-assist")
        self.assertFalse(out["publishable"])
        self.assertEqual(out["unchanged_stable_package_count"], 0)
        self.assertEqual({x["nevra"].split("-0:", 1)[0] for x in out["resulting_stable_packages"]}, {"ro-assist"})

    def test_dolphin_requires_all_subpackages(self):
        out = plan(self.beta, None, REGISTRY, "ro-kde-dolphin")
        self.assertEqual(len(out["selected_group_packages"]), 4)
        bad = copy.deepcopy(self.beta)
        bad["packages"] = [x for x in bad["packages"] if not x["nevra"].startswith("dolphin-devel-")]
        with self.assertRaises(PlanningError):
            plan(bad, None, REGISTRY, "ro-kde-dolphin")

    def test_unrelated_stable_packages_are_preserved(self):
        stable = snapshot("repo-f44-20261001-001", assist("0.2.4"))
        out = plan(self.beta, stable, REGISTRY, "ro-kde-dolphin")
        self.assertEqual(len(out["resulting_stable_packages"]), 7)
        self.assertEqual(out["unchanged_stable_package_count"], 3)
        self.assertTrue(any("ro-assist-0:0.2.4" in x["nevra"] for x in out["resulting_stable_packages"]))

    def test_same_nevra_substitution_rejected(self):
        old = assist()
        old[1]["published_signed_artifact_sha256"] = F
        with self.assertRaisesRegex(PlanningError, "same NEVRA"):
            plan(self.beta, snapshot("old", old), REGISTRY, "ro-assist")

    def test_duplicate_nevra_and_bad_digests_rejected(self):
        broken = copy.deepcopy(self.beta)
        broken["packages"].append(copy.deepcopy(broken["packages"][0]))
        with self.assertRaises(PlanningError):
            plan(broken, None, REGISTRY, "ro-assist")
        broken = copy.deepcopy(self.beta)
        broken["packages"][0]["producer_manifest_digest"] = "invalid"
        with self.assertRaises(PlanningError):
            plan(broken, None, REGISTRY, "ro-assist")

    def test_provenance_and_architecture_rejected(self):
        broken = copy.deepcopy(self.beta)
        broken["packages"][1]["producer_manifest_digest"] = E
        with self.assertRaises(PlanningError):
            plan(broken, None, REGISTRY, "ro-assist")
        broken = copy.deepcopy(self.beta)
        broken["packages"][1]["architecture"] = "noarch"
        with self.assertRaises(PlanningError):
            plan(broken, None, REGISTRY, "ro-assist")

    def test_does_not_mutate_or_depend_on_package_order(self):
        source = copy.deepcopy(self.beta)
        forward = plan(source, None, REGISTRY, "ro-assist")
        self.beta["packages"].reverse()
        backward = plan(self.beta, None, REGISTRY, "ro-assist")
        self.assertEqual(forward["candidate_sha256"], backward["candidate_sha256"])
        self.assertEqual(source["packages"][0]["architecture"], "src")

    def test_unknown_group_fails(self):
        with self.assertRaises(PlanningError):
            plan(self.beta, None, REGISTRY, "ro-store")

if __name__ == "__main__":
    unittest.main()
