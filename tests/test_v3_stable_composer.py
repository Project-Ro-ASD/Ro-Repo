import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_promotion_planner import PlanningError
from v3_stable_composer import compose

REGISTRY = {"producers": [
    {"components": [{"component": "ro-assist", "promotion_group": "ro-assist",
                      "package_names": ["ro-assist"], "architectures": ["x86_64", "aarch64"]}]},
    {"components": [{"component": "dolphin", "promotion_group": "ro-kde-dolphin",
                      "package_names": ["dolphin", "dolphin-libs", "dolphin-devel"],
                      "architectures": ["x86_64"], "require_complete_architecture_set": True}]},
    {"components": [{"component": "branding", "promotion_group": "ro-asd-branding",
                      "package_names": ["ro-asd-branding"], "architectures": ["noarch"]}]},
]}


def package(name, version, arch, *, manifest=None):
    content = f"{name}/{version}/{arch}".encode()
    release = "1.fc44"
    return {"nevra": f"{name}-0:{version}-{release}.{arch}",
            "architecture": arch,
            "filename": f"{name}-{version}-{release}.{arch}.rpm",
            "producer_manifest_digest": manifest or hashlib.sha256(name.encode()).hexdigest(),
            "producer_artifact_sha256": hashlib.sha256(content).hexdigest(),
            "published_signed_artifact_sha256": hashlib.sha256(content).hexdigest()}


def group_assist(version):
    return [package("ro-assist", version, arch) for arch in ("src", "x86_64", "aarch64")]


def group_dolphin():
    return [package(name, "26.08.1", "x86_64", manifest="b" * 64)
            for name in ("dolphin", "dolphin-libs", "dolphin-devel")] + [
                package("dolphin", "26.08.1", "src", manifest="b" * 64)]


def group_noarch():
    return [package("ro-asd-branding", "1.0", arch) for arch in ("src", "noarch")]


def write_snapshot(parent, name, packages):
    root = parent / name
    root.mkdir()
    (root / "repository-snapshot-v1.json").write_text(json.dumps(
        {"snapshot_id": name, "fedora_release": 44, "packages": packages}))
    for p in packages:
        arch = p["architecture"]
        folders = ("source",) if arch in ("src", "nosrc") else (
            ("x86_64", "aarch64") if arch == "noarch" else (arch,))
        for folder in folders:
            path = root / "rpm" / folder / p["filename"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"{p['nevra'].split('-0:')[0]}/{p['nevra'].split(':')[1].split('-')[0]}/{arch}".encode())
    return root


class ComposerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.beta = write_snapshot(self.root, "repo-f44-20261009-001",
                                   group_assist("0.2.5") + group_dolphin() + group_noarch())
        self.out = self.root / "out"

    def tearDown(self):
        self.temporary.cleanup()

    def test_bootstrap_selects_only_ro_assist(self):
        manifest = compose(self.beta, None, REGISTRY, "ro-assist", self.out)
        self.assertFalse(manifest["publishable"])
        self.assertFalse(manifest["repository_metadata_signed"])
        self.assertEqual(manifest["rpm_file_count"], 3)
        self.assertFalse(list(self.out.rglob("dolphin*.rpm")))
        self.assertEqual(len(list(self.out.rglob("ro-assist*.rpm"))), 3)
        self.assertFalse(list(self.out.rglob("repomd.xml")))
        self.assertTrue((self.out / "promotion-plan-v3.json").exists())

    def test_preserve_previous_stable_and_add_dolphin(self):
        prior = write_snapshot(self.root, "repo-f44-20261001-001", group_assist("0.2.4"))
        result = compose(self.beta, prior, REGISTRY, "ro-kde-dolphin", self.out)
        self.assertEqual(result["rpm_file_count"], 7)
        self.assertTrue((self.out / "rpm/x86_64/ro-assist-0.2.4-1.fc44.x86_64.rpm").exists())
        self.assertTrue((self.out / "rpm/x86_64/dolphin-devel-26.08.1-1.fc44.x86_64.rpm").exists())
        self.assertFalse(list(self.out.rglob("ro-asd-branding*.rpm")))
        self.assertTrue((prior / "rpm/x86_64/ro-assist-0.2.4-1.fc44.x86_64.rpm").exists())

    def test_noarch_replicated_into_both_architectures(self):
        m = compose(self.beta, None, REGISTRY, "ro-asd-branding", self.out)
        self.assertEqual(m["rpm_file_count"], 3)
        assert (self.out / "rpm/x86_64/ro-asd-branding-1.0-1.fc44.noarch.rpm").read_bytes() == (
            self.out / "rpm/aarch64/ro-asd-branding-1.0-1.fc44.noarch.rpm").read_bytes()

    def test_corrupt_candidate_fails_without_output(self):
        path = self.beta / "rpm/x86_64/ro-assist-0.2.5-1.fc44.x86_64.rpm"
        path.write_bytes(b"tampered")
        with self.assertRaisesRegex(PlanningError, "digest mismatch"):
            compose(self.beta, None, REGISTRY, "ro-assist", self.out)
        self.assertFalse(self.out.exists())

    def test_missing_previous_stable_file_fails_atomically(self):
        prior = write_snapshot(self.root, "repo-f44-20261001-001", group_assist("0.2.4"))
        (prior / "rpm/aarch64/ro-assist-0.2.4-1.fc44.aarch64.rpm").unlink()
        with self.assertRaises(PlanningError):
            compose(self.beta, prior, REGISTRY, "ro-kde-dolphin", self.out)
        self.assertFalse(self.out.exists())

    def test_incomplete_dolphin_group_fails(self):
        manifest_path = self.beta / "repository-snapshot-v1.json"
        data = json.loads(manifest_path.read_text())
        data["packages"] = [p for p in data["packages"] if not p["nevra"].startswith("dolphin-devel-")]
        manifest_path.write_text(json.dumps(data))
        with self.assertRaises(PlanningError):
            compose(self.beta, None, REGISTRY, "ro-kde-dolphin", self.out)
        self.assertFalse(self.out.exists())

    def test_symlinked_input_rpm_is_rejected(self):
        target = self.beta / "rpm/x86_64/ro-assist-0.2.5-1.fc44.x86_64.rpm"
        target.unlink()
        target.symlink_to(self.beta / "rpm/aarch64/ro-assist-0.2.5-1.fc44.aarch64.rpm")
        with self.assertRaisesRegex(PlanningError, "unsafe source"):
            compose(self.beta, None, REGISTRY, "ro-assist", self.out)
        self.assertFalse(self.out.exists())

    def test_output_preexists_or_inside_input_is_rejected(self):
        self.out.mkdir()
        with self.assertRaisesRegex(PlanningError, "already exists"):
            compose(self.beta, None, REGISTRY, "ro-assist", self.out)
        with self.assertRaisesRegex(PlanningError, "inside an input snapshot"):
            compose(self.beta, None, REGISTRY, "ro-assist", self.beta / "nested-output")

    def test_deterministic_composition_manifest(self):
        first = compose(self.beta, None, REGISTRY, "ro-assist", self.out)
        content = (self.out / "composition-v3.json").read_bytes()
        second = compose(self.beta, None, REGISTRY, "ro-assist", self.root / "another-output")
        self.assertEqual(first, second)
        self.assertEqual(content, (self.root / "another-output/composition-v3.json").read_bytes())

if __name__ == "__main__":
    unittest.main()
