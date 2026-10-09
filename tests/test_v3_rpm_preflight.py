import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_promotion_planner import PlanningError
import v3_rpm_preflight as preflight

def sha(data):
    return hashlib.sha256(data).hexdigest()

class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.key = self.root / "trusted.asc"
        self.key.write_bytes(b"trusted public key")
        self.digest = sha(self.key.read_bytes())
        self.source = "ro-assist-0.2.5-1.fc44.src.rpm"
        self.nevra = "ro-assist-0:0.2.5-1.fc44.x86_64"
        self.filename = "ro-assist-0.2.5-1.fc44.x86_64.rpm"
        files = {
            "rpm/source/" + self.source: ("ro-assist-0:0.2.5-1.fc44.src", self.source),
            "rpm/x86_64/" + self.filename: (self.nevra, self.filename),
        }
        packages = []
        for rel, (nevra, filename) in files.items():
            path = self.candidate / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(rel.encode())
            packages.append({
                "nevra": nevra, "filename": filename,
                "architecture": "src" if "/source/" in rel else "x86_64",
                "producer_artifact_sha256": sha(rel.encode()),
                "producer_manifest_digest": "b" * 64,
                "published_signed_artifact_sha256": sha(rel.encode())
            })
        self.plan = {"publishable": False, "promotion_group": "ro-assist",
                     "candidate_sha256": "a" * 64, "resulting_stable_packages": packages}
        self.composition = {
            "scope": "offline-v3-untrusted-composition", "publishable": False,
            "promotion_group": "ro-assist", "candidate_sha256": "a" * 64,
            "files": [{"path": rel, "sha256": sha(rel.encode())} for rel in files],
        }
        self.save()
    def tearDown(self):
        self.tmp.cleanup()
    def save(self):
        (self.candidate / "promotion-plan-v3.json").write_text(json.dumps(self.plan))
        (self.candidate / "composition-v3.json").write_text(json.dumps(self.composition))
    def fake_run(self, args):
        if args[0] == "rpmkeys":
            return "signature OK\n"
        if args[0] == "rpm":
            if args[-1].endswith(".src.rpm"):
                return "ro-assist\t0\t0.2.5\t1.fc44\tx86_64\t1\t(none)\n"
            return "ro-assist\t0\t0.2.5\t1.fc44\tx86_64\t0\t" + self.source + "\n"
        raise AssertionError(args)
    def test_real_file_inventory_and_headers_with_mocked_rpm_interface(self):
        with mock.patch.object(preflight, "_run", side_effect=self.fake_run) as calls:
            result = preflight.verify(self.candidate, self.key, self.digest)
        self.assertTrue(result["local_header_checks_passed"])
        self.assertFalse(result["publishable"])
        self.assertFalse(result["dnf_tests_executed"])
        self.assertEqual(len(result["checked_rpm_files"]), 2)
        self.assertTrue(any(c.args[0][0] == "rpmkeys" for c in calls.call_args_list))
    def test_tampered_bytes_fail_closed(self):
        (self.candidate / "rpm/x86_64" / self.filename).write_bytes(b"tampered")
        with self.assertRaisesRegex(PlanningError, "bytes differ"):
            with mock.patch.object(preflight, "_run", side_effect=self.fake_run):
                preflight.verify(self.candidate, self.key, self.digest)
    def test_key_not_pinned_fail_closed(self):
        with self.assertRaisesRegex(PlanningError, "key hash mismatch"):
            preflight.verify(self.candidate, self.key, "f" * 64)
    def test_missing_or_extra_rpm_rejected(self):
        extra = self.candidate / "rpm/x86_64/rogue.rpm"
        extra.write_bytes(b"not allowed")
        with self.assertRaisesRegex(PlanningError, "unexpected/missing RPMs"):
            preflight.verify(self.candidate, self.key, self.digest)
    def test_symlinked_rpm_rejected(self):
        path = self.candidate / "rpm/x86_64" / self.filename
        path.unlink()
        path.symlink_to(self.key)
        with self.assertRaises(PlanningError):
            with mock.patch.object(preflight, "_run", side_effect=self.fake_run):
                preflight.verify(self.candidate, self.key, self.digest)
    def test_binary_source_linkage_enforced(self):
        def bad(args):
            value = self.fake_run(args)
            if args[0] == "rpm" and args[-1].endswith(".x86_64.rpm"):
                return value.replace(self.source, "rogue.src.rpm")
            return value
        with self.assertRaisesRegex(PlanningError, "not linked"):
            with mock.patch.object(preflight, "_run", side_effect=bad):
                preflight.verify(self.candidate, self.key, self.digest)
    def test_failed_signature_rejected(self):
        def bad(args):
            if args[0] == "rpmkeys" and "--checksig" in args:
                return "unsigned"
            return self.fake_run(args)
        with self.assertRaisesRegex(PlanningError, "signature"):
            with mock.patch.object(preflight, "_run", side_effect=bad):
                preflight.verify(self.candidate, self.key, self.digest)

if __name__ == "__main__":
    unittest.main()
