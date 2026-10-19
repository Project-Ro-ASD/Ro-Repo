"""Phase-A preparation boundaries; existing V2/V3 behavior stays under its tests."""
import copy
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import psop_audit as audit
import ro_repo
from v3_fenced_publisher import FencedPublisher
from v3_immutable_view import production_publish
from v3_promotion_planner import PlanningError
from v3_rpm_preflight import verify as verify_rpms
from v3_signed_beta_history import _keyring
from v3_stable_composer import _read_snapshot


class PhaseAContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = json.loads((ROOT / "docs/psop/phase-a-profile.json").read_text())
        cls.baseline = json.loads((ROOT / "docs/evidence/psop-phase1/base-protected-files.json").read_text())

    def test_real_source_and_public_roots_are_preserved(self):
        report = audit.audit_source(ROOT, self.baseline)
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["source_preservation"], "PASS")
        self.assertFalse(report["publishable"])
        self.assertEqual(audit.validate_profile(self.profile, ROOT)["production_activation"], "BLOCKED")

    def test_profile_cannot_enable_activation_or_inherit_v2_or_v3_authority(self):
        variants = [{"production_activation": True}, {"production_activation": 0},
                    {"writer_authority": ["promote-remote-stable.yml"]},
                    {"writer_authority": ["ro-repo-remote-beta", "psop"]},
                    {"strict_v3_compatible": True}, {"phase": "C"},
                    {"approval_granted": True}, {"profile": "v3"}]
        for change in variants:
            with self.subTest(change=change), self.assertRaises(audit.AuditError):
                audit.validate_profile({**self.profile, **change}, ROOT)
        for guarantee in self.profile["provider_guarantees"]:
            profile = copy.deepcopy(self.profile)
            profile["provider_guarantees"][guarantee] = True
            with self.subTest(guarantee=guarantee), self.assertRaises(audit.AuditError):
                audit.validate_profile(profile, ROOT)

    def test_wrong_role_or_unpinned_trust_fails_before_external_verification(self):
        profile = copy.deepcopy(self.profile)
        profile["public_roots"]["metadata"] = profile["public_roots"]["rpm"]
        with self.assertRaises(audit.AuditError):
            audit.validate_profile(profile, ROOT)
        with tempfile.TemporaryDirectory() as temp, mock.patch("subprocess.run") as external:
            with self.assertRaisesRegex(PlanningError, "pin mismatch"):
                _keyring(ROOT / audit.PUBLIC_ROOTS["metadata"]["path"], "0" * 64, temp)
            external.assert_not_called()

    def test_strict_v3_locks_reject_psop_objects(self):
        for value in (self.profile, {"profile": "psop", "approval_granted": True}, None):
            with self.subTest(value=value), self.assertRaisesRegex(PlanningError, "BLOCKED"):
                production_publish(value)
        with self.assertRaisesRegex(PlanningError, "BLOCKED"):
            FencedPublisher.activate_production(None)

    def test_legacy_v1_tree_is_not_a_stable_snapshot_or_signed_composition(self):
        with self.assertRaises(PlanningError):
            _read_snapshot(ROOT / "x86_64")
        with self.assertRaises(PlanningError):
            verify_rpms(ROOT / "x86_64", ROOT / audit.PUBLIC_ROOTS["rpm"]["path"],
                        audit.PUBLIC_ROOTS["rpm"]["sha256"])

    def test_source_guard_detects_workflow_authority_and_runtime_mutations(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            reviewed = json.loads((ROOT / audit.V2_REVIEWED_CONTRACT).read_text())
            protected_files = set(self.baseline["files"]) | set(reviewed["files"]) | {audit.V2_REVIEWED_CONTRACT}
            for rel in protected_files:
                dest = root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / rel, dest)
            for rel in (".github/workflows/publish-remote-beta.yml",
                        ".github/workflows/promote-remote-stable.yml",
                        ".github/workflows/v3-stable-promotion-disabled.yml",
                        "tools/v3_fenced_publisher.py", audit.PUBLIC_ROOTS["metadata"]["path"]):
                self.assertEqual(audit.audit_source(root, self.baseline)["issues"], [])
                path = root / rel
                original = path.read_bytes()
                path.write_bytes(original + b"\n# unauthorized mutation\n")
                with self.subTest(rel=rel):
                    self.assertIn("changed: " + rel, audit.audit_source(root, self.baseline)["issues"])
                path.write_bytes(original)
            added = root / ".github/workflows/psop-publish.yml"
            added.write_text("permissions: {contents: write}\n")
            self.assertIn("unreviewed addition: .github/workflows/psop-publish.yml",
                          audit.audit_source(root, self.baseline)["issues"])
            added.unlink()
            metadata = root / audit.PUBLIC_ROOTS["metadata"]["path"]
            metadata.write_bytes(b"untrusted root")
            with self.assertRaises(audit.AuditError):
                audit.validate_profile(self.profile, root)
            metadata.unlink()
            metadata.symlink_to(ROOT / audit.PUBLIC_ROOTS["metadata"]["path"])
            with self.assertRaises(audit.AuditError):
                audit.validate_profile(self.profile, root)
            self.assertIn("missing/unsafe: " + audit.PUBLIC_ROOTS["metadata"]["path"],
                          audit.audit_source(root, self.baseline)["issues"])

    def test_reviewed_v2_contract_is_exact_and_cannot_be_shortened(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            target = root / audit.V2_REVIEWED_CONTRACT
            target.parent.mkdir(parents=True)
            data = json.loads((ROOT / audit.V2_REVIEWED_CONTRACT).read_text())
            data["files"].pop("tools/v2_selected_stable.py")
            target.write_text(json.dumps(data))
            with self.assertRaisesRegex(audit.AuditError, "reviewed V2 source contract"):
                audit.audit_source(root, self.baseline)

    def test_baseline_cannot_be_shortened_to_hide_changed_writers(self):
        baseline = copy.deepcopy(self.baseline)
        baseline["files"].pop(".github/workflows/promote-remote-stable.yml")
        with self.assertRaises(audit.AuditError):
            audit.audit_source(ROOT, baseline)

    def test_github_collector_only_uses_allowlisted_gets_and_keeps_denials_unverified(self):
        def response(argv, **kwargs):
            self.assertEqual(argv[:4], ["gh", "api", "--method", "GET"])
            endpoint = argv[4].removeprefix("repos/" + audit.REPOSITORY + "/")
            self.assertIn(endpoint, audit.GITHUB_GETS)
            self.assertNotIn("secrets", endpoint)
            self.assertEqual(len(argv), 5)
            if endpoint == "environments":
                return subprocess.CompletedProcess(argv, 1, '{"status":"403"}', 'private diagnostic')
            return subprocess.CompletedProcess(argv, 0, '{}', '')
        with mock.patch("psop_audit.subprocess.run", side_effect=response):
            report = audit.collect_github()
        denied = next(o for o in report["observations"] if o["endpoint"] == "environments")
        self.assertEqual(denied["status"], "UNVERIFIED")
        self.assertNotIn("private diagnostic", json.dumps(report))
        self.assertFalse(report["secret_endpoints_requested"])
        self.assertFalse(report["publishable"])


class HistoryAuditTests(unittest.TestCase):
    def test_deleted_stable_is_detected_in_earlier_reachable_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.DEVNULL).strip()
            git("init")
            git("config", "user.name", "Disposable PSOP history test")
            git("config", "user.email", "test@example.invalid")
            marker = root / "rpm/fedora/44/stable/x86_64/repodata/repomd.xml"
            marker.parent.mkdir(parents=True)
            marker.write_bytes(b"synthetic history; no repository publication")
            immutable = root / "snapshots/fedora/44/repo-f44-20261015-001/manifest"
            immutable.parent.mkdir(parents=True)
            immutable.write_bytes(b"old immutable bytes")
            git("add", ".")
            git("-c", "commit.gpgsign=false", "commit", "-m", "historical stable")
            old = git("rev-parse", "HEAD")
            marker.unlink()
            immutable.write_bytes(b"forbidden historical rewrite")
            git("add", "-u")
            git("-c", "commit.gpgsign=false", "commit", "-m", "current stable absent")
            report = audit.audit_history(root, git("rev-parse", "HEAD"))
            self.assertEqual(report["historical_absence"], "FOUND")
            self.assertEqual(report["stable_tree_hits"], [{"commit": old, "paths": [marker.relative_to(root).as_posix()]}])
            self.assertEqual(report["deleted_or_unreachable_history"], "UNVERIFIED")
            self.assertEqual(report["immutable_history"], "FAIL")
            self.assertEqual([entry["path"] for entry in report["immutable_drift"]],
                             [immutable.relative_to(root).as_posix()])

    def test_mutable_ref_is_not_accepted_as_history_evidence(self):
        with self.assertRaises(audit.AuditError):
            audit.audit_history(ROOT, "pages-storage")


class BetaIsolationTests(unittest.TestCase):
    def test_beta_rollback_preserves_stable_snapshot_and_entire_existing_history(self):
        # Reuse the V2 fixture, and exercise the real staging/rollback functions.
        # Signature acceptance is stubbed exactly as in the V2 fixture; this test
        # proves path isolation, not cryptographic correctness.
        import test_remote_beta_rollback
        fixture = test_remote_beta_rollback.RemoteBetaRollbackTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        stable = fixture.site / "rpm/fedora/44/stable"
        stable.mkdir()
        (stable / "sentinel").write_bytes(b"unchanged stable")
        protected = (stable, fixture.snapshot, fixture.history)
        before = [ro_repo.directory_tree_digest(p) for p in protected]
        with mock.patch.object(ro_repo, "verify_signed_remote_publication",
                               side_effect=lambda pub, *args: ro_repo.load(pathlib.Path(pub) / "publication-v1.json")):
            ro_repo.rollback_remote_channel(fixture.site, "beta", "100", "300", "isolation regression", fixture.root / "gnupg")
        self.assertEqual(before, [ro_repo.directory_tree_digest(p) for p in protected])
        self.assertEqual(ro_repo.load(fixture.site / "rpm/fedora/44/beta/publication-v1.json")["publication_run"], "100")


if __name__ == "__main__":
    unittest.main()
