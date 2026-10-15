"""Real signed legacy archive, availability/genesis and source-guard boundaries."""
import copy
import json
import pathlib
import shutil
import sys
import unittest
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from psop_context import Context, Evidence, SEAL
from psop_history import read_archive, assess_history, availability_request
from psop_genesis import verify_genesis, genesis_request
from psop_inputs import acquire
from psop_plan import prepare
from psop_signing import MetadataSigner
from v3_promotion_planner import PlanningError, plan
from v3_backend_trust import canonical, digest
from v3_policy_profile import sha
from ro_repo import _sign_file_exact, ContractError
from test_v3_signed_beta_history import REG, S1, pub
import psop_audit

ROOT = pathlib.Path(__file__).resolve().parents[1]
NOW = 1792065600
UTC = "2026-10-15T12:00:00Z"


class InputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = Context.create()
        cls.signer = MetadataSigner.create(cls.context)

    @classmethod
    def tearDownClass(cls):
        import subprocess
        subprocess.run(["gpgconf", "--homedir", str(cls.signer.home), "--kill", "gpg-agent"], capture_output=True)
        cls.context.close()

    def setUp(self):
        self.root = self.context.path("archive-" + uuid.uuid4().hex)
        self.root.mkdir()
        self.publications, self.snapshots = self.root / "publications", self.root / "snapshots"
        self.publications.mkdir();self.snapshots.mkdir()
        self.snapshot = self.snapshots / S1["snapshot_id"];self.snapshot.mkdir()
        self.publication = self.publications / "10";self.publication.mkdir()
        self.key = self.root / "metadata.asc";self.key.write_bytes(self.signer.public)
        self.write(self.snapshot, "repository-snapshot-v1.json", S1)
        self.record = pub("10", S1["snapshot_id"], "2026-10-01T12:00:00Z")
        self.record.pop("store_tree_sha256")
        self.write(self.publication, "publication-v1.json", self.record)
        self.candidate = plan(S1, None, REG, "ro-assist")["candidate_sha256"]
        self.first = {"publication_run": "10", "published_at": "2026-10-02T12:00:00Z"}

    def write(self, folder, name, data):
        path = folder / name;path.write_bytes(canonical(data))
        sig = pathlib.Path(str(path) + ".asc")
        if sig.exists():sig.unlink()
        _sign_file_exact(path, self.signer.home, self.signer.fingerprint, self.signer.password)

    def archive(self):
        return read_archive(self.publications, self.snapshots, REG, "ro-assist", self.key,
                            digest(self.key.read_bytes()), UTC, context=self.context)

    def history(self, archive=None, changes=None):
        archive = archive or self.archive()
        request = availability_request(archive, self.candidate, self.first)
        request.update(changes or {})
        raw = self.context.envelope("availability", request, now=NOW)
        return assess_history(archive, [{"observed_at": "1990-01-01T00:00:00Z"}], raw,
            context=self.context, candidate=self.candidate, now=UTC)

    def test_legacy_signature_is_preserved_without_synthetic_fields_or_dwell_credit(self):
        path = self.publication / "publication-v1.json"
        before = path.read_bytes()
        archive = self.archive()
        self.assertEqual(path.read_bytes(), before)
        self.assertNotIn("store_tree_sha256", json.loads(path.read_bytes()))
        self.assertIsNone(archive.data["signed_records"][0]["store_tree_sha256"])
        self.assertEqual(archive.data["production_dwell"], "BLOCKED")

    def test_api_timestamp_and_signed_published_at_cannot_be_trusted_availability(self):
        a = self.archive()
        h = assess_history(a, [{"published_at": "1990-01-01T00:00:00Z"}], None,
                           context=self.context, candidate=self.candidate, now=UTC)
        self.assertEqual(h.data["status"], "BLOCKED")
        self.assertTrue(h.data["unproven_intervals"])
        self.assertIsNone(h.data["first_seen"])

    def test_authenticated_complete_synthetic_coverage_never_grants_production_dwell(self):
        h = self.history()
        self.assertEqual(h.data["status"], "PASS_TEST_ONLY")
        self.assertEqual(h.data["production_dwell"], "BLOCKED")
        self.assertFalse(h.data["publishable"])

    def test_incomplete_coverage_wrong_candidate_or_missing_run_rejected(self):
        for change in ({"coverage_complete": False}, {"covered_publication_runs": []}, {"candidate_sha256": "f" * 64}):
            with self.subTest(change=change), self.assertRaises(PlanningError):
                self.history(changes=change)

    def test_first_availability_cannot_precede_signed_publication_or_be_future(self):
        for when in ("2026-09-01T00:00:00Z", "2027-01-01T00:00:00Z"):
            self.first["published_at"] = when
            with self.subTest(when=when), self.assertRaises(PlanningError):
                self.history()

    def test_planner_cannot_borrow_authenticated_availability_from_another_candidate(self):
        h = self.history()
        beta = copy.deepcopy(S1)
        for package in beta["packages"]:
            package["published_signed_artifact_sha256"] = "f" * 64
        self.assertNotEqual(plan(beta, None, REG, "ro-assist")["candidate_sha256"], self.candidate)
        i = Evidence({"context": self.context.pin, "group": "ro-assist", "registry_sha256": sha(REG),
            "archive_sha256": h.data["archive"]["archive_sha256"], "previous_stable_sha256": None,
            "pins": {"main_sha": "a" * 40, "pages_sha": "b" * 40}, "manifests": {"beta": beta}}, SEAL)
        g = verify_genesis(i, h, self.context.envelope("genesis", genesis_request(i, h), now=NOW),
                           context=self.context, now=NOW)
        with self.assertRaisesRegex(PlanningError, "different candidate"):
            prepare(i, "ro-assist", REG, {}, history=h, genesis=g, context=self.context, now=UTC)

    def test_signed_archive_unknown_field_is_rejected_even_when_resigned(self):
        self.record["allow_missing_evidence"] = True
        self.write(self.publication, "publication-v1.json", self.record)
        with self.assertRaisesRegex(PlanningError, "fields"):
            self.archive()

    def test_tampered_or_unsigned_publication_rejected(self):
        p = self.publication / "publication-v1.json"
        p.write_bytes(p.read_bytes() + b" ")
        with self.assertRaisesRegex(PlanningError, "signature"):
            self.archive()

    def test_key_hash_and_mutable_source_pins_fail_closed(self):
        with self.assertRaisesRegex(PlanningError, "pin mismatch"):
            read_archive(self.publications, self.snapshots, REG, "ro-assist", self.key, "f" * 64, UTC, context=self.context)
        with self.assertRaisesRegex(PlanningError, "SHA pins"):
            acquire({"main_sha": "main", "pages_sha": "b" * 40}, {}, self.archive(),
                beta=self.snapshot, stable=None, registry=REG, group="ro-assist", source_evidence=b"",
                context=self.context, now=NOW)

    def test_archive_mutation_invalidates_verified_capability(self):
        a = self.archive()
        (self.publication / "extra").write_bytes(b"unverified")
        with self.assertRaisesRegex(PlanningError, "changed"):
            self.history(a)

    def test_explicit_genesis_binds_input_history_and_approval(self):
        h = self.history()
        i = Evidence({"context": self.context.pin, "pins": {"main_sha": "a" * 40, "pages_sha": "b" * 40},
                      "previous_stable_sha256": None}, SEAL)
        request = genesis_request(i, h)
        raw = self.context.envelope("genesis", request, now=NOW)
        result = verify_genesis(i, h, raw, context=self.context, now=NOW)
        self.assertEqual(result.data["production_genesis"], "BLOCKED")
        for data in (canonical({"http_status": 404, "reachable_commits": 300}),
                     self.context.envelope("approval", request, now=NOW),
                     self.context.envelope("genesis", {**request, "history_sha256": "f" * 64}, now=NOW)):
            with self.assertRaises(PlanningError):
                verify_genesis(i, h, data, context=self.context, now=NOW)

    def test_missing_availability_or_nonempty_base_cannot_be_empty_genesis(self):
        h = self.history()
        i = Evidence({"context": self.context.pin, "pins": {}, "previous_stable_sha256": "a" * 64}, SEAL)
        with self.assertRaises(PlanningError):
            verify_genesis(i, h, b"{}", context=self.context, now=NOW)

    def test_original_baseline_and_new_writer_credential_guard_remain_narrow(self):
        baseline = json.loads((ROOT / "docs/evidence/psop-phase1/base-protected-files.json").read_text())
        self.assertEqual(len(baseline["files"]), 234)
        dest = self.root / "source";dest.mkdir()
        for rel in baseline["files"]:
            target = dest / rel;target.parent.mkdir(parents=True, exist_ok=True);shutil.copy2(ROOT / rel, target)
        self.assertEqual(psop_audit.audit_source(dest, baseline)["issues"], [])
        for rel in ("tools/psop_production.py", "tools/psop_credentials.json", ".github/workflows/psop-write.yml"):
            target = dest / rel;target.parent.mkdir(parents=True, exist_ok=True);target.write_text("unauthorized")
            self.assertIn("unreviewed addition: " + rel, psop_audit.audit_source(dest, baseline)["issues"])
            target.unlink()


if __name__ == "__main__":
    unittest.main()
