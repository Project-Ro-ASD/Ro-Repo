import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_authorization import request, verify_signed
from v3_group_validation import validate_claim
from v3_integration import proposal, verify_proposal, acceptance, tree_inventory
from v3_policy_profile import profile, sha, BASE, DESKTOP, SYSTEM
from v3_promotion_planner import PlanningError, plan, version_compare
from v3_publication_rehearsal import initialize, begin, finish, audit
from v3_signed_beta_history import _json_file, _signature
from test_v3_promotion_planner import assist, dolphin, snapshot, REGISTRY as PLANNER_REGISTRY
from test_v3_group_validation import mkplan, mkclaim, REGISTRY as CLAIM_REGISTRY

REGISTRY = copy.deepcopy(PLANNER_REGISTRY)
for producer in REGISTRY["producers"]:
    producer["repository"] = "Project-Ro-ASD/test-only"
    for policy in producer["components"]:
        policy["risk_class"] = "critical-desktop" if policy["component"] == "dolphin" else "normal-app"
        policy["required_tests"] = sorted(BASE)
        policy["trusted_signer_workflow"] = "Project-Ro-ASD/test-only/.github/workflows/release.yml"


def make_proposal(*, version="0.2.5", previous=None, result="d" * 64, mode="normal", now="2026-10-11T12:00:00Z"):
    p = plan(snapshot("repo-f44-20261010-001", assist(version) + dolphin()), previous, REGISTRY, "ro-assist")
    history = [{"publication_run": "101", "published_at": "2026-10-01T12:00:00Z",
                "promotion_group": "ro-assist", "candidate_sha256": p["candidate_sha256"]}]
    return proposal(p, REGISTRY, history, [{"release_id": 123, "source_commit": "a" * 40}],
                    now=now, mode=mode, reason="security fix" if mode == "fast-track" else None,
                    previous_sha256=None if previous is None else "c" * 64, result_sha256=result,
                    evidence={"group-validation-claim": "b" * 64})


class IntegrationTests(unittest.TestCase):
    def test_duplicate_metadata_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "metadata.json"
            for raw in ('{"a": 1, "a": 2}', '{"a": NaN}'):
                path.write_text(raw)
                with self.assertRaises(PlanningError):
                    _json_file(path)

    def test_signed_metadata_toctou_is_rejected(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            file = root / "signed.json"
            file.write_text('{"a": 1}')
            (root / "signed.json.asc").write_text("signature")
            def mutate(_):
                file.write_text('{"a": 2}')
            with mock.patch("v3_signed_beta_history._verify", side_effect=mutate):
                with self.assertRaisesRegex(PlanningError, "changed during"):
                    _signature(root, "signed.json", root / "keyring")

    def test_policy_uses_registry_and_contract_risk_floor(self):
        for group, risk in (("ro-assist", "normal-app"), ("ro-kde-dolphin", "critical-desktop")):
            p = profile(REGISTRY, group)
            self.assertEqual(p["risk_class"], risk)
            self.assertEqual(set(p["required_tests"]), BASE | (DESKTOP if risk == "critical-desktop" else set()))

    def test_policy_divergence_rejected(self):
        changed = profile(REGISTRY, "ro-assist")
        changed["minimum_beta_days"] = 0
        with self.assertRaisesRegex(PlanningError, "divergence"):
            profile(REGISTRY, "ro-assist", expected=changed)

    def test_candidate_binds_policy_and_source_provenance(self):
        original = make_proposal()
        for field in ("policy", "source_provenance", "packages"):
            changed = copy.deepcopy(original)
            changed["candidate_identity"][field] = []
            changed["proposal_sha256"] = sha({k: v for k, v in changed.items() if k != "proposal_sha256"})
            with self.assertRaisesRegex(PlanningError, "candidate identity"):
                verify_proposal(changed)

    def test_unrelated_beta_preserves_candidate_and_first_seen(self):
        first = make_proposal()
        p = plan(snapshot("repo-f44-20261011-002", assist()), None, REGISTRY, "ro-assist")
        history = [{"publication_run": "101", "published_at": "2026-10-01T12:00:00Z",
                    "promotion_group": "ro-assist", "candidate_sha256": p["candidate_sha256"]},
                   {"publication_run": "102", "published_at": "2026-10-11T12:00:00Z",
                    "promotion_group": "ro-assist", "candidate_sha256": p["candidate_sha256"]}]
        later = proposal(p, REGISTRY, history, first["candidate_identity"]["source_provenance"],
                         now="2026-10-11T12:00:00Z", result_sha256="d" * 64,
                         evidence=first["evidence_sha256"])
        self.assertEqual(first["candidate_sha256"], later["candidate_sha256"])
        self.assertEqual(first["first_seen"], later["first_seen"])

    def test_artifact_change_creates_new_candidate(self):
        self.assertNotEqual(make_proposal()["candidate_sha256"], make_proposal(version="0.2.6")["candidate_sha256"])

    def test_complete_canonical_architecture_is_required(self):
        p = plan(snapshot("repo-f44-20261010-001", [x for x in assist() if x["architecture"] != "aarch64"]),
                 None, REGISTRY, "ro-assist")
        with self.assertRaisesRegex(PlanningError, "incomplete registered architecture"):
            proposal(p, REGISTRY, [], [], now="2026-10-11T12:00:00Z")

    def test_incomplete_retained_group_is_rejected(self):
        old = dolphin()
        old = [p for p in old if not p["nevra"].startswith("dolphin-devel-")]
        with self.assertRaisesRegex(PlanningError, "incomplete binary"):
            plan(snapshot("beta", assist()), snapshot("stable", old), REGISTRY, "ro-assist")

    def test_missing_retained_source_is_rejected(self):
        old = [p for p in dolphin() if p["architecture"] != "src"]
        with self.assertRaisesRegex(PlanningError, "missing binary or SRPM"):
            plan(snapshot("beta", assist()), snapshot("stable", old), REGISTRY, "ro-assist")

    def test_normal_insufficient_dwell_cannot_request_approval(self):
        p = make_proposal(now="2026-10-02T12:00:00Z")
        with self.assertRaisesRegex(PlanningError, "insufficient"):
            request(p, "attempt-1")

    def test_fast_track_waives_only_dwell(self):
        p = make_proposal(mode="fast-track", now="2026-10-02T12:00:00Z")
        request(p, "attempt-1")
        p["evidence_sha256"] = {}
        p["proposal_sha256"] = sha({k: v for k, v in p.items() if k != "proposal_sha256"})
        with self.assertRaisesRegex(PlanningError, "mandatory component tests"):
            request(p, "attempt-1")

    def test_full_set_architecture_evidence_includes_retained_packages(self):
        p = mkplan("ro-kde-dolphin", ("x86_64",))
        c = mkclaim(p, BASE | DESKTOP)
        p["resulting_stable_packages"].append({"architecture": "aarch64", "nevra": "retained"})
        from v3_group_validation import stable_set_digest
        c["stable_set_sha256"] = stable_set_digest(p)
        for check in c["checks"]:
            check["stable_set_sha256"] = c["stable_set_sha256"]
        with self.assertRaisesRegex(PlanningError, "architecture baseline"):
            validate_claim(p, CLAIM_REGISTRY, c)

    def test_no_receipt_can_unlock_production(self):
        p = make_proposal()
        result = acceptance(p)
        self.assertFalse(result["publishable"])
        self.assertEqual(result["gates"]["production-activation"], "BLOCKED")
        self.assertEqual(result["gates"]["protected-environment-authorization"], "UNVERIFIED")

    def test_wrong_stable_base_digest_rejected(self):
        p = make_proposal()
        p["previous_stable_sha256"] = "a" * 64
        with self.assertRaisesRegex(PlanningError, "mutable proposal"):
            verify_proposal(p)

    def test_downgrades_and_epoch_downgrades_rejected(self):
        for older, newer in (("0.2.4", "0.2.5"), ("2.9", "2.10"), ("2.0~rc1", "2.0"), ("2.0", "2.0^git1")):
            with self.subTest(older=older):
                with self.assertRaisesRegex(PlanningError, "downgrade"):
                    plan(snapshot("beta", assist(older)), snapshot("stable", assist(newer)), REGISTRY, "ro-assist")
        old = assist()
        for package in old:
            package["nevra"] = package["nevra"].replace("-0:", "-1:")
        with self.assertRaisesRegex(PlanningError, "downgrade"):
            plan(snapshot("beta", assist("99.0")), snapshot("stable", old), REGISTRY, "ro-assist")

    def test_rpm_ordering_special_versions(self):
        for low, high in (("1.9", "1.10"), ("1~rc", "1"), ("1", "1^git"), ("1^git", "1.1"), ("1a", "1.1")):
            self.assertLess(version_compare(low, high), 0)
        self.assertEqual(version_compare("1.01", "1.1"), 0)


class SignedRehearsalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = pathlib.Path(cls.tmp.name)
        cls.home = cls.base / "gpg"
        cls.home.mkdir(mode=0o700)
        cls.command(["gpg", "--homedir", str(cls.home), "--batch", "--pinentry-mode", "loopback",
                     "--passphrase", "", "--quick-generate-key", "V3 TEST ONLY <test@invalid>", "ed25519", "sign", "1d"])
        cls.key = cls.base / "approval-public.asc"
        cls.key.write_bytes(cls.command(["gpg", "--homedir", str(cls.home), "--armor", "--export"]))
        cls.key_sha = hashlib.sha256(cls.key.read_bytes()).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.command(["gpgconf", "--homedir", str(cls.home), "--kill", "gpg-agent"])
        cls.tmp.cleanup()

    @staticmethod
    def command(argv):
        return subprocess.run(argv, check=True, capture_output=True).stdout

    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(dir=self.base))
        self.tree = self.work / "result"
        self.tree.mkdir()
        (self.tree / "complete-content").write_bytes(b"signed fixture view")
        self.value = make_proposal(result=sha(tree_inventory(self.tree)))
        self.root = self.work / "rehearsal"
        initialize(self.root)
        self.now = "2026-10-11T12:00:00Z"

    def sign(self, value=None, attempt="try-1", operation="promote", known=None):
        value = self.value if value is None else value
        directory = self.work / (attempt + "-approval")
        directory.mkdir()
        approval = {**request(value, attempt, operation=operation, target_verified_sha256=known),
                    "actor": "test-maintainer", "approved_at": self.now, "expires_at": "2026-10-11T13:00:00Z"}
        file = directory / "authorization-v3.json"
        file.write_text(json.dumps(approval))
        self.command(["gpg", "--homedir", str(self.home), "--batch", "--yes", "--armor", "--detach-sign", str(file)])
        return directory

    def begin(self, approval, value=None, attempt="try-1", tree=None, operation="promote"):
        return begin(self.root, self.value if value is None else value, self.tree if tree is None else tree,
                     approval, attempt, key=self.key, key_sha256=self.key_sha, now=self.now, operation=operation)

    def test_actual_signed_approval_and_idempotent_complete(self):
        directory = self.sign()
        first = self.begin(directory)
        self.assertEqual(first["phase"], "staged")
        self.assertIsNone(audit(self.root)["current"])
        complete = finish(self.root, "try-1", now=self.now)
        self.assertEqual(complete, self.begin(directory))
        self.assertEqual(complete, finish(self.root, "try-1", now=self.now))
        self.assertEqual(audit(self.root)["current"], self.value["result_stable_sha256"])

    def test_signed_fast_track_waives_dwell_with_exact_reason(self):
        self.value = make_proposal(result=sha(tree_inventory(self.tree)), mode="fast-track", now="2026-10-02T12:00:00Z")
        self.assertFalse(self.value["dwell_met"])
        directory = self.sign()
        self.begin(directory)
        self.assertEqual(finish(self.root, "try-1", now=self.now)["phase"], "completed")
        changed = copy.deepcopy(self.value)
        changed["reason"] = "different emergency"
        changed["proposal_sha256"] = sha({k: v for k, v in changed.items() if k != "proposal_sha256"})
        with self.assertRaisesRegex(PlanningError, "authorization binding"):
            self.begin(directory, value=changed)

    def test_unsigned_readonly_receipt_cannot_authorize(self):
        directory = self.work / "readonly-receipt"
        directory.mkdir()
        (directory / "authorization-v3.json").write_text(json.dumps({"approval_granted": True, "publishable": True}))
        with self.assertRaisesRegex(PlanningError, "signed metadata"):
            self.begin(directory)

    def test_forged_signature_and_wrong_key_rejected(self):
        directory = self.sign()
        for tamper in ("key", "signature"):
            with self.subTest(tamper=tamper):
                if tamper == "signature":
                    (directory / "authorization-v3.json.asc").write_text("forged")
                with self.assertRaises(PlanningError):
                    verify_signed(self.value, directory, "try-1", self.key,
                                  "e" * 64 if tamper == "key" else self.key_sha, now=self.now)
        self.assertIsNone(audit(self.root)["current"])

    def test_modified_signed_approval_rejected(self):
        directory = self.sign()
        file = directory / "authorization-v3.json"
        content = json.loads(file.read_text())
        content["actor"] = "attacker"
        file.write_text(json.dumps(content))
        with self.assertRaisesRegex(PlanningError, "signature"):
            self.begin(directory)

    def test_stale_approval_and_attempt_reuse_rejected(self):
        directory = self.sign()
        for attempt, now in (("try-2", self.now), ("try-1", "2026-10-11T13:00:00Z")):
            with self.assertRaises(PlanningError):
                verify_signed(self.value, directory, attempt, self.key, self.key_sha, now=now)

    def test_result_policy_reason_and_base_substitution_rejected(self):
        directory = self.sign()
        for field, replacement in (("result_stable_sha256", "e" * 64), ("mode", "fast-track"),
                                   ("reason", "different"), ("policy_version", "other"),
                                   ("previous_stable_sha256", "e" * 64)):
            changed = copy.deepcopy(self.value)
            changed[field] = replacement
            changed["proposal_sha256"] = sha({k: v for k, v in changed.items() if k != "proposal_sha256"})
            with self.subTest(field=field), self.assertRaises(PlanningError):
                self.begin(directory, value=changed)

    def test_partial_staging_preserves_previous_pointer_and_consumes_attempt(self):
        directory = self.sign()
        self.begin(directory)
        staged = self.root / "snapshots" / self.value["result_stable_sha256"] / "complete-content"
        staged.unlink()
        with self.assertRaises(PlanningError):
            finish(self.root, "try-1", now=self.now)
        self.assertIsNone(audit(self.root)["current"])
        with self.assertRaises(PlanningError):
            self.begin(directory)

    def test_tampered_source_does_not_advertise(self):
        directory = self.sign()
        (self.tree / "complete-content").write_bytes(b"tampered")
        with self.assertRaisesRegex(PlanningError, "tampered"):
            self.begin(directory)
        self.assertIsNone(audit(self.root)["current"])
        self.assertEqual(audit(self.root)["attempts"]["try-1"]["phase"], "failed")

    def test_concurrent_stale_base_is_rejected(self):
        a = self.sign()
        b = self.sign(attempt="try-2")
        self.begin(a)
        self.begin(b, attempt="try-2")
        finish(self.root, "try-1", now=self.now)
        with self.assertRaisesRegex(PlanningError, "concurrent"):
            finish(self.root, "try-2", now=self.now)
        self.assertEqual(audit(self.root)["current"], self.value["result_stable_sha256"])

    def test_expiry_between_staging_and_publication(self):
        self.begin(self.sign())
        with self.assertRaisesRegex(PlanningError, "expired"):
            finish(self.root, "try-1", now="2026-10-11T13:00:00Z")
        self.assertIsNone(audit(self.root)["current"])

    def test_completed_snapshot_tampering_blocks_idempotent_success(self):
        self.begin(self.sign())
        finish(self.root, "try-1", now=self.now)
        path = self.root / "snapshots" / self.value["result_stable_sha256"] / "complete-content"
        path.write_bytes(b"tampered historical content")
        with self.assertRaisesRegex(PlanningError, "historical snapshot"):
            finish(self.root, "try-1", now=self.now)

    def test_unverified_rollback_cannot_be_authorized(self):
        with self.assertRaisesRegex(PlanningError, "previously verified"):
            request(self.value, "recover-1", operation="recover")

    def test_authorized_recovery_to_verified_history(self):
        self.begin(self.sign())
        finish(self.root, "try-1", now=self.now)
        new_tree = self.work / "second-result"
        new_tree.mkdir()
        (new_tree / "complete-content").write_bytes(b"new signed fixture")
        second = copy.deepcopy(self.value)
        second["previous_stable_sha256"] = self.value["result_stable_sha256"]
        second["previous_stable_snapshot_id"] = "repo-f44-20261011-001"
        second["result_stable_sha256"] = sha(tree_inventory(new_tree))
        second["proposal_sha256"] = sha({k: v for k, v in second.items() if k != "proposal_sha256"})
        self.begin(self.sign(second, "try-2"), value=second, attempt="try-2", tree=new_tree)
        finish(self.root, "try-2", now=self.now)
        recovery = copy.deepcopy(self.value)
        recovery["previous_stable_sha256"] = second["result_stable_sha256"]
        recovery["previous_stable_snapshot_id"] = "repo-f44-20261011-002"
        recovery["proposal_sha256"] = sha({k: v for k, v in recovery.items() if k != "proposal_sha256"})
        directory = self.sign(recovery, "recover-1", "recover", self.value["result_stable_sha256"])
        self.begin(directory, value=recovery, attempt="recover-1", operation="recover")
        finish(self.root, "recover-1", now=self.now)
        self.assertEqual(audit(self.root)["current"], self.value["result_stable_sha256"])
        self.assertTrue((self.root / "snapshots" / second["result_stable_sha256"]).is_dir())

    def test_symlink_and_audit_mutation_fail_closed(self):
        path = self.root / "state.json"
        state = json.loads(path.read_text())
        state["audit"] = [{"previous_event_sha256": "e" * 64}]
        path.write_text(json.dumps(state))
        with self.assertRaisesRegex(PlanningError, "audit chain"):
            audit(self.root)
        path.unlink()
        path.symlink_to(self.tree / "complete-content")
        with self.assertRaisesRegex(PlanningError, "unsafe"):
            audit(self.root)


if __name__ == "__main__":
    unittest.main()
