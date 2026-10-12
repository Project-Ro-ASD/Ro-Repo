"""PR72 negatives: real signatures/Git, injected clocks and race boundaries.

Synthetic package fixtures are not application or production acceptance.
"""
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_backend_support import Keys, Fixture, NOW
from v3_backend_trust import verify_envelope, strict_json
from v3_backend_evidence import verify_protected
from v3_immutable_view import IsolatedStore, verify_remote
from v3_pages_backend import IsolatedGitStore, GitReader
from v3_promotion_planner import PlanningError


class AdversarialBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Keys()

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    def setUp(self):
        self.fx = Fixture(self.keys)
        self.addCleanup(self.fx.close)

    def view(self):
        self.fx.advance("AUTHORIZED")
        self.fx.view = IsolatedStore(self.fx.root).stage(
            self.fx.result, self.fx.approval, self.keys.signers["publication"],
            origin="https://test.invalid", audit_key_sha256=self.keys.signers["audit"].key_sha256, now=NOW)
        return self.fx.view

    def git_view(self):
        view = self.view()
        store = IsolatedGitStore(self.fx.root)
        staged = store.stage(view, expected=None)
        deployment = self.keys.attestation("deployment", {
            "result_stable_sha256": view.sha256, "publication_sha256": view.envelope_sha256,
            "git_commit": staged["git_commit"], "deployment_id": "test-only"})
        return store, staged, deployment

    def test_stale_pre_verification_cannot_publish(self):
        self.fx.advance("AUTHORIZED")
        self.fx.stage()
        before = self.fx.ledger.inspect()
        self.fx.now = NOW + 61  # Approval remains valid for another 239 seconds.
        with self.assertRaises(PlanningError):
            self.fx.backend.publish(self.fx.attempt, self.fx.approval)
        self.fx.now = NOW
        self.assertEqual(before, self.fx.ledger.inspect())

    def test_expired_authorization_cannot_advance_staging(self):
        view = self.view()
        self.fx.backend.signed(self.fx.attempt, view)
        before = self.fx.ledger.inspect()
        self.fx.now = NOW + 300
        with self.assertRaises(PlanningError):
            self.fx.backend.staged(self.fx.attempt, view)
        self.fx.now = NOW
        self.assertEqual(before, self.fx.ledger.inspect())

    def test_expiry_during_audit_signing_rolls_back_consumption(self):
        self.fx.advance()
        before = self.fx.ledger.inspect()
        sign = self.fx.ledger.signer.sign
        def slow_sign(data):
            raw = sign(data)
            self.fx.now = NOW + 300
            return raw
        with mock.patch.object(self.fx.ledger.signer, "sign", side_effect=slow_sign):
            with self.assertRaises(PlanningError):
                self.fx.backend.authorized(self.fx.attempt, self.fx.approval)
        self.fx.now = NOW
        self.assertEqual(before, self.fx.ledger.inspect())

    def test_noop_staging_retry_still_performs_ref_cas(self):
        store, staged, _ = self.git_view()
        concurrent = IsolatedGitStore(self.fx.root)
        build_tree = store._tree
        winner = []
        def racing_tree(files):
            tree = build_tree(files)
            winner.append(concurrent._cas({"v3/concurrent-record.json": b"independent writer"}, staged["git_commit"]))
            return tree
        with mock.patch.object(store, "_tree", side_effect=racing_tree):
            with self.assertRaises(PlanningError):
                store.stage(self.fx.view, expected=staged["git_commit"])
        self.assertEqual(store.head(), winner[0])

    def test_advertisement_signer_failure_cannot_move_ref(self):
        store, staged, deployment = self.git_view()
        remote = verify_remote(self.fx.view, GitReader(store, self.fx.view), deployment, now=NOW)
        signer = self.keys.signers["publication"]
        with mock.patch.object(signer, "sign", side_effect=self.keys.signers["approval"].sign):
            with self.assertRaises(PlanningError):
                store.advertise(self.fx.view, self.fx.approval, remote, signer,
                                expected=staged["git_commit"], previous_digest=None, now=NOW)
        self.assertEqual(store.head(), staged["git_commit"])

    def test_deployment_commit_must_match_git_reader(self):
        store, _, _ = self.git_view()
        wrong = self.keys.attestation("deployment", {
            "result_stable_sha256": self.fx.view.sha256, "publication_sha256": self.fx.view.envelope_sha256,
            "git_commit": "a" * 40, "deployment_id": "another-deployment"})
        with self.assertRaises(PlanningError):
            verify_remote(self.fx.view, GitReader(store, self.fx.view), wrong, now=NOW)

    def test_ref_change_during_remote_read_is_rejected(self):
        store, staged, deployment = self.git_view()
        reader = GitReader(store, self.fx.view)
        original = reader.read
        def racing_read(path):
            raw = original(path)
            store._cas({"v3/concurrent-record.json": b"new deployment"}, staged["git_commit"])
            return raw
        with mock.patch.object(reader, "read", side_effect=racing_read):
            with self.assertRaises(PlanningError):
                verify_remote(self.fx.view, reader, deployment, now=NOW)

    def test_audit_key_cannot_also_authorize_human_approval(self):
        self.fx.advance()
        args = dict(self.fx.approval_args)
        signer = self.keys.signers["audit"]
        payload = strict_json(args["approval_raw"])["payload"]
        args.update(approval_key=signer.public, approval_key_sha256=signer.key_sha256,
                    approval_raw=signer.envelope("human-approval", payload))
        approval = verify_envelope(args["approval_raw"], role="human-approval", public_key=signer.public,
                    key_sha256=signer.key_sha256, expected={k: v for k, v in payload.items() if k not in {"issued_at", "expires_at"}}, now=NOW)
        witness = strict_json(args["witness_raw"])["payload"]
        witness["approval_sha256"] = approval.sha256
        args["witness_raw"] = self.keys.signers["witness"].envelope("protected-environment-witness", witness)
        authority = verify_protected(self.fx.proposal, self.fx.attempt, self.fx.evidence, self.fx.workload, **args)
        before = self.fx.ledger.inspect()
        with self.assertRaises(PlanningError):
            self.fx.backend.authorized(self.fx.attempt, authority)
        self.assertEqual(before, self.fx.ledger.inspect())


if __name__ == "__main__":
    unittest.main()
