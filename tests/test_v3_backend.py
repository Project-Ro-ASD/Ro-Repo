import copy
import multiprocessing
import pathlib
import shutil
import sqlite3
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_backend_trust import (verify_oidc, digest, canonical, encode, strict_json,
                              verify_envelope, require_test_root)
from v3_backend_evidence import verify_protected, verify_evidence
from v3_backend_ledger import Ledger, SQLiteAdapter, PostgreSQLAdapter
from v3_publication_backend import STATES, Backend
from v3_immutable_view import (IsolatedStore, DirectoryReader, verify_remote,
                               immutable_url, production_publish)
from v3_promotion_planner import PlanningError
from v3_policy_profile import sha
from v3_backend_support import Keys, Fixture, NOW
from test_v3_promotion_planner import snapshot, assist, dolphin


class BackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Keys()

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    def setUp(self):
        self.fx = Fixture(self.keys)
        self.addCleanup(self.fx.close)

    def reject(self, call):
        with self.assertRaises(PlanningError):
            call()

    def test_complete_signed_rehearsal(self):
        self.fx.complete()
        status = self.fx.ledger.inspect(self.fx.attempt)
        self.assertEqual(status["attempt"]["state"], "POST_VERIFIED")
        self.assertEqual(status["head"]["last_verified"], self.fx.result.sha256)
        self.assertFalse(status["publishable"])
        with self.fx.ledger.adapter.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM consumed").fetchone()[0], 4)

    def test_idempotent_completed_attempt_is_read_only(self):
        self.fx.complete()
        before = self.fx.ledger.inspect()
        self.fx.advance("AUTHORIZED")
        self.fx.backend.publish(self.fx.attempt, self.fx.approval)
        self.fx.backend.post_verified(self.fx.attempt, self.fx.remote)
        self.assertEqual(before, self.fx.ledger.inspect())

    def test_conflicting_attempt_replay(self):
        self.fx.advance("PROPOSED")
        p = copy.deepcopy(self.fx.proposal)
        p["reason"], p["mode"] = "different", "fast-track"
        p["proposal_sha256"] = sha({k: v for k, v in p.items() if k != "proposal_sha256"})
        self.reject(lambda: self.fx.backend.create(p, self.fx.plan, self.fx.registry, self.fx.attempt))

    def test_no_unsigned_json_can_authorize(self):
        self.fx.advance()
        self.reject(lambda: self.fx.backend.authorized(self.fx.attempt, {"approved": True, "publishable": True}))
        self.reject(lambda: self.fx.backend.verified(self.fx.attempt, {"result": "PASS"}))

    def test_verified_result_bytes_cannot_change(self):
        self.fx.advance("VERIFIED")
        (self.fx.source / "test-payload").write_text("substituted")
        self.reject(lambda: self.fx.backend.composed(self.fx.attempt, self.fx.result))

    def test_fast_track_still_requires_authenticated_tests(self):
        fx = Fixture(self.keys, mode="fast-track")
        self.addCleanup(fx.close)
        fx.advance()
        bad = dict(fx.attestations)
        del bad["tests"]
        self.reject(lambda: verify_evidence(fx.proposal, fx.plan, fx.registry, fx.claim, bad, now=NOW))

    def test_retained_desktop_tests_cannot_be_omitted(self):
        fx = Fixture(self.keys, previous=snapshot("repo-f44-20261010-001", dolphin()), previous_digest="c" * 64, retained=True)
        self.addCleanup(fx.close)
        broken = copy.deepcopy(fx.claim)
        broken["checks"] = [c for c in broken["checks"] if c["name"] not in {"plasma-integration", "login-session"}]
        p = copy.deepcopy(fx.proposal)
        p["evidence_sha256"]["group-validation-claim"] = sha(broken)
        p["proposal_sha256"] = sha({k: v for k, v in p.items() if k != "proposal_sha256"})
        attestations = {}
        for role, payload in fx.expectations.items():
            payload = copy.deepcopy(payload)
            payload["proposal_sha256"], payload["evidence_sha256"] = p["proposal_sha256"], p["evidence_sha256"]
            if role == "tests":
                payload["claim_sha256"] = sha(broken)
            attestations[role] = self.keys.attestation(role, payload)
        self.reject(lambda: verify_evidence(p, fx.plan, fx.registry, broken, attestations, now=NOW))

    def test_expiry_checked_again_at_consumption(self):
        self.fx.advance()
        self.fx.now = NOW + 301
        self.reject(lambda: self.fx.backend.authorized(self.fx.attempt, self.fx.approval))

    def test_oidc_alone_is_not_approval(self):
        self.fx.advance()
        self.reject(lambda: self.fx.backend.authorized(self.fx.attempt, self.fx.workload))

    def test_wrong_approval_key_pin(self):
        args = dict(self.fx.approval_args, approval_key_sha256="0" * 64)
        self.reject(lambda: verify_protected(self.fx.proposal, self.fx.attempt, self.fx.evidence, self.fx.workload, **args))

    def test_wrong_witness_key_pin(self):
        args = dict(self.fx.approval_args, witness_key_sha256=self.keys.signers["approval"].key_sha256)
        self.reject(lambda: verify_protected(self.fx.proposal, self.fx.attempt, self.fx.evidence, self.fx.workload, **args))

    def test_unauthorized_reviewer(self):
        args = dict(self.fx.approval_args, allowed_reviewer_ids={"999"})
        self.reject(lambda: verify_protected(self.fx.proposal, self.fx.attempt, self.fx.evidence, self.fx.workload, **args))

    def test_replayed_jti_consumption(self):
        self.fx.advance("AUTHORIZED")
        fx = Fixture(self.keys, attempt="attempt-2")
        self.addCleanup(fx.close)
        fx.backend, fx.ledger = self.fx.backend, self.fx.ledger
        fx.workload = self.keys.workload(self.fx.attempt)
        args = fx.approval_inputs()
        fx.approval = verify_protected(fx.proposal, fx.attempt, fx.evidence, fx.workload, **args)
        fx.advance()
        self.reject(lambda: fx.backend.authorized(fx.attempt, fx.approval))

    def test_concurrent_base_publication_conflict(self):
        fx = Fixture(self.keys, attempt="attempt-2", version="0.2.6")
        self.addCleanup(fx.close)
        fx.backend, fx.ledger = self.fx.backend, self.fx.ledger
        self.fx.advance("AUTHORIZED")
        fx.advance("AUTHORIZED")
        self.fx.stage()
        fx.stage()
        self.fx.backend.publish(self.fx.attempt, self.fx.approval)
        self.reject(lambda: fx.backend.publish(fx.attempt, fx.approval))

    def test_published_does_not_mean_remotely_post_verified(self):
        self.fx.advance("AUTHORIZED")
        self.fx.stage()
        self.fx.backend.publish(self.fx.attempt, self.fx.approval)
        status = self.fx.ledger.inspect(self.fx.attempt)
        self.assertIsNone(status["head"]["last_verified"])
        self.assertEqual(status["attempt"]["state"], "PUBLISHED")
        self.fx.backend.fail(self.fx.attempt, "CDN post-verification failed")
        status = self.fx.ledger.inspect(self.fx.attempt)
        self.assertEqual(status["head"]["digest"], self.fx.result.sha256)
        self.assertTrue(status["attempt"]["failure"]["needs_fresh_recovery"])
        self.reject(lambda: self.fx.backend.post_verified(self.fx.attempt, self.fx.remote))

    def test_unverified_recovery_rejected(self):
        fx = Fixture(self.keys, attempt="recover-1", operation="recover")
        self.addCleanup(fx.close)
        self.reject(lambda: fx.backend.create(fx.proposal, fx.plan, fx.registry, fx.attempt, operation="recover"))

    def test_fresh_signed_recovery_preserves_history(self):
        self.fx.complete()
        old = self.fx.result.sha256
        newer = Fixture(self.keys, attempt="upgrade-2", version="0.2.6", previous=snapshot("repo-f44-20261011-099", assist()), previous_digest=old)
        self.addCleanup(newer.close)
        newer.backend, newer.ledger = self.fx.backend, self.fx.ledger
        newer.complete()
        recovery = Fixture(self.keys, attempt="recover-3", result_source=self.fx.source,
                           previous=snapshot("repo-f44-20261011-099", assist()), previous_digest=newer.result.sha256,
                           operation="recover")
        self.addCleanup(recovery.close)
        recovery.backend, recovery.ledger = self.fx.backend, self.fx.ledger
        recovery.advance()
        self.reject(lambda: recovery.backend.authorized(recovery.attempt, self.fx.approval))
        recovery.backend.authorized(recovery.attempt, recovery.approval)
        recovery.stage()
        recovery.backend.publish(recovery.attempt, recovery.approval)
        recovery.remote = recovery.verify_post()
        recovery.backend.post_verified(recovery.attempt, recovery.remote)
        self.assertEqual(self.fx.ledger.inspect()["head"]["last_verified"], old)
        self.assertEqual(self.fx.ledger.inspect()["head"]["generation"], 3)
        with self.fx.ledger.adapter.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM views").fetchone()[0], 2)

    def test_after_stage_rename_can_resume_exact_envelope(self):
        self.fx.advance("AUTHORIZED")
        store = IsolatedStore(self.fx.root)
        def crash(stage):
            if stage == "after-stage-rename":
                raise RuntimeError("crash")
        with self.assertRaises(RuntimeError):
            store.stage(self.fx.result, self.fx.approval, self.keys.signers["publication"], origin="https://test.invalid", audit_key_sha256=self.keys.signers["audit"].key_sha256, now=NOW, inject=crash)
        view = store.reopen(self.fx.result, self.fx.approval, self.keys.signers["publication"], now=NOW)
        self.fx.backend.signed(self.fx.attempt, view)
        self.assertIsNone(self.fx.ledger.inspect()["head"]["digest"])

    def test_remote_corruption_cannot_advance(self):
        self.fx.advance("AUTHORIZED")
        self.fx.stage()
        class Corrupt(DirectoryReader):
            def read(self, path):
                return b"mixed deployment bytes"
        self.reject(lambda: verify_remote(self.fx.view, Corrupt(self.fx.view), self.fx.deployment, now=NOW))

    def test_remote_partial_upload_cannot_advance(self):
        self.fx.advance("AUTHORIZED")
        self.fx.stage()
        class Missing(DirectoryReader):
            def read(self, path):
                raise FileNotFoundError(path)
        self.reject(lambda: verify_remote(self.fx.view, Missing(self.fx.view), self.fx.deployment, now=NOW))

    def test_unexpected_remote_member_rejected(self):
        self.fx.advance("AUTHORIZED")
        self.fx.stage()
        (self.fx.view.path / "payload" / "evil.rpm").write_bytes(b"unexpected")
        self.reject(lambda: verify_remote(self.fx.view, DirectoryReader(self.fx.view), self.fx.deployment, now=NOW))

    def test_audit_signature_detects_full_chain_rewrite(self):
        self.fx.advance()
        with self.fx.ledger.adapter.transaction() as db:
            seq, raw = db.execute("SELECT seq,body FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            event = strict_json(raw)
            event["operation"] = "authorized-by-attacker"
            db.execute("UPDATE events SET body=? WHERE seq=?", (canonical(event).decode(), seq))
        self.reject(lambda: self.fx.ledger.inspect())

    def test_consumed_ledger_tampering_detected(self):
        self.fx.advance("AUTHORIZED")
        with self.fx.ledger.adapter.transaction() as db:
            db.execute("DELETE FROM consumed")
        self.reject(lambda: self.fx.ledger.inspect())

    def test_missing_stable_head_cannot_be_resigned_as_initialization(self):
        self.fx.advance("AUTHORIZED")
        with self.fx.ledger.adapter.transaction() as db:
            db.execute("DELETE FROM head")
        self.reject(lambda: Ledger(self.fx.ledger.adapter, self.keys.signers["audit"],
                    audit_key=self.keys.signers["audit"].public, audit_key_sha256=self.keys.signers["audit"].key_sha256,
                    clock=lambda: NOW))

    def test_partial_schema_cannot_be_silently_repaired_and_resigned(self):
        with self.fx.ledger.adapter.transaction() as db:
            db.execute("DROP TABLE consumed")
        self.reject(lambda: Ledger(self.fx.ledger.adapter, self.keys.signers["audit"],
                    audit_key=self.keys.signers["audit"].public, audit_key_sha256=self.keys.signers["audit"].key_sha256,
                    clock=lambda: NOW))

    def test_independent_checkpoint_detects_valid_old_database(self):
        old = self.fx.ledger.inspect()["checkpoint"]
        self.fx.advance()
        recent = self.fx.ledger.inspect()["checkpoint"]
        with self.fx.ledger.adapter.transaction() as db:
            db.execute("DELETE FROM attempts")
            db.execute("DELETE FROM events WHERE seq>?", (old["seq"],))
        self.fx.ledger.inspect()  # A valid signed old state alone cannot reveal rollback.
        self.reject(lambda: self.fx.ledger.inspect(checkpoint=recent))

    def test_live_database_adapter_is_unreachable(self):
        self.reject(lambda: PostgreSQLAdapter(host="production.invalid", port=5432, dbname="stable", user="x", password="x"))

    def test_no_production_publisher(self):
        self.reject(lambda: production_publish(publishable=True, approved=True))

    def test_https_immutable_urls_only(self):
        for url in ("http://repo.test", "https://user:password@repo.test", "https://repo.test/mutable", "https://repo.test?x=1"):
            self.reject(lambda: immutable_url(url, "a" * 64, "x86_64"))
        self.assertIn("/v3/views/" + "a" * 64, immutable_url("https://repo.test", "a" * 64, "aarch64"))

    def test_stage_symlink_attack(self):
        self.fx.advance("AUTHORIZED")
        (self.fx.root / "views").symlink_to(self.fx.source, target_is_directory=True)
        self.reject(lambda: IsolatedStore(self.fx.root))

    def test_strict_json_rejects_duplicate_and_nonfinite(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            self.reject(lambda: strict_json(raw))

    def test_transaction_crash_around_authorization_and_audit(self):
        self.fx.advance()
        for point in ("after-authorization-consumption", "before-audit", "after-audit"):
            def crash(stage):
                if stage == point:
                    raise RuntimeError(point)
            before = self.fx.ledger.inspect()
            with self.assertRaises(RuntimeError):
                self.fx.backend.authorized(self.fx.attempt, self.fx.approval, inject=crash)
            self.assertEqual(self.fx.ledger.inspect(), before)
        self.fx.backend.authorized(self.fx.attempt, self.fx.approval)

    def test_transaction_crash_around_advertisement(self):
        self.fx.advance("AUTHORIZED")
        self.fx.stage()
        for point in ("after-advertisement", "before-audit", "after-audit"):
            def crash(stage):
                if stage == point:
                    raise RuntimeError(point)
            before = self.fx.ledger.inspect()
            with self.assertRaises(RuntimeError):
                self.fx.backend.publish(self.fx.attempt, self.fx.approval, inject=crash)
            self.assertEqual(self.fx.ledger.inspect(), before)

    def test_independent_processes_share_one_cas_boundary(self):
        fx = Fixture(self.keys, attempt="runner-2", version="0.2.6")
        self.addCleanup(fx.close)
        fx.backend, fx.ledger = self.fx.backend, self.fx.ledger
        self.fx.advance("AUTHORIZED")
        fx.advance("AUTHORIZED")
        self.fx.stage()
        fx.stage()
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        def writer(fixture):
            try:
                fixture.backend.publish(fixture.attempt, fixture.approval)
                queue.put("published")
            except PlanningError:
                queue.put("conflict")
        processes = [context.Process(target=writer, args=(f,)) for f in (self.fx, fx)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(30)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sorted(queue.get(timeout=5) for _ in processes), ["conflict", "published"])
        self.assertEqual(self.fx.ledger.inspect()["head"]["generation"], 1)

    def test_process_death_rolls_back_authorization_and_audit(self):
        import os
        self.fx.advance()
        before = self.fx.ledger.inspect()
        def die(stage):
            if stage == "after-audit":
                os._exit(17)
        process = multiprocessing.get_context("fork").Process(target=lambda: self.fx.backend.authorized(self.fx.attempt, self.fx.approval, inject=die))
        process.start()
        process.join(30)
        self.assertEqual(process.exitcode, 17)
        self.assertEqual(self.fx.ledger.inspect(), before)
        self.fx.backend.authorized(self.fx.attempt, self.fx.approval)

    def test_pre_verification_cannot_substitute_post_verification(self):
        self.fx.advance("AUTHORIZED")
        self.fx.stage()
        self.fx.backend.publish(self.fx.attempt, self.fx.approval)
        self.reject(lambda: self.fx.backend.post_verified(self.fx.attempt, self.fx.remote))

    def test_remote_stable_advertisement_substitution_rejected(self):
        self.fx.complete()
        file = self.fx.view.path / "stable-advertisement.json"
        raw = strict_json(file.read_bytes())
        raw["payload"]["result_stable_sha256"] = "0" * 64
        file.write_bytes(canonical(raw))
        signer = self.keys.signers["publication"]
        self.reject(lambda: verify_remote(self.fx.view, DirectoryReader(self.fx.view), self.fx.deployment,
                    now=NOW, post_ledger=self.fx.ledger, advertisement_key=signer.public,
                    advertisement_key_sha256=signer.key_sha256))


def make_oidc_negative(field, bad):
    def test(self):
        raw, pins = self.keys.oidc(changes={field: bad})
        self.reject(lambda: verify_oidc(raw, self.keys.jwks, jwks_sha256=digest(self.keys.jwks), pins=pins, now=NOW, fetched_at=NOW))
    return test


for _field, _bad in {"iss": "https://evil.invalid", "aud": "other", "sub": "other", "repository": "attacker/repo", "repository_id": "1", "repository_owner_id": "2", "ref": "refs/pull/1/head", "sha": "b" * 40, "workflow_ref": "wrong", "workflow_sha": "b" * 40, "job_workflow_ref": "wrong", "job_workflow_sha": "b" * 40, "environment": "beta", "event_name": "pull_request", "runner_environment": "self-hosted", "actor_id": "999", "run_id": "99", "run_attempt": "2", "exp": NOW, "iat": NOW + 1, "nbf": NOW + 1, "jti": ""}.items():
    setattr(BackendTests, "test_oidc_reject_" + _field, make_oidc_negative(_field, _bad))


def make_skip_transition(target):
    def test(self):
        self.fx.advance("PROPOSED")
        self.reject(lambda: self.fx.backend._transition(self.fx.attempt, target, {}, lambda db, value: None))
    return test


for _state in STATES[2:]:
    setattr(BackendTests, "test_no_stage_skip_to_" + _state.lower(), make_skip_transition(_state))


def make_transition_crash(target):
    def test(self):
        real = self.fx.ledger.execute
        operation = "create-promote" if target == "PROPOSED" else target
        def execute(name, attempt, change, **kwargs):
            if name == operation:
                def crash(point):
                    if point == "after-audit":
                        raise RuntimeError("interrupted " + target)
                kwargs["inject"] = crash
            return real(name, attempt, change, **kwargs)
        with mock.patch.object(self.fx.ledger, "execute", side_effect=execute):
            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                self.fx.complete()
        status = self.fx.ledger.inspect(None if target == "PROPOSED" else self.fx.attempt)
        if target != "PROPOSED":
            self.assertEqual(status["attempt"]["state"], STATES[STATES.index(target) - 1])
        self.assertIsNone(status["head"]["last_verified"])
        self.assertEqual(status["head"]["generation"], 1 if target == "POST_VERIFIED" else 0)
    return test


for _state in STATES:
    setattr(BackendTests, "test_interrupted_transition_" + _state.lower(), make_transition_crash(_state))


if __name__ == "__main__":
    unittest.main()
