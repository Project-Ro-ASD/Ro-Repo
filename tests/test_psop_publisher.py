"""Real signatures, signed SQLite transactions and private Git CAS fault tests."""
import copy
import json
import pathlib
import sys
import threading
import subprocess
import os
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from psop_support import Fixture
from psop_authorization import verify_approval
from psop_context import Context
from psop_ledger import Ledger
from psop_storage_gateway import Gateway
from psop_signing import MetadataSigner
from v3_promotion_planner import PlanningError
from v3_backend_trust import canonical, digest
from ro_repo import ContractError


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.close)

    def test_local_git_publication_and_restart_idempotence(self):
        j = self.fx.job()
        self.fx.gateway.admit(j.prepared, j.approval)
        result = self.fx.gateway.apply(j.attempt)
        self.assertEqual(result["status"], "COMPLETE")
        self.assertFalse(result["publishable"])
        self.fx.reopen()
        self.assertEqual(self.fx.gateway.apply(j.attempt), result)
        self.assertEqual(self.fx.gateway._store.head(), j.prepared.data["target_git"])

    def test_nonce_consumption_and_enqueue_roll_back_together(self):
        j = self.fx.job()
        def crash(at):
            if at == "after-audit":
                raise RuntimeError("crash before commit")
        with self.assertRaises(RuntimeError):
            self.fx.gateway.admit(j.prepared, j.approval, inject=crash)
        self.fx.reopen()
        with self.fx.ledger.adapter.transaction() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM consumed").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM attempts").fetchone()[0], 0)
        self.fx.gateway.admit(j.prepared, j.approval)

    def test_consumed_nonce_cannot_be_reused_for_new_attempt_after_restart(self):
        j = self.fx.job()
        self.fx.gateway.admit(j.prepared, j.approval)
        self.fx.gateway.apply(j.attempt)
        self.fx.reopen()
        another = self.fx.job(nonce=j.nonce, previous=j.prepared.data["result_sha256"])
        with self.assertRaisesRegex(PlanningError, "replay"):
            self.fx.gateway.admit(another.prepared, another.approval)

    def test_expired_wrong_result_wrong_identity_and_approved_boolean_rejected(self):
        j = self.fx.job(expiry=1)
        self.fx.now += 1
        with self.assertRaises(PlanningError):
            self.fx.gateway.admit(j.prepared, j.approval)
        with self.assertRaises((PlanningError, ContractError)):
            verify_approval(canonical({"approved": True}), self.fx.identity, j.review, self.fx.policy,
                            self.fx.now, context=self.fx.context)
        body = copy.deepcopy(j.body)
        body["review"]["result_sha256"] = "f" * 64
        raw = self.fx.context.envelope("approval", body, now=self.fx.now)
        with self.assertRaises(PlanningError):
            verify_approval(raw, self.fx.identity, j.review, self.fx.policy, self.fx.now, context=self.fx.context)

    def test_v1_v2_v3_domains_and_unknown_fields_cannot_grant_authority(self):
        j = self.fx.job()
        for domain in ("ro-repo-v3-backend-1", "publication-v1", "v1", "psop-production"):
            raw = json.loads(j.raw)
            raw["domain"] = domain
            with self.subTest(domain=domain), self.assertRaises(PlanningError):
                verify_approval(canonical(raw), self.fx.identity, j.review, self.fx.policy, self.fx.now, context=self.fx.context)
        body = {**j.body, "allow_production": True}
        with self.assertRaises((PlanningError, ContractError)):
            verify_approval(self.fx.context.envelope("approval", body, now=self.fx.now), self.fx.identity,
                            j.review, self.fx.policy, self.fx.now, context=self.fx.context)

    def test_wrong_role_signature_rejected(self):
        j = self.fx.job()
        raw = self.fx.context.envelope("source", j.body, now=self.fx.now)
        with self.assertRaises(PlanningError):
            verify_approval(raw, self.fx.identity, j.review, self.fx.policy, self.fx.now, context=self.fx.context)

    def test_all_simulated_writers_share_pending_realm(self):
        first = self.fx.job(writer="v2-snapshot")
        self.fx.gateway.admit(first.prepared, first.approval)
        for writer in ("psop-stable", "v2-beta", "v2-rollback", "v2-stable"):
            later = self.fx.job(writer=writer)
            with self.subTest(writer=writer), self.assertRaisesRegex(PlanningError, "realm"):
                self.fx.gateway.admit(later.prepared, later.approval)

    def test_two_independent_gateway_instances_have_one_admission_winner(self):
        one, two = self.fx.job(writer="v2-beta"), self.fx.job()
        context = Context(self.fx.context.root, self.fx.context.pin)
        other = Gateway(Ledger(context, clock=lambda: self.fx.now), context)
        barrier = threading.Barrier(2)
        def enter(gateway, job):
            barrier.wait(timeout=10)
            try:
                gateway.admit(job.prepared, job.approval)
                return True
            except PlanningError:
                return False
        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(enter, g, j) for g, j in [(self.fx.gateway, one), (other, two)]]
            self.assertEqual(sorted(f.result() for f in futures), [False, True])

    def test_lost_response_reconciles_exact_target_after_restart_without_cas_retry(self):
        j = self.fx.job()
        self.fx.gateway.admit(j.prepared, j.approval)
        def loss(at):
            if at == "after-git-cas":
                raise OSError("lost provider response")
        with self.assertRaises(OSError):
            self.fx.gateway.apply(j.attempt, inject=loss)
        self.fx.reopen()
        self.assertEqual(self.fx.gateway.receipt(j.attempt)["status"], "UNKNOWN")
        with self.assertRaises(PlanningError):
            self.fx.gateway.apply(j.attempt)
        self.assertEqual(self.fx.gateway.reconcile(j.attempt)["status"], "COMPLETE")

    def test_base_head_and_timeout_do_not_resolve_unknown(self):
        j = self.fx.job()
        self.fx.gateway.admit(j.prepared, j.approval)
        def crash(at):
            raise RuntimeError("crash before provider")
        with self.assertRaises(RuntimeError):
            self.fx.gateway.apply(j.attempt, inject=crash)
        self.fx.now += 1000
        self.fx.reopen()
        with self.assertRaises(PlanningError):
            self.fx.gateway.reconcile(j.attempt)
        later = self.fx.job(writer="v2-rollback")
        with self.assertRaises(PlanningError):
            self.fx.gateway.admit(later.prepared, later.approval)
        self.assertEqual(self.fx.gateway.receipt(j.attempt)["status"], "UNKNOWN")

    def test_late_admitted_cas_never_claims_deadline_fence_or_advances_stable(self):
        j = self.fx.job(expiry=1)
        self.fx.gateway.admit(j.prepared, j.approval)
        def delayed(at):
            if at == "after-durable-intent":
                self.fx.now += 2
        r = self.fx.gateway.apply(j.attempt, inject=delayed)
        self.assertEqual(r["status"], "COMMITTED_EXPIRED")
        self.assertIsNone(self.fx.ledger.inspect()["head"]["digest"])
        self.assertEqual(r["provider_deadline_fencing"], "UNVERIFIED")

    def test_independent_local_drain_fences_late_request_and_allows_abort(self):
        j = self.fx.job()
        self.fx.gateway.admit(j.prepared, j.approval)
        with self.assertRaises(RuntimeError):
            self.fx.gateway.apply(j.attempt, inject=lambda at: (_ for _ in ()).throw(RuntimeError("crash")))
        state = self.fx.ledger.inspect(j.attempt)
        binding = state["attempt"]["proofs"]["OUTBOX"]["receipts"]["provider_intent"]["binding"]
        raw = self.fx.gateway._store.drain(binding, state["checkpoint"], now=self.fx.now)
        self.assertEqual(self.fx.gateway.abort_noncommit(j.attempt, raw)["status"], "ABORTED")
        with self.assertRaisesRegex(PlanningError, "fenced"):
            self.fx.gateway._store.apply(j.prepared.data)

    def test_unexpected_head_and_altered_payload_cannot_reconcile(self):
        j = self.fx.job()
        self.fx.gateway.admit(j.prepared, j.approval)
        self.fx.gateway._store._cas({"unexpected": b"not target"}, None)
        with self.assertRaises(PlanningError):
            self.fx.gateway.apply(j.attempt)
        with self.assertRaises(PlanningError):
            self.fx.gateway.reconcile(j.attempt)

    def test_previous_beta_snapshot_history_blobs_preserved(self):
        markers = {"rpm/fedora/44/beta/payload": b"beta", "snapshots/fedora/44/old/file": b"snapshot",
                   "publications/fedora/44/beta/1.json": b"history"}
        before = self.fx.gateway._store._cas(markers, None)
        old = self.fx.gateway._store._files(before)
        j = self.fx.job()
        self.fx.gateway.admit(j.prepared, j.approval)
        self.fx.gateway.apply(j.attempt)
        new = self.fx.gateway._store._files(self.fx.gateway._store.head())
        self.assertTrue(all(new[k] == v for k, v in old.items()))

    def test_production_ref_repository_origin_and_issuer_rejected(self):
        path = self.fx.context.root / "psop-context.json"
        original = path.read_bytes()
        for field, value in (("repository", "Project-Ro-ASD/Ro-Repo"), ("ref", "refs/heads/pages-storage"),
                             ("origin", "https://repo.ro-asd.org")):
            d = json.loads(original); d[field] = value; raw = canonical(d); path.write_bytes(raw)
            with self.subTest(field=field), self.assertRaises(PlanningError):
                Context(self.fx.context.root, digest(raw))
        path.write_bytes(original)
        j = self.fx.job()
        identity = {**self.fx.identity, "issuer": "https://token.actions.githubusercontent.com"}
        with self.assertRaises(PlanningError):
            verify_approval(j.raw, identity, j.review, self.fx.policy, self.fx.now, context=self.fx.context)

    def test_remote_credential_helper_alternates_and_hooks_are_rejected(self):
        root = self.fx.gateway._store.git
        config = root / "config"
        old = config.read_bytes()
        for text in ('\n[remote "origin"]\nurl=https://github.com/Project-Ro-ASD/Ro-Repo\n',
                     '\n[credential]\nhelper=malicious\n', '\n[include]\npath=/tmp/evil\n'):
            config.write_bytes(old + text.encode())
            with self.assertRaises(PlanningError):
                self.fx.gateway._store.check()
        config.write_bytes(old)
        hook = root / "hooks/reference-transaction"
        hook.write_text("exit 0")
        with self.assertRaises(PlanningError):
            self.fx.gateway._store.check()

    def test_old_receipt_and_bytes_stay_fixed_after_next_publication(self):
        first = self.fx.job()
        self.fx.gateway.admit(first.prepared, first.approval)
        receipt = self.fx.gateway.apply(first.attempt)
        second = self.fx.job(previous=first.prepared.data["result_sha256"])
        self.fx.gateway.admit(second.prepared, second.approval)
        self.fx.gateway.apply(second.attempt)
        self.fx.reopen()
        self.assertEqual(self.fx.gateway.apply(first.attempt), receipt)

    def test_process_death_before_and_after_cas_retains_durable_unknown(self):
        for boundary in ("after-durable-intent", "after-git-cas"):
            fx = Fixture()
            try:
                job = fx.job()
                fx.gateway.admit(job.prepared, job.approval)
                code = '''import os,sys
from psop_context import Context
from psop_ledger import Ledger
from psop_storage_gateway import Gateway
c=Context(sys.argv[1],sys.argv[2]);g=Gateway(Ledger(c,clock=lambda:int(sys.argv[5])),c)
def kill(at):
 if at==sys.argv[4]: os._exit(87)
g.apply(sys.argv[3],inject=kill)
'''
                env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(pathlib.Path(__file__).parents[1] / "tools")}
                result = subprocess.run([sys.executable, "-c", code, str(fx.context.root), fx.context.pin,
                                         job.attempt, boundary, str(fx.now)], env=env, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 87, result.stderr.decode())
                fx.reopen()
                self.assertEqual(fx.gateway.receipt(job.attempt)["status"], "UNKNOWN")
                if boundary == "after-git-cas":
                    self.assertEqual(fx.gateway.reconcile(job.attempt)["status"], "COMPLETE")
                else:
                    with self.assertRaises(PlanningError):fx.gateway.reconcile(job.attempt)
            finally:
                fx.close()

    def test_missing_ledger_cannot_reinitialize_existing_storage(self):
        self.fx.ledger.adapter.path.unlink()
        with self.assertRaisesRegex(PlanningError, "reinitialization"):
            self.fx.reopen()

    def test_prepared_blob_hash_mismatch_is_rejected_before_cas(self):
        j = self.fx.job()
        p = j.prepared.data
        p["file_sha256"][next(iter(p["file_sha256"]))] = "f" * 64
        with self.assertRaises(PlanningError):
            self.fx.gateway._store.apply(p)
        self.assertIsNone(self.fx.gateway._store.head())
