"""Protocol acceptance with ephemeral identities and disposable writes only."""
import copy
import datetime as dt
import pathlib
import shutil
import sys
import threading
import unittest
import urllib.request
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_backend_support import Keys, Fixture, NOW
from v3_backend_trust import canonical, digest, strict_json, TestSigner, test_workspace
from v3_publication_backend import Backend
from v3_publication_outbox import Outbox, Coordinator, SimulatedDeployment
from v3_pages_backend import IsolatedGitStore
from v3_immutable_view import IsolatedStore, DirectoryReader, production_publish
from v3_independent_authority import LocalAuthority, AuthorityClient, CheckpointedLedger, server
from v3_identity_integration import lifecycle_oidc, verify_root_set, proposal_from_genesis
from v3_client_update import Client, discovery_payload
from v3_postgresql_production import ProductionPostgreSQLAdapter, provisioning_sql
from v3_promotion_planner import PlanningError
from v3_hardware_kit import collect


class ClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Keys()
        cls.checkpoint_signer = TestSigner(cls.keys.root, "checkpoint")

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    def setUp(self):
        self.fx = Fixture(self.keys)
        self.addCleanup(self.fx.close)

    def prepared(self):
        self.fx.advance("AUTHORIZED")
        self.view = IsolatedStore(self.fx.root).stage(self.fx.result, self.fx.approval, self.keys.signers["publication"],
            origin="https://test.invalid", audit_key_sha256=self.keys.signers["audit"].key_sha256, now=NOW)
        self.fx.backend.signed(self.fx.attempt, self.view)
        self.fx.backend.staged(self.fx.attempt, self.view)
        self.store = IsolatedGitStore(self.fx.root)
        self.coordinator = Coordinator(self.fx.backend, self.store, SimulatedDeployment(self.store, self.keys.attestation))
        self.outbox = self.coordinator.outbox
        self.outbox.enqueue(self.view, self.fx.approval, None)
        self.fence = self.outbox.claim(self.fx.attempt, "worker")

    def run_job(self, inject=lambda _: None, owner="worker", fence=None):
        return self.coordinator.run(self.view, self.fx.approval, self.keys.signers["publication"], owner=owner,
                                    fence=self.fence if fence is None else fence, inject=inject)

    def authority(self):
        root = test_workspace()
        self.addCleanup(shutil.rmtree, root)
        update = self.keys.signers["audit"]
        authority = LocalAuthority(root, self.checkpoint_signer, update.public, update.key_sha256, lambda: self.fx.now)
        authority.recovery_key = self.keys.signers["witness"].public
        authority.recovery_pin = self.keys.signers["witness"].key_sha256
        client = AuthorityClient(authority.exchange, public_key=self.checkpoint_signer.public,
            key_sha256=self.checkpoint_signer.key_sha256, clock=lambda: self.fx.now, updater=update)
        return authority, client

    def test_outbox_complete_and_durable_idempotence(self):
        self.prepared()
        receipt = self.run_job()
        self.assertEqual(receipt["attempt"]["state"], "POST_VERIFIED")
        self.assertEqual(receipt["attempt"]["proofs"]["OUTBOX"]["status"], "COMPLETE")
        self.assertEqual(self.run_job(), receipt)
        self.assertFalse(receipt["publishable"])

    def test_all_provider_response_loss_boundaries_reconcile(self):
        for boundary in ("after-git-stage", "after-pre-verification", "after-db-intent", "after-git-advertisement", "after-post-verification"):
            with self.subTest(boundary=boundary):
                if hasattr(self, "store"):
                    self.fx = Fixture(self.keys)
                    self.addCleanup(self.fx.close)
                self.prepared()
                def crash(at):
                    if at == boundary:
                        raise RuntimeError("simulated provider response loss")
                with self.assertRaises(RuntimeError):
                    self.run_job(crash)
                # A new coordinator reads durable state and actual Git bytes.
                self.coordinator = Coordinator(self.fx.backend, IsolatedGitStore(self.fx.root),
                    SimulatedDeployment(self.store, self.keys.attestation))
                self.assertEqual(self.run_job()["attempt"]["state"], "POST_VERIFIED")

    def test_outbox_rejects_concurrent_claim_and_stale_fence(self):
        self.prepared()
        with self.assertRaises(PlanningError):
            self.outbox.claim(self.fx.attempt, "other")
        self.fx.now += 31
        fence = self.outbox.claim(self.fx.attempt, "other")
        with self.assertRaises(PlanningError):
            self.run_job()
        self.assertEqual(self.run_job(owner="other", fence=fence)["attempt"]["state"], "POST_VERIFIED")

    def test_outbox_rejects_conflicting_immutable_enqueue(self):
        self.prepared()
        with self.assertRaises(PlanningError):
            self.outbox.enqueue(self.view, self.fx.approval, "a" * 40)

    def test_expired_authority_and_deployment_failure_cannot_complete(self):
        self.prepared()
        with patch.object(self.coordinator.deployment, "verify", side_effect=PlanningError("deployment failed")):
            with self.assertRaises(PlanningError):
                self.run_job()
        self.assertEqual(self.fx.ledger.inspect(self.fx.attempt)["attempt"]["state"], "STAGED")
        self.fx.now += 301
        with self.assertRaises(PlanningError):
            self.outbox.claim(self.fx.attempt, "new-worker")

    def test_checkpoint_missing_and_restore_rollback_rejected(self):
        authority, client = self.authority()
        with self.assertRaises(PlanningError):
            CheckpointedLedger(self.fx.ledger, client, "test")
        initial = self.fx.ledger.inspect()["checkpoint"]
        client.advance("checkpoint/test", None, initial)
        guarded = CheckpointedLedger(self.fx.ledger, client, "test")
        backup = self.fx.ledger.adapter.path.read_bytes()
        self.fx.backend = Backend(guarded)
        self.fx.advance("AUTHORIZED")
        newest = client.read("checkpoint/test")
        self.assertGreater(newest["seq"], initial["seq"])
        self.fx.ledger.adapter.path.write_bytes(backup)
        with self.assertRaises(PlanningError):
            guarded.inspect()
        with self.assertRaises(PlanningError):
            client.advance("checkpoint/test", newest, initial)

    def test_checkpoint_response_loss_reconciles_after_commit(self):
        authority, client = self.authority()
        client.advance("checkpoint/test", None, self.fx.ledger.inspect()["checkpoint"])
        guarded = CheckpointedLedger(self.fx.ledger, client, "test")
        self.fx.backend = Backend(guarded)
        original = client.advance
        def lost(*args):
            result = original(*args)
            if args[0].startswith("checkpoint/"):
                raise OSError("response lost")
            return result
        with patch.object(client, "advance", side_effect=lost):
            with self.assertRaises(OSError):
                self.fx.advance("PROPOSED")
        guarded.reconcile()
        self.fx.advance("PROPOSED")
        self.assertEqual(guarded.inspect()["checkpoint"], client.read("checkpoint/test"))

    def test_precommit_reservation_crash_requires_independent_abort(self):
        authority, client = self.authority()
        client.advance("checkpoint/test", None, self.fx.ledger.inspect()["checkpoint"])
        guarded = CheckpointedLedger(self.fx.ledger, client, "test")
        self.fx.backend = Backend(guarded)
        original = client.advance
        def lost_prepare(*args):
            result = original(*args)
            if args[0].startswith("reservation/"):
                raise OSError("prepare response lost before DB commit")
            return result
        with patch.object(client, "advance", side_effect=lost_prepare):
            with self.assertRaises(OSError):
                self.fx.advance("PROPOSED")
        with self.assertRaises(PlanningError):
            guarded.inspect()
        pending = client.read("reservation/test")
        expected = {"reservation": "reservation/test", "base": pending["base"], "target": pending["target"],
                    "transaction_not_committed": True, "writers_fenced": True, "logs_sha256": "a"*64,
                    "issued_at": NOW, "expires_at": NOW+60}
        bad = self.keys.signers["audit"].envelope("restore-observation", expected)
        with self.assertRaises(PlanningError):
            guarded.reconcile_abort(bad)
        raw = self.keys.signers["witness"].envelope("restore-observation", expected)
        guarded.reconcile_abort(raw)
        self.fx.advance("PROPOSED")
        self.assertEqual(guarded.inspect()["checkpoint"], client.read("checkpoint/test"))

    def test_committed_reservation_cannot_be_lost_by_restoring_old_db(self):
        authority, client = self.authority()
        client.advance("checkpoint/test", None, self.fx.ledger.inspect()["checkpoint"])
        guarded = CheckpointedLedger(self.fx.ledger, client, "test")
        self.fx.backend = Backend(guarded)
        saved = self.fx.ledger.adapter.path.read_bytes()
        with patch.object(guarded, "reconcile", side_effect=[None, OSError("crash after DB commit")]):
            with self.assertRaises(OSError):
                self.fx.advance("PROPOSED")
        self.fx.ledger.adapter.path.write_bytes(saved)
        with self.assertRaises(PlanningError):
            guarded.inspect()

    def test_signed_checkpoint_replay_and_compromised_signature_rejected(self):
        authority, client = self.authority()
        cached = authority.exchange({"name": "checkpoint/test", "nonce": "a" * 64, "update": None})
        with patch.object(client, "exchange", return_value=cached):
            with self.assertRaises(PlanningError):
                client.read("checkpoint/test")
        wrong = AuthorityClient(authority.exchange, public_key=self.keys.signers["witness"].public,
            key_sha256=self.keys.signers["witness"].key_sha256, clock=lambda: NOW)
        with self.assertRaises(PlanningError):
            wrong.read("checkpoint/test")

    def test_reproducible_independent_http_service(self):
        authority, client = self.authority()
        http = server(authority)
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        thread.start()
        try:
            def exchange(request):
                req = urllib.request.Request("http://127.0.0.1:" + str(http.server_port) + "/v1/exchange", data=canonical(request))
                with urllib.request.urlopen(req, timeout=3) as response:
                    return response.read()
            client.exchange = exchange
            tip = self.fx.ledger.inspect()["checkpoint"]
            self.assertEqual(client.advance("checkpoint/http", None, tip), tip)
            self.assertEqual(client.read("checkpoint/http"), tip)
        finally:
            http.shutdown()
            thread.join(3)
            http.server_close()

    def test_fresh_genesis_zero_dwell_and_no_backdating(self):
        authority, client = self.authority()
        p = self.fx.proposal
        row = {"candidate_sha256": p["candidate_sha256"], "promotion_group": p["promotion_group"],
            "publication_run": "101", "availability_sha256": "a" * 64, "published_at": "2026-10-11T12:00:00Z"}
        name = "history/" + p["candidate_sha256"]
        old = dict(row, published_at="2026-10-01T12:00:00Z")
        with self.assertRaises(PlanningError):
            client.advance(name, None, old)
        client.advance(name, None, row)
        actual = proposal_from_genesis(client, self.fx.plan, self.fx.registry, p["candidate_identity"]["source_provenance"],
            availability_sha256="a" * 64, now=row["published_at"], result_sha256=p["result_stable_sha256"])
        self.assertFalse(actual["dwell_met"])
        from v3_authorization import request
        with self.assertRaises(PlanningError):
            request(actual, "fresh-genesis")
        with self.assertRaises(PlanningError):
            client.advance(name, row, row)
        later = proposal_from_genesis(client, self.fx.plan, self.fx.registry, p["candidate_identity"]["source_provenance"],
            availability_sha256="a" * 64, now="2026-10-18T12:00:00Z", result_sha256=p["result_stable_sha256"])
        self.assertTrue(later["dwell_met"])

    def test_jwks_lifecycle_revocation_expiry_and_epoch(self):
        raw, pins = self.keys.oidc()
        expected = {"issuer": "https://token.actions.githubusercontent.com", "jwks_sha256": digest(self.keys.jwks),
            "epoch": 2, "fetched_at": NOW, "revoked_kids": []}
        lifecycle = self.keys.attestation("jwks-lifecycle", expected)
        self.assertEqual(lifecycle_oidc(raw, self.keys.jwks, lifecycle, pins=pins, now=NOW, minimum_epoch=2).claims["actor_id"], "123")
        for mutation, clock, epoch in (({"revoked_kids": ["test-key"]}, NOW, 2), ({}, NOW + 501, 2), ({}, NOW, 3), ({"fetched_at": NOW-3601}, NOW, 2)):
            att = self.keys.attestation("jwks-lifecycle", {**expected, **mutation})
            with self.assertRaises(PlanningError):
                lifecycle_oidc(raw, self.keys.jwks, att, pins=pins, now=clock, minimum_epoch=epoch)

    def test_production_guard_missing_roots_and_invalid_config(self):
        with self.assertRaises(PlanningError):
            verify_root_set({})
        with self.assertRaises(PlanningError):
            ProductionPostgreSQLAdapter({}, password="test")
        ca = self.fx.root / "ca.pem"
        ca.write_text("test CA; no real network connection")
        config = dict(host="db.invalid", port=5432, dbname="ro_v3", user="ro_v3_writer", schema="ro_v3",
            sslrootcert=str(ca), sslrootcert_sha256=digest(ca.read_bytes()), application_name="ro_v3")
        adapter = ProductionPostgreSQLAdapter(config, password="disposable")
        with self.assertRaises(PlanningError):
            with adapter.transaction():
                self.fail("production connected")
        for key, value in (("user", "postgres"), ("sslrootcert_sha256", "0"*64), ("host", "db.invalid,attacker.invalid"), ("port", True)):
            with self.assertRaises(PlanningError):
                ProductionPostgreSQLAdapter({**config, key: value}, password="test")
        with self.assertRaises(PlanningError):
            production_publish()
        self.assertNotIn("DELETE", provisioning_sql())

    def client(self):
        self.prepared()
        self.run_job()
        sign = self.keys.signers["publication"]
        client = Client(self.fx.root, origin="https://test.invalid", discovery_key=self.checkpoint_signer.public,
            discovery_pin=self.checkpoint_signer.key_sha256, publication_key=sign.public, publication_pin=sign.key_sha256,
            rpm_key_url="file:///test/rpm.asc", metadata_key_url="file:///test/metadata.asc", clock=lambda: self.fx.now)
        def discovery(nonce, mutation=None):
            payload = discovery_payload(self.fx.ledger, self.view, nonce, origin="https://test.invalid")
            payload.update(mutation or {})
            return self.checkpoint_signer.envelope("client-discovery", {**payload, "issued_at": self.fx.now, "expires_at": self.fx.now + 60})
        reader = lambda *args: DirectoryReader(self.view)
        return client, discovery, reader

    def test_client_verified_discovery_after_publication_expiry(self):
        client, discovery, reader = self.client()
        self.fx.now += 400
        result = client.update(discovery, reader_factory=reader)
        self.assertEqual(result["view_verification"], "PASS")
        config = (self.fx.root / "repos/ro-stable-v3.repo").read_text()
        self.assertIn(self.view.sha256, config)
        self.assertIn("repo_gpgcheck=1", config)
        self.assertIn("gpgcheck=1", config)

    def test_client_wrong_nonce_mixed_view_and_bad_signature_rejected(self):
        client, discovery, reader = self.client()
        with self.assertRaises(PlanningError):
            client.update(lambda nonce: discovery("a" * 64), reader_factory=reader)
        cached = discovery("b" * 64)
        with self.assertRaises(PlanningError):
            client.update(lambda nonce: cached, reader_factory=reader)
        with patch.object(DirectoryReader, "read", return_value=b"corrupt"):
            with self.assertRaises(PlanningError):
                client.update(discovery, reader_factory=reader)
        client.discovery_pin = "0" * 64
        with self.assertRaises(PlanningError):
            client.update(discovery, reader_factory=reader)

    def test_client_generation_and_checkpoint_rollback_rejected(self):
        client, discovery, reader = self.client()
        client.update(discovery, reader_factory=reader)
        with self.assertRaises(PlanningError):
            client.update(lambda nonce: discovery(nonce, {"checkpoint": {"seq": 1, "sha256": "a" * 64}}), reader_factory=reader)
        state = self.fx.root / "client-state.json"
        old = strict_json(state.read_bytes())
        old["generation"] = 2
        state.write_bytes(canonical(old))
        with self.assertRaises(PlanningError):
            client.update(discovery, reader_factory=reader)

    def test_client_cannot_disable_checks_or_write_host_installroot(self):
        client, discovery, reader = self.client()
        for command in (["rm", "-rf", "/"], ["dnf5", "--installroot=/", "upgrade"],
                        ["dnf5", "--installroot=" + str(self.fx.root / "root"), "--no-gpgchecks", "upgrade"],
                        ["dnf5", "--installroot=" + str(self.fx.root / "root"), "--setopt=ro-stable-v3.repo_gpgcheck=0", "upgrade"]):
            with self.assertRaises(PlanningError):
                client.update(discovery, reader_factory=reader, command=command)

    def test_hardware_collection_never_invents_pass(self):
        output = self.fx.root / "hardware"
        class Result:
            returncode, stdout, stderr = 0, b"observed", b""
        report = collect(output, environment="emulated-aarch64", run=lambda *args, **kwargs: Result())
        self.assertEqual({x["result"] for x in report["cases"].values()}, {"UNVERIFIED"})
        self.assertFalse(report["publishable"])
        with self.assertRaises(PlanningError):
            collect(output, environment="emulated-aarch64")


if __name__ == "__main__":
    unittest.main()
