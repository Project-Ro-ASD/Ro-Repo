import concurrent.futures
import pathlib
import ssl
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_backend_support import Keys, Fixture, NOW
from v3_backend_trust import TestSigner, canonical, digest, strict_json
from v3_backend_ledger import DDL, Ledger, SQLiteAdapter
from v3_bootstrap_provider import (observe_empty, authorize_empty, initialize_empty,
                                   interrupted_first_publication, import_existing)
from v3_github_provider import GitHubStorage, GitHubPages
from v3_immutable_view import DirectoryReader, IsolatedStore
from v3_independent_authority import LocalAuthority
from v3_protected_provider import (ProtectedSigner, IndependentDeployment, authority_client,
                                   workload_from_services, protected_authorization)
from v3_provider_transport import ProviderTransport, ProviderUnavailable, ProviderHTTPError
from v3_publication_outbox import Coordinator, SimulatedDeployment, Outbox
from v3_promotion_planner import PlanningError
from v3_provider_support import ProtocolServer


class LiveProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Keys()
        cls.storage_key = TestSigner(cls.keys.root, "storage-observer")
        cls.https_key = TestSigner(cls.keys.root, "https-observer")

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    def setUp(self):
        self.fx = Fixture(self.keys)
        self.addCleanup(self.fx.close)
        self.server = ProtocolServer(self.fx, self.keys)
        self.addCleanup(self.server.close)
        self.pins = dict(repository="test/disposable", repository_id=123, node_id="R_test", ref="refs/heads/isolated-storage")
        self.storage = GitHubStorage.rehearsal(self.server.transport, root=self.fx.root, **self.pins)

    def view(self):
        self.fx.advance("AUTHORIZED")
        self.view_value = IsolatedStore(self.fx.root).stage(self.fx.result, self.fx.approval,
            self.keys.signers["publication"], origin="https://test.invalid",
            audit_key_sha256=self.keys.signers["audit"].key_sha256, now=self.fx.now)
        self.fx.backend.signed(self.fx.attempt, self.view_value)
        self.fx.backend.staged(self.fx.attempt, self.view_value)
        return self.view_value

    def stage(self, expected=None):
        signer = self.keys.signers["publication"]
        return self.storage.stage(self.view_value, self.fx.approval,
            expected=expected or self.server.initial, publication_key=signer.public,
            publication_pin=signer.key_sha256, now=self.fx.now)

    def test_authenticated_rest_objects_graphql_cas_preserve_signed_history(self):
        before = self.storage.files(self.server.initial)
        self.view()
        receipt = self.stage()
        after = self.storage.files(receipt["git_commit"])
        self.assertEqual({p: after[p] for p in before}, before)
        self.assertEqual(receipt["deployment"], "UNVERIFIED")
        self.assertFalse(receipt["publishable"])
        calls = [b for m, p, b in self.server.calls if p == "/graphql"]
        self.assertEqual(calls[0]["variables"]["input"]["refUpdates"][0]["beforeOid"], self.server.initial)
        self.assertEqual(self.stage()["git_commit"], receipt["git_commit"])
        self.assertEqual(self.stage(receipt["git_commit"]), receipt)

    def test_lost_cas_response_reconciles_after_client_restart(self):
        self.view()
        self.server.lose_cas = True
        with self.assertRaises(ProviderUnavailable):
            self.stage()
        committed = self.storage.head()
        self.storage = GitHubStorage.rehearsal(self.server.transport, root=self.fx.root, **self.pins)
        self.assertEqual(self.stage()["git_commit"], committed)

    def test_provider_cannot_substitute_staged_commit_parent(self):
        self.view()
        original = self.server.respond
        def substituted(method, path, body):
            status, response = original(method, path, body)
            if method == "GET" and "/git/commits/" in path and not path.endswith(self.server.initial):
                response = {**response, "parents": []}
            return status, response
        with patch.object(self.server, "respond", side_effect=substituted):
            with self.assertRaises(PlanningError):
                self.stage()
        self.assertEqual(self.storage.head(), self.server.initial)

    def test_simultaneous_different_publishers_have_one_git_cas_winner(self):
        self.view()
        before = self.storage.files(self.server.initial)
        other = Fixture(self.keys, attempt="publisher-two", version="0.2.6")
        self.addCleanup(other.close)
        other.advance("AUTHORIZED")
        signer = self.keys.signers["publication"]
        view = IsolatedStore(other.root).stage(other.result, other.approval, signer,
            origin="https://test.invalid", audit_key_sha256=self.keys.signers["audit"].key_sha256, now=NOW)
        # Both clients must finish building against the SAME HEAD before
        # either CAS is submitted; thread start timing alone proves no race.
        ready = threading.Barrier(2)
        def publish(v, approval):
            try:
                storage = GitHubStorage.rehearsal(self.server.transport, root=self.fx.root, **self.pins)
                storage.stage(v, approval, expected=self.server.initial, publication_key=signer.public,
                              publication_pin=signer.key_sha256, now=NOW,
                              before_cas=lambda old,new: ready.wait(timeout=10))
                return "won"
            except PlanningError:
                return "conflict"
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda args: publish(*args), [(self.view_value, self.fx.approval), (view, other.approval)]))
        self.assertEqual(sorted(results), ["conflict", "won"])
        updates = [b["variables"]["input"]["refUpdates"][0]
                   for m,p,b in self.server.calls if m == "POST" and p == "/graphql"]
        self.assertEqual(len(updates), 2)
        self.assertEqual({u["beforeOid"] for u in updates}, {self.server.initial})
        self.assertEqual(len({u["afterOid"] for u in updates}), 2)
        self.assertIn(self.storage.head(), {u["afterOid"] for u in updates})
        after = self.storage.files(self.storage.head())
        self.assertEqual({p: after[p] for p in before}, before)
        self.assertEqual(sum("v3/publications/" + v.descriptor["request"]["attempt_id"] + ".json" in after
                             for v in (self.view_value, view)), 1)

    def test_stale_git_head_and_immutable_replacement_are_rejected(self):
        self.view()
        self.stage()
        winner = self.server.store._cas({"new-history.asc": b"signed historical bytes"}, self.storage.head())
        with self.assertRaises(PlanningError):
            self.stage()
        self.assertEqual(self.storage.head(), winner)
        path = "v3/views/" + self.view_value.sha256 + "/test-payload"
        corrupt = self.server.store._run(["hash-object", "-w", "--stdin"], data=b"substitution").decode().strip()
        files = self.server.store._files(winner)
        files[path] = corrupt
        tree = self.server.store._tree(files)
        changed = self.server.store._run(["commit-tree", tree, "-p", winner], data=b"test corruption").decode().strip()
        self.server.store._run(["update-ref", "refs/heads/isolated-storage", changed, winner])
        with self.assertRaises(PlanningError):
            self.stage(changed)

    def test_truncation_repository_substitution_and_bad_blob_fail_closed(self):
        self.view()
        for attr, value in (("truncated", True), ("repo_id", 999), ("corrupt_blob", True)):
            with self.subTest(attr=attr):
                setattr(self.server, attr, value)
                with self.assertRaises(PlanningError):
                    self.stage()
                setattr(self.server, attr, False if attr != "repo_id" else 123)
        self.assertEqual(self.storage.head(), self.server.initial)

    def test_expired_signing_or_approval_cannot_stage(self):
        self.view()
        self.fx.now += 301
        with self.assertRaises(PlanningError):
            self.stage()
        self.assertEqual(self.storage.head(), self.server.initial)

    def test_delayed_staging_response_after_expiration_cannot_update_ref(self):
        self.view()
        original = self.server.respond
        def delayed(method, path, body):
            response = original(method, path, body)
            if path.endswith("/git/blobs") and method == "POST":
                self.fx.now += 301
            return response
        with patch.object(self.server, "respond", side_effect=delayed):
            with self.assertRaises(ProviderUnavailable):
                self.stage()
        self.assertEqual(self.storage.head(), self.server.initial)

    def test_transport_redirect_and_oversized_response_are_rejected(self):
        self.server.handlers["/redirect"] = lambda m,b: (302, {}, {"Location": "http://127.0.0.1:1/credential-target"})
        with self.assertRaises(PlanningError):
            self.server.transport.request("GET", "/redirect")
        self.assertFalse(any(path == "/credential-target" for _,path,_ in self.server.calls))
        self.server.handlers["/oversized"] = lambda m,b: (200, {"data": "x"*1024})
        self.server.transport.max_bytes = 128
        with self.assertRaises(PlanningError):
            self.server.transport.request("GET", "/oversized")

    def test_live_storage_and_pages_mutation_guards_do_not_contact_provider(self):
        transport = ProviderTransport("https://api.github.com", lambda: ("never-used", NOW + 30), lambda: NOW)
        live = GitHubStorage(transport, **self.pins)
        with patch.object(transport, "request", side_effect=AssertionError("live request")):
            for call in (lambda: live.stage(None, None, expected="a"*40, publication_key=b"", publication_pin="", now=NOW),
                         lambda: live.advertise(), lambda: GitHubPages(live).request(), lambda: import_existing()):
                with self.assertRaises(PlanningError):
                    call()

    def test_transport_expired_credential_tls_and_path_guards(self):
        bad = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        bad.check_hostname = False
        bad.verify_mode = ssl.CERT_NONE
        with self.assertRaises(PlanningError):
            ProviderTransport("https://api.github.com", lambda: None, lambda: NOW, context=bad)
        for origin in ("http://api.github.com", "https://api.github.com@evil.invalid", "https://api.github.com/path"):
            with self.assertRaises(PlanningError):
                ProviderTransport(origin, lambda: None, lambda: NOW)
        self.server.transport.credential = lambda: ("expired", NOW)
        with self.assertRaises(PlanningError):
            self.server.transport.request("GET", "/repos/test/disposable")
        for path in ("//evil.invalid", "/%2e%2e/secret", "https://evil.invalid"):
            with self.assertRaises(PlanningError):
                self.server.transport.request("GET", path)

    def test_external_signer_and_audit_boundary_verify_exact_bytes(self):
        audit = self.keys.signers["audit"]
        self.server.signing_service(audit)
        remote = ProtectedSigner(self.server.transport, public_key=audit.public, key_sha256=audit.key_sha256,
                                 purpose="audit", context={"workload_token_sha256": self.fx.workload.token_sha256})
        ledger = Ledger(self.fx.ledger.adapter, remote, audit_key=audit.public, audit_key_sha256=audit.key_sha256, clock=lambda: self.fx.now)
        ledger.execute("remote-audit-test", None, lambda db: db.execute("INSERT INTO consumed VALUES(?,?,?)", ("test", "test", "test")))
        self.assertEqual(ledger.inspect()["checkpoint"]["seq"], 2)
        with self.assertRaises(PlanningError):
            remote.envelope("human-approval", {"issued_at": NOW, "expires_at": NOW+60})
        self.server.signing_service(self.keys.signers["publication"])
        with self.assertRaises(PlanningError):
            remote.sign(b"audit substitution")

    def test_publication_stage_wires_external_signer_and_reopens_without_resigning(self):
        self.fx.advance("AUTHORIZED")
        key = self.keys.signers["publication"]
        self.server.signing_service(key)
        remote = ProtectedSigner(self.server.transport, public_key=key.public, key_sha256=key.key_sha256,
            purpose="publication", context={"approval": strict_json(self.fx.approval_args["approval_raw"]),
                "witness": strict_json(self.fx.approval_args["witness_raw"]), "workload_token_sha256": self.fx.workload.token_sha256})
        store = IsolatedStore(self.fx.root)
        view = store.stage(self.fx.result, self.fx.approval, remote, origin="https://test.invalid",
            audit_key_sha256=self.keys.signers["audit"].key_sha256, now=NOW)
        self.fx.backend.signed(self.fx.attempt, view)
        before = len(self.server.calls)
        self.assertEqual(store.reopen(self.fx.result, self.fx.approval, remote, now=NOW).envelope, view.envelope)
        self.assertEqual(len(self.server.calls), before)
        with self.assertRaises(PlanningError):
            remote.envelope("publication", {"issued_at": NOW-61, "expires_at": NOW-1})
        self.assertEqual(len(self.server.calls), before)

    def test_protected_approval_uses_existing_exact_result_verifier(self):
        self.server.approval_services()
        approval, witness = self.keys.signers["approval"], self.keys.signers["witness"]
        result = protected_authorization(self.fx.proposal, self.fx.attempt, self.fx.evidence, self.fx.workload,
            approval_transport=self.server.transport, witness_transport=self.server.transport,
            approval_key=approval.public, approval_pin=approval.key_sha256,
            witness_key=witness.public, witness_pin=witness.key_sha256,
            allowed_reviewer_ids={"456"}, environment_config_sha256="f"*64)
        self.assertEqual(result.payload["request"]["result_stable_sha256"], self.fx.result.sha256)
        self.server.handlers["/v1/approval"] = lambda m,b: (200, {"approved": True})
        with self.assertRaises(PlanningError):
            protected_authorization(self.fx.proposal, self.fx.attempt, self.fx.evidence, self.fx.workload,
                approval_transport=self.server.transport, witness_transport=self.server.transport,
                approval_key=approval.public, approval_pin=approval.key_sha256,
                witness_key=witness.public, witness_pin=witness.key_sha256,
                allowed_reviewer_ids={"456"}, environment_config_sha256="f"*64)

    def test_oidc_lifecycle_nonce_revocation_and_replay(self):
        key = self.https_key
        def lifecycle(m, body):
            return 200, self.server.envelope(key, "jwks-lifecycle", {**body, "epoch": 3, "fetched_at": NOW, "revoked_kids": []})
        self.server.handlers["/v1/jwks-lifecycle"] = lifecycle
        raw, pins = self.keys.oidc()
        args = dict(lifecycle_key=key.public, lifecycle_pin=key.key_sha256, pins=pins, minimum_epoch=3)
        self.assertEqual(workload_from_services(raw, self.keys.jwks, self.server.transport, **args).token_sha256, self.fx.workload.token_sha256)
        saved = lifecycle(None, {"nonce": "a"*64, "issuer": "https://token.actions.githubusercontent.com", "jwks_sha256": digest(self.keys.jwks)})
        self.server.handlers["/v1/jwks-lifecycle"] = lambda m,b: saved
        with self.assertRaises(PlanningError):
            workload_from_services(raw, self.keys.jwks, self.server.transport, **args)

    def test_independent_checkpoint_uses_authenticated_http_nonce_contract(self):
        audit, checkpoint = self.keys.signers["audit"], self.https_key
        authority = LocalAuthority(self.fx.root, checkpoint, audit.public, audit.key_sha256, lambda: self.fx.now)
        self.server.handlers["/v1/exchange"] = lambda m,b: (200, strict_json(authority.exchange(b)))
        self.server.signing_service(audit)
        updater = ProtectedSigner(self.server.transport, public_key=audit.public, key_sha256=audit.key_sha256,
                                  purpose="independent-update", context={"ledger_identity": "disposable"})
        client = authority_client(self.server.transport, public_key=checkpoint.public, key_sha256=checkpoint.key_sha256, updater=updater)
        tip = self.fx.ledger.inspect()["checkpoint"]
        self.assertEqual(client.advance("checkpoint/disposable", None, tip), tip)
        self.assertEqual(client.read("checkpoint/disposable"), tip)

    def test_independent_deployment_requires_visible_bytes_and_fresh_signed_observation(self):
        view = self.view()
        commit = self.stage()["git_commit"]
        observer = self.https_key
        self.server.handlers["/v1/deployment-observation"] = lambda m,b: (200,
            self.server.envelope(observer, "deployment", {**b, "deployment_id": "independently-observed-1"}))
        deployment = IndependentDeployment(self.server.transport, public_key=observer.public,
            key_sha256=observer.key_sha256, origin="https://test.invalid")
        factory = lambda *args: DirectoryReader(view)
        self.assertEqual(deployment.verify(view, commit, now=NOW, reader_factory=factory).data["phase"], "pre")
        with patch.object(DirectoryReader, "read", side_effect=FileNotFoundError("not externally visible")):
            with self.assertRaises(PlanningError):
                deployment.verify(view, commit, now=NOW, reader_factory=factory)
        self.server.handlers["/v1/deployment-observation"] = lambda m,b: (200, {"status": "succeed"})
        with self.assertRaises(PlanningError):
            deployment.verify(view, commit, now=NOW, reader_factory=factory)

    def empty_evidence(self):
        def observe(m, body):
            key = self.storage_key if body["observation"] == "storage" else self.https_key
            return 200, self.server.envelope(key, "empty-stable", {**body, "remote_sha256": "c"*64})
        self.server.handlers["/v1/empty-stable"] = observe
        return observe_empty(self.storage, self.server.transport, self.server.transport,
            database="ro_v3_test_bootstrap", schema="ro_v3", origin="https://test.invalid",
            storage_key=self.storage_key.public, storage_pin=self.storage_key.key_sha256,
            https_key=self.https_key.public, https_pin=self.https_key.key_sha256)

    def bootstrap_approval(self, evidence):
        self.server.approval_services()
        a, w = self.keys.signers["approval"], self.keys.signers["witness"]
        return authorize_empty(evidence, self.fx.workload, attempt="bootstrap-test",
            approval_transport=self.server.transport, witness_transport=self.server.transport,
            approval_key=a.public, approval_pin=a.key_sha256, witness_key=w.public, witness_pin=w.key_sha256,
            allowed_reviewer_ids={"456"}, environment_config_sha256="f"*64)

    def empty_adapter(self):
        adapter = SQLiteAdapter(self.fx.root, filename="empty-bootstrap.sqlite")
        adapter.config = {"dbname": "ro_v3_test_bootstrap", "schema": "ro_v3"}
        with adapter.transaction() as db:
            for sql in DDL:
                db.execute(sql)
        return adapter

    def test_authenticated_empty_bootstrap_consumes_approval_without_touching_beta(self):
        before = self.server.store.head()
        authorization = self.bootstrap_approval(self.empty_evidence())
        adapter = self.empty_adapter()
        audit = self.keys.signers["audit"]
        tip = initialize_empty(adapter, audit, authorization, audit_key=audit.public, audit_pin=audit.key_sha256)
        ledger = Ledger(adapter, audit, audit_key=audit.public, audit_key_sha256=audit.key_sha256, clock=lambda: self.fx.now)
        self.assertEqual(ledger.inspect()["head"], {"digest": None, "generation": 0, "last_verified": None})
        self.assertEqual(ledger.inspect()["checkpoint"], tip)
        with self.assertRaises(PlanningError):
            initialize_empty(adapter, audit, authorization, audit_key=audit.public, audit_pin=audit.key_sha256)
        self.assertEqual(self.server.store.head(), before)
        with adapter.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM consumed").fetchone()[0], 2)

    def test_bootstrap_refuses_deleted_real_stable_history(self):
        stable = self.server.store._cas({"publications/fedora/44/stable/9/publication-v1.json.asc": b"real historical signed bytes"}, self.server.initial)
        tree = self.server.store._tree(self.server.store._files(self.server.initial))
        deleted = self.server.store._run(["commit-tree", tree, "-p", stable], data=b"delete historical stable marker").decode().strip()
        self.server.store._run(["update-ref", "refs/heads/isolated-storage", deleted, stable])
        with self.assertRaises(PlanningError):
            self.empty_evidence()

    def test_bootstrap_independent_observers_must_agree_on_https_evidence(self):
        self.empty_evidence()
        def disagree(method, body):
            key = self.storage_key if body["observation"] == "storage" else self.https_key
            return 200, self.server.envelope(key, "empty-stable", {**body,
                "remote_sha256": ("c" if body["observation"] == "storage" else "d")*64})
        self.server.handlers["/v1/empty-stable"] = disagree
        with self.assertRaises(PlanningError):
            observe_empty(self.storage, self.server.transport, self.server.transport,
                database="ro_v3_test_bootstrap", schema="ro_v3", origin="https://test.invalid",
                storage_key=self.storage_key.public, storage_pin=self.storage_key.key_sha256,
                https_key=self.https_key.public, https_pin=self.https_key.key_sha256)

    def test_bootstrap_absence_is_not_http_404_or_expired_approval(self):
        self.server.handlers["/v1/empty-stable"] = lambda m,b: (404, {"message": "absent"})
        with self.assertRaises(ProviderHTTPError):
            observe_empty(self.storage, self.server.transport, self.server.transport,
                database="ro_v3_test_bootstrap", schema="ro_v3", origin="https://test.invalid",
                storage_key=self.storage_key.public, storage_pin=self.storage_key.key_sha256,
                https_key=self.https_key.public, https_pin=self.https_key.key_sha256)
        auth = self.bootstrap_approval(self.empty_evidence())
        adapter = self.empty_adapter()
        self.fx.now += 61
        audit = self.keys.signers["audit"]
        with self.assertRaises(PlanningError):
            initialize_empty(adapter, audit, auth, audit_key=audit.public, audit_pin=audit.key_sha256)
        with adapter.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM head").fetchone()[0], 0)

    def test_bootstrap_signing_expiration_rolls_back_initialization(self):
        auth = self.bootstrap_approval(self.empty_evidence())
        adapter = self.empty_adapter()
        audit = self.keys.signers["audit"]
        original = audit.sign
        def delayed(data):
            result = original(data)
            self.fx.now += 61
            return result
        with patch.object(audit, "sign", side_effect=delayed):
            with self.assertRaises(PlanningError):
                initialize_empty(adapter, audit, auth, audit_key=audit.public, audit_pin=audit.key_sha256)
        with adapter.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM head").fetchone()[0], 0)

    def coordinator(self):
        self.view()
        coordinator = Coordinator(self.fx.backend, self.server.store, SimulatedDeployment(self.server.store, self.keys.attestation))
        coordinator.outbox.enqueue(self.view_value, self.fx.approval, self.server.initial)
        fence = coordinator.outbox.claim(self.fx.attempt, "worker")
        return coordinator, fence

    def test_durable_deployment_identity_survives_restart_and_lease_turnover(self):
        coordinator, fence = self.coordinator()
        identity = coordinator.outbox.deployment_identity(self.fx.attempt, "worker", fence, phase="pre", git_commit=self.server.initial)
        self.fx.now += 31
        restarted = Outbox(self.fx.backend)
        new_fence = restarted.claim(self.fx.attempt, "other")
        self.assertEqual(restarted.deployment_identity(self.fx.attempt, "other", new_fence, phase="pre", git_commit=self.server.initial), identity)
        with self.assertRaises(PlanningError):
            restarted.deployment_identity(self.fx.attempt, "worker", fence, phase="pre", git_commit=self.server.initial)
        with self.assertRaises(PlanningError):
            restarted.deployment_identity(self.fx.attempt, "other", new_fence, phase="pre", git_commit="a"*40)

    def test_interrupted_first_publication_reconciles_but_expired_recovery_is_blocked(self):
        coordinator, fence = self.coordinator()
        def crash(at):
            if at == "after-git-advertisement":
                raise RuntimeError("crash at first advertisement; no prior stable")
        with self.assertRaises(RuntimeError):
            coordinator.run(self.view_value, self.fx.approval, self.keys.signers["publication"], owner="worker", fence=fence, inject=crash)
        self.assertEqual(self.fx.ledger.inspect()["head"]["last_verified"], None)
        result = interrupted_first_publication(self.fx.backend, self.fx.attempt, self.fx.approval, now=self.fx.now)
        self.assertFalse(result["reinitialize"])
        final = coordinator.run(self.view_value, self.fx.approval, self.keys.signers["publication"], owner="worker", fence=fence)
        self.assertEqual(final["attempt"]["state"], "POST_VERIFIED")
        with self.assertRaises(PlanningError):
            interrupted_first_publication(self.fx.backend, self.fx.attempt, self.fx.approval, now=NOW+301)

    def test_stale_first_publication_recovery_authorization_is_rejected(self):
        self.coordinator()
        other = Fixture(self.keys, attempt="wrong-recovery")
        self.addCleanup(other.close)
        with self.assertRaises(PlanningError):
            interrupted_first_publication(self.fx.backend, self.fx.attempt, other.approval, now=NOW)


if __name__ == "__main__":
    unittest.main()
