"""Deterministic local counterexamples, NOT GitHub/CDN guarantees.

Existing loss/restart/race tests are inventoried in the companion document.
Only their uncovered provider boundaries are exercised here. All Git mutations
use marked private /tmp roots and loopback; Pages/HTTPS responses are snapshots
of real disposable Git objects. No live transport, RPM install or activation.
"""
import concurrent.futures
import contextlib
import io
import pathlib
import sys
import tempfile
import threading
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_backend_support import Fixture, Keys, NOW
from v3_backend_ledger import Ledger, SQLiteAdapter
from v3_backend_trust import TestSigner
from v3_branch_pages import BranchPagesIdentity, BranchPagesDeployment
from v3_client_update import Client, discovery_payload
from v3_fenced_publisher import FencedPublisher
from v3_github_provider import GitHubStorage
from v3_immutable_view import IsolatedStore
from v3_provider_support import ProtocolServer
from v3_provider_transport import ProviderUnavailable
from v3_publication_backend import Backend
from v3_publication_outbox import Coordinator, Outbox
from v3_promotion_planner import PlanningError

ORIGIN = "https://test.invalid"
PINS = dict(repository="test/disposable", repository_id=123, node_id="R_test",
            ref="refs/heads/isolated-storage")


def payload_fixture(keys, attempt, version):
    with tempfile.TemporaryDirectory() as source:
        for path in ("rpm/x86_64/repodata/repomd.xml", "rpm/aarch64/repodata/repomd.xml",
                     "rpm/source/repodata/repomd.xml", "history.asc", "repository-snapshot-v1.json"):
            target = pathlib.Path(source) / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("SYNTHETIC ONLY " + version + " " + path)
        return Fixture(keys, attempt=attempt, version=version, result_source=source)


class ControlledPages:
    """Explicit completion order and independent public snapshot selection.

    Successful REST facts are retained when an older build replaces public
    bytes. This is an adversarial model, not a claim about actual Pages order.
    The opener double exercises real HTTPSReader requests and byte verifiers;
    it does not test TLS, real CDN caching or a real independent witness.
    """
    def __init__(self, api, observer):
        self.api, self.observer = api, observer
        self.builds, self.completed, self.public_commit = {}, [], None
        self.overrides, self.requests = {}, []
        base = "/repos/test/disposable"
        api.handlers[base + "/pages"] = lambda m,b: (200, {
            "build_type": "legacy", "source": {"branch": "isolated-storage", "path": "/"}})
        api.handlers[base + "/pages/builds"] = lambda m,b: (200, [v["build"] for v in self.builds.values()])
        api.handlers[base + "/deployments"] = lambda m,b: (200, [v["deployment"] for v in self.builds.values()])
        api.handlers[base + "/actions/runs"] = lambda m,b: (200, {"workflow_runs": [v["run"] for v in self.builds.values()]})
        def observe(method, body):
            build, deployment, run = self.ids(body["git_commit"])
            return 200, api.envelope(observer, "deployment", {
                **body, "deployment_id": "github-pages:" + build + ":" + deployment + ":" + run})
        api.handlers["/v1/deployment-observation"] = observe

    def register(self, commit):
        if commit in self.builds:
            return self.ids(commit)
        number = len(self.builds) + 1
        ids = tuple(str(n) for n in (number, number + 100, number + 200))
        build, deployment, run = ids
        base = "/repos/test/disposable"
        facts = {"ids": ids,
            "build": {"commit": commit, "status": "building", "error": {"message": None},
                      "url": "https://api.github.com" + base + "/pages/builds/" + build},
            "deployment": {"id": int(deployment), "sha": commit, "ref": "isolated-storage", "environment": "github-pages"},
            "run": {"id": int(run), "head_sha": commit, "head_branch": "isolated-storage",
                    "path": "dynamic/pages/pages-build-deployment", "event": "dynamic",
                    "status": "in_progress", "conclusion": None},
            "statuses": [{"state": "pending", "log_url": "https://github.com/test/disposable/actions/runs/" + run + "/job/1"}]}
        self.builds[commit] = facts
        for path, key in (("/pages/builds/" + build, "build"), ("/deployments/" + deployment, "deployment"),
                          ("/actions/runs/" + run, "run"), ("/deployments/" + deployment + "/statuses", "statuses")):
            self.api.handlers[base + path] = lambda m,b,k=key,f=facts: (200, f[k])
        return ids

    def ids(self, commit):
        return self.builds[commit]["ids"]

    def finish(self, commit):
        self.register(commit)
        facts = self.builds[commit]
        facts["build"]["status"] = "built"
        facts["run"].update(status="completed", conclusion="success")
        facts["statuses"][0]["state"] = "success"
        self.completed.append(commit)
        self.public_commit = commit

    def open(self, request, *, timeout):
        url = request.full_url
        if not url.startswith(ORIGIN + "/") or request.get_header("Authorization") is not None:
            raise AssertionError("public transport must stay on the pinned test origin without credentials")
        self.requests.append(url)
        path = url.removeprefix(ORIGIN + "/")
        if path in self.overrides:
            raw = self.overrides[path]
        else:
            files = self.api.store._files(self.public_commit)
            raw = None if path not in files else self.api.store._run(["cat-file", "blob", files[path]])
        if raw is None:
            error = urllib.error.HTTPError(url, 404, "delayed test CDN member", {}, io.BytesIO())
            error.close()
            raise error
        return io.BytesIO(raw)


class ProviderCase:
    def __init__(self, keys, observer, attempt="fault-current"):
        self.cleanup = contextlib.ExitStack()
        self.fx = payload_fixture(keys, attempt, "0.2.6")
        self.cleanup.callback(self.fx.close)
        self.api = ProtocolServer(self.fx, keys)
        self.cleanup.callback(self.api.close)
        self.storage = GitHubStorage.rehearsal(self.api.transport, root=self.fx.root, **PINS)
        self.signer, self.observer = keys.signers["publication"], observer
        prior = payload_fixture(keys, "archive-" + attempt, "0.2.5")
        self.cleanup.callback(prior.close)
        prior_view = self.signed(prior)
        self.old_commit = self.storage.stage(prior_view, prior.approval, expected=self.api.initial,
            publication_key=self.signer.public, publication_pin=self.signer.key_sha256, now=NOW)["git_commit"]
        self.history = {p: self.api.store._run(["cat-file", "blob", oid])
                        for p,oid in self.api.store._files(self.old_commit).items()}
        self.view = self.signed(self.fx)
        self.fx.backend.signed(self.fx.attempt, self.view)
        self.fx.backend.staged(self.fx.attempt, self.view)
        self.outbox = Outbox(self.fx.backend)
        self.outbox.enqueue(self.view, self.fx.approval, self.old_commit)
        self.fence = self.outbox.claim(self.fx.attempt, "worker")
        self.publisher = FencedPublisher(self.fx.backend, self.storage)
        self.pages = ControlledPages(self.api, observer)
        self.pages.register(self.old_commit)  # Old build stays queued until explicitly completed.
        self.identity = BranchPagesIdentity(self.storage, branch="isolated-storage")
        self.deployment = BranchPagesDeployment(self.api.transport, public_key=observer.public,
            key_sha256=observer.key_sha256, origin=ORIGIN, identity=self.identity)

    def signed(self, fx):
        fx.advance("AUTHORIZED")
        return IsolatedStore(fx.root).stage(fx.result, fx.approval, self.signer, origin=ORIGIN,
            audit_key_sha256=fx.keys.signers["audit"].key_sha256, now=fx.now)

    def stage(self):
        return self.publisher.stage(self.view, self.fx.approval, self.signer, owner="worker", fence=self.fence)

    def verify(self, commit, *, post=False):
        build, deployment, run = self.pages.ids(commit)
        return self.deployment.verify_branch(self.identity, self.view, commit, build_id=build,
            deployment_id=deployment, run_id=run, now=self.fx.now,
            ledger=self.fx.ledger if post else None, signer=self.signer if post else None)

    def advertised(self):
        staged = self.stage()["git_commit"]
        self.pages.finish(staged)
        remote = self.verify(staged)
        self.fx.backend.remotely_verified(self.fx.attempt, remote)
        self.fx.backend.publish(self.fx.attempt, self.fx.approval)
        commit = self.publisher.advertise(self.view, self.fx.approval, remote, self.signer,
            owner="worker", fence=self.fence)["git_commit"]
        self.pages.finish(commit)
        return commit

    def restart(self):
        audit = self.fx.keys.signers["audit"]
        ledger = Ledger(SQLiteAdapter(self.fx.root), audit, audit_key=audit.public,
                        audit_key_sha256=audit.key_sha256, clock=lambda: self.fx.now)
        backend = Backend(ledger)
        storage = GitHubStorage.rehearsal(self.api.transport, root=self.fx.root, **PINS)
        return FencedPublisher(backend, storage)

    def auto_deployment(self):
        case = self
        class AutoBuild:
            def verify(self, view, commit, *, now, ledger=None, signer=None):
                case.pages.finish(commit)
                return case.deployment.verify(view, commit, now=now, ledger=ledger, signer=signer)
        return AutoBuild()

    def assert_history(self, test):
        current = self.api.store._files(self.storage.head())
        for path, raw in self.history.items():
            test.assertIn(path, current)
            test.assertEqual(self.api.store._run(["cat-file", "blob", current[path]]), raw)


class ProviderFaultInjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Keys()
        cls.observer = TestSigner(cls.keys.root, "fault-observer")

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    def case(self, attempt="fault-current"):
        value = ProviderCase(self.keys, self.observer, attempt)
        self.addCleanup(value.cleanup.close)
        return value

    def test_admitted_cas_applies_after_approval_expiry_but_cannot_become_stable(self):
        case = self.case()
        # Keep the App credential fresh across approval expiry; these are
        # separate deadlines. The provider double enforces expected HEAD only.
        case.api.transport.credential = lambda: ("disposable-test-only", NOW + 900)
        queued, release = threading.Event(), threading.Event()
        applied_at = []
        original = case.api.respond
        def delayed(method, path, body):
            if method == "POST" and path == "/graphql":
                queued.set()
                if not release.wait(10):
                    raise PlanningError("test controller did not release queued CAS")
                applied_at.append(case.fx.now)
            return original(method, path, body)
        graphql_before = sum(p == "/graphql" for m,p,b in case.api.calls)
        case.api.lose_cas = True
        with patch.object(case.api, "respond", side_effect=delayed), concurrent.futures.ThreadPoolExecutor(1) as pool:
            pending = pool.submit(case.stage)
            try:
                self.assertTrue(queued.wait(10))
                restarted = case.restart()
                intent = restarted.backend.ledger.inspect(case.fx.attempt)["attempt"]["proofs"]["OUTBOX"]["receipts"]["provider_intent"]
                self.assertEqual(intent["status"], "IN_FLIGHT")
                self.assertLess(intent["admitted_at"], case.fx.approval.expiry)
                self.assertEqual(case.storage.head(), case.old_commit)
                with self.assertRaises(PlanningError):
                    restarted.reconcile(case.fx.attempt)  # Base HEAD cannot prove drain/noncommit.
                case.fx.now = int(case.fx.approval.expiry) + 1
            finally:
                release.set()
            with self.assertRaises(ProviderUnavailable):
                pending.result(timeout=10)
        self.assertEqual(applied_at, [case.fx.now])
        self.assertGreater(applied_at[0], case.fx.approval.expiry)
        self.assertEqual(case.storage.head(), intent["binding"]["target_git"])
        restarted = case.restart()
        self.assertEqual(restarted.reconcile(case.fx.attempt)["status"], "CONFIRMED")
        state = restarted.backend.ledger.inspect(case.fx.attempt)
        self.assertEqual(state["attempt"]["state"], "STAGED")
        self.assertIsNone(state["head"]["digest"])
        self.assertNotEqual(state["attempt"]["proofs"]["OUTBOX"]["status"], "COMPLETE")
        with self.assertRaises(PlanningError):
            restarted.stage(case.view, case.fx.approval, case.signer, owner="worker", fence=case.fence)
        with self.assertRaises(PlanningError):
            discovery_payload(restarted.backend.ledger, case.view, "a" * 64, origin=ORIGIN)
        with self.assertRaises(PlanningError):
            restarted.activate_production()
        self.assertEqual(sum(p == "/graphql" for m,p,b in case.api.calls), graphql_before + 1)
        case.assert_history(self)
        # Expected counterexample PASS; provider deadline fencing UNVERIFIED,
        # strict deadline requirement and production activation remain BLOCKED.

    def test_old_build_finishing_after_post_verified_build_blocks_client_without_rollback(self):
        case = self.case()
        with patch("urllib.request.build_opener", return_value=case.pages):
            latest = case.advertised()
            case.fx.backend.post_verified(case.fx.attempt, case.verify(latest, post=True))
            client = Client(case.fx.root, origin=ORIGIN, discovery_key=self.observer.public,
                discovery_pin=self.observer.key_sha256, publication_key=case.signer.public,
                publication_pin=case.signer.key_sha256, rpm_key_url="file:///test/rpm.asc",
                metadata_key_url="file:///test/metadata.asc", clock=lambda: case.fx.now)
            def discovery(nonce):
                payload = discovery_payload(case.fx.ledger, case.view, nonce, origin=ORIGIN)
                return self.observer.envelope("client-discovery", {**payload,
                    "issued_at": case.fx.now, "expires_at": case.fx.now + 60})
            self.assertEqual(client.update(discovery)["view_verification"], "PASS")
            client_state = (case.fx.root / "client-state.json").read_bytes()
            repo_state = (case.fx.root / "repos/ro-stable-v3.repo").read_bytes()
            ledger_state = case.fx.ledger.inspect(case.fx.attempt)
            case.pages.finish(case.old_commit)
            self.assertEqual(case.pages.completed[-2:], [latest, case.old_commit])
            self.assertEqual(case.storage.head(), latest)  # Git HEAD never rolled back.
            build, deployment, run = case.pages.ids(latest)
            facts = case.identity.identify(latest, build_id=build, deployment_id=deployment, run_id=run)
            self.assertEqual(facts["public_visibility"], "UNVERIFIED")
            self.assertEqual(facts["production_activation"], "BLOCKED")
            with self.assertRaises(PlanningError):
                case.verify(latest, post=True)
            with self.assertRaises((PlanningError, OSError)):
                client.update(discovery)
            self.assertEqual((case.fx.root / "client-state.json").read_bytes(), client_state)
            self.assertEqual((case.fx.root / "repos/ro-stable-v3.repo").read_bytes(), repo_state)
            self.assertEqual(case.fx.ledger.inspect(case.fx.attempt), ledger_state)
            case.pages.finish(latest)
            self.assertEqual(client.update(discovery)["view_verification"], "PASS")
        case.assert_history(self)

    def test_delayed_or_stale_each_public_member_cannot_complete_post_verification(self):
        case = self.case()
        with patch("urllib.request.build_opener", return_value=case.pages):
            latest = case.advertised()
            before = case.fx.ledger.inspect(case.fx.attempt)
            self.assertEqual(before["attempt"]["state"], "PUBLISHED")
            paths = ["v3/publications/" + case.fx.attempt + ".json",
                     "v3/advertisements/" + case.fx.approval.sha256 + ".json"]
            paths += ["v3/views/" + case.view.sha256 + "/" + item["path"] for item in case.view.result.inventory]
            for path in paths:
                for raw in (None, b"stale cached synthetic bytes"):
                    with self.subTest(path=path, missing=raw is None):
                        case.pages.overrides[path] = raw
                        with self.assertRaises(PlanningError):
                            case.verify(latest, post=True)
                        self.assertEqual(case.fx.ledger.inspect(case.fx.attempt), before)
                        with self.assertRaises(PlanningError):
                            discovery_payload(case.fx.ledger, case.view, "a" * 64, origin=ORIGIN)
                        case.pages.overrides.clear()
            post = case.verify(latest, post=True)
            case.fx.backend.post_verified(case.fx.attempt, post)
            self.assertEqual(case.fx.ledger.inspect(case.fx.attempt)["attempt"]["state"], "POST_VERIFIED")
            self.assertIs(post.data["publishable"], False)
        case.assert_history(self)

    def test_branch_restart_at_uncovered_io_boundaries_is_idempotent_and_preserves_history(self):
        # after-db-intent is already covered in test_v3_pages_finalization.
        for boundary in ("after-git-stage", "after-pre-verification", "after-git-advertisement", "after-post-verification"):
            with self.subTest(boundary=boundary):
                case = self.case("restart-" + boundary)
                with patch("urllib.request.build_opener", return_value=case.pages):
                    coordinator = Coordinator.rehearsal_branch(case.fx.backend, case.publisher, case.auto_deployment())
                    def crash(point):
                        if point == boundary:
                            raise RuntimeError("controlled interruption at " + boundary)
                    with self.assertRaises(RuntimeError):
                        coordinator.run(case.view, case.fx.approval, case.signer, owner="worker",
                                        fence=case.fence, inject=crash)
                    admitted = [b for m,p,b in case.api.calls if p == "/graphql"]
                    publisher = case.restart()
                    restarted = Coordinator.rehearsal_branch(publisher.backend, publisher, case.auto_deployment())
                    result = restarted.run(case.view, case.fx.approval, case.signer, owner="worker", fence=case.fence)
                    self.assertEqual(result["attempt"]["state"], "POST_VERIFIED")
                    self.assertEqual(result["attempt"]["proofs"]["OUTBOX"]["status"], "COMPLETE")
                    writes = [b for m,p,b in case.api.calls if m == "POST"]
                    self.assertEqual(restarted.run(case.view, case.fx.approval, case.signer,
                                                   owner="worker", fence=case.fence), result)
                    self.assertEqual([b for m,p,b in case.api.calls if m == "POST"], writes)
                    self.assertEqual([b for m,p,b in case.api.calls if p == "/graphql"][:len(admitted)], admitted)
                    self.assertEqual(len([p for m,p,b in case.api.calls if p == "/graphql"]), 3)  # archive + stage + advertisement
                case.assert_history(self)


if __name__ == "__main__":
    unittest.main()
