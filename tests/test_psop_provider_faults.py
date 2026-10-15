"""PSOP cross-layer counterexamples; provider guarantees are never inferred."""
import pathlib
import shutil
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from psop_support import Fixture
from psop_client_support import ClientFixture, DirectoryReader
from psop_client import issue_descriptor
from v3_backend_trust import test_workspace
from v3_promotion_planner import PlanningError


class PublisherAuthorityFaultTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()

    def tearDown(self):
        self.fx.close()

    def test_delayed_cas_then_expiry_cannot_issue_client_authority(self):
        job = self.fx.job(expiry=5);self.fx.gateway.admit(job.prepared, job.approval)
        held = []
        def hold(stage):
            if stage == "after-durable-intent":
                held.append(job.prepared.data)
                raise ConnectionError("provider request accepted; response lost")
        with self.assertRaises(ConnectionError):self.fx.gateway.apply(job.attempt, inject=hold)
        self.fx.reopen()
        self.assertEqual(self.fx.gateway.receipt(job.attempt)["status"], "UNKNOWN")
        successor = self.fx.job()
        with self.assertRaisesRegex(PlanningError, "UNKNOWN"):
            self.fx.gateway.admit(successor.prepared, successor.approval)
        self.fx.now += 6
        self.fx.gateway._store.apply(held[0])
        receipt = self.fx.gateway.reconcile(job.attempt)
        self.assertEqual(receipt["status"], "COMMITTED_EXPIRED")
        self.assertEqual(self.fx.gateway.reconcile(job.attempt), receipt)
        self.assertIsNone(self.fx.ledger.inspect()["head"]["digest"])
        with self.assertRaisesRegex(PlanningError, "completed result/receipt"):
            issue_descriptor(self.fx.gateway, job.signed, job.approval, job.attempt,
                origin="https://localhost:18443", now=self.fx.now)

    def test_response_loss_requires_exact_target_and_idempotent_reconciliation_before_descriptor(self):
        # Existing writer/race/process-death primitives stay covered by PR-B's
        # unchanged tests. This case adds the client-authority gate above them.
        job = self.fx.job();self.fx.gateway.admit(job.prepared, job.approval)
        def loss(stage):
            if stage == "after-git-cas":raise ConnectionError("lost response")
        with self.assertRaises(ConnectionError):self.fx.gateway.apply(job.attempt, inject=loss)
        self.fx.reopen()
        with self.assertRaises(PlanningError):
            issue_descriptor(self.fx.gateway, job.signed, job.approval, job.attempt,
                origin="https://localhost:18443", now=self.fx.now)
        first = self.fx.gateway.reconcile(job.attempt)
        self.assertEqual(self.fx.gateway.reconcile(job.attempt), first)
        descriptor = issue_descriptor(self.fx.gateway, job.signed, job.approval, job.attempt,
            origin="https://localhost:18443", now=self.fx.now)
        self.assertIn(b'"publishable":false', descriptor)
        self.assertEqual(first["provider_deadline_fencing"], "UNVERIFIED")


class PublicVisibilityFaultTests(unittest.TestCase):
    def setUp(self):
        self.fx = ClientFixture()
        self.rpm_model = mock.patch("psop_client.verify_signed_rpms");self.rpm_model.start()

    def tearDown(self):
        self.rpm_model.stop();self.fx.close()

    def test_old_build_mixed_stale_missing_members_never_become_public_success(self):
        first = self.fx.publication();self.fx.client.update(first.descriptor, reader=first.reader)
        second = self.fx.publication(version="2.0", previous=first)
        self.assertEqual(self.fx.gateway._store.head(), self.fx.gateway.receipt(second.attempt)["target_git"])
        before = self.fx.client.active()
        paths = [x["path"] for x in second.signed.data["inventory"]]
        for victim in paths:
            def missing(path, raw):
                if path == victim:raise FileNotFoundError("one CDN member missing")
                return raw
            with self.subTest(member=victim), self.assertRaises((PlanningError, OSError)):
                self.fx.client.update(second.descriptor, reader=DirectoryReader(second.signed, second.reader.raw, mutation=missing))
            self.assertEqual(self.fx.client.active(), before)
        def stale(path, raw):
            if path == "psop-result-v1.json":return (first.signed.path / path).read_bytes()
            return raw
        with self.assertRaises(PlanningError):
            self.fx.client.update(second.descriptor, reader=DirectoryReader(second.signed, second.reader.raw, mutation=stale))
        # Reverted Pages build serves an old signed descriptor. It can be valid
        # for an uninitialized client, but cannot move a known newer state back.
        self.fx.client.update(second.descriptor, reader=second.reader)
        with self.assertRaisesRegex(PlanningError, "replay/rollback"):
            self.fx.client.update(first.descriptor, reader=first.reader)
        self.assertEqual(self.fx.client.active()["generation"], 2)
        receipt = self.fx.gateway.receipt(second.attempt)
        self.assertNotIn("public_https", receipt)
        self.assertEqual(receipt["pages_build_ordering"], "UNVERIFIED")

    def test_wrong_success_receipt_cannot_authenticate_a_different_public_result(self):
        first = self.fx.publication()
        second = self.fx.publication(version="2.0", previous=first)
        reader = DirectoryReader(first.signed, second.reader.raw)
        with self.assertRaisesRegex(PlanningError, "publication identity"):
            self.fx.client.update(first.descriptor, reader=reader)
        self.assertIsNone(self.fx.client.active())


class CIIsolationTests(unittest.TestCase):
    def test_new_acceptance_job_has_only_disposable_read_permissions(self):
        import yaml
        root = pathlib.Path(__file__).parents[1]
        path = root / ".github/workflows/psop-acceptance-tests.yml"
        v = yaml.safe_load(path.read_text())
        self.assertEqual(v["permissions"], {"contents": "read"})
        self.assertEqual(set(v["on"]), {"pull_request", "push"})
        self.assertEqual(set(v["jobs"]), {"psop-fedora44-acceptance"})
        for job in v["jobs"].values():
            self.assertEqual(job["container"], "fedora:44")
            checkout = next(i for i, step in enumerate(job["steps"]) if step.get("uses", "").startswith("actions/checkout@"))
            runtime = next(i for i, step in enumerate(job["steps"]) if step.get("name") == "Install disposable test runtime")
            self.assertLess(runtime, checkout, "Git must exist before checkout; archive fallback has no commit metadata")
            self.assertIn("git", job["steps"][runtime]["run"].split())
            for forbidden in ("environment", "permissions", "continue-on-error", "if"):
                self.assertNotIn(forbidden, job)
            for step in job["steps"]:
                self.assertNotIn("continue-on-error", step)
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertFalse(step["with"]["persist-credentials"])
        for forbidden in ("secrets.", "id-token", "gh api", "git push", "workflow_dispatch"):
            self.assertNotIn(forbidden, path.read_text())


if __name__ == "__main__":
    unittest.main()
