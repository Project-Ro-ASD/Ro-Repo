import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_pages_backend import IsolatedGitStore
from v3_immutable_view import verify_remote, DirectoryReader
from v3_promotion_planner import PlanningError
from v3_backend_support import Keys, Fixture, NOW


class PagesBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Keys()

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    def setUp(self):
        self.fx = Fixture(self.keys)
        self.addCleanup(self.fx.close)
        self.fx.advance("AUTHORIZED")
        self.fx.stage()
        self.store = IsolatedGitStore(self.fx.root)

    def stage(self):
        receipt = self.store.stage(self.fx.view, expected=None)
        deployment = self.keys.attestation("deployment", {"result_stable_sha256": self.fx.result.sha256,
                     "publication_sha256": self.fx.view.envelope_sha256, "git_commit": receipt["git_commit"], "deployment_id": "test-only"})
        self.remote = verify_remote(self.fx.view, DirectoryReader(self.fx.view), deployment, now=NOW)
        return receipt

    def test_actual_git_staging_and_advertisement_cas(self):
        staged = self.stage()
        result = self.store.advertise(self.fx.view, self.fx.approval, self.remote, self.keys.signers["publication"],
                  expected=staged["git_commit"], previous_digest=None, now=NOW)
        self.assertEqual(self.store.head(), result["git_commit"])
        self.assertEqual(result["remote_post_verification"], "UNVERIFIED")
        self.assertNotEqual(result["git_commit"], staged["git_commit"])

    def test_git_commit_is_not_deployment_or_cdn_proof(self):
        staged = self.store.stage(self.fx.view, expected=None)
        self.assertEqual(staged["cdn_atomicity"], "UNVERIFIED")
        with self.assertRaises(PlanningError):
            self.store.advertise(self.fx.view, self.fx.approval, self.fx.remote, self.keys.signers["publication"],
                    expected=staged["git_commit"], previous_digest=None, now=NOW)

    def test_stale_git_head_cannot_overwrite_winner(self):
        staged = self.stage()
        self.store.advertise(self.fx.view, self.fx.approval, self.remote, self.keys.signers["publication"], expected=staged["git_commit"], previous_digest=None, now=NOW)
        with self.assertRaises(PlanningError):
            self.store.stage(self.fx.view, expected=staged["git_commit"])

    def test_immutable_git_file_replacement_rejected(self):
        staged = self.stage()
        path = "v3/views/" + self.fx.result.sha256 + "/test-payload"
        with self.assertRaises(PlanningError):
            self.store._cas({path: b"changed signed bytes"}, staged["git_commit"])

    def test_git_store_refuses_remote_and_symlink(self):
        self.store._run(["config", "remote.origin.url", "https://github.com/Project-Ro-ASD/Ro-Repo"])
        with self.assertRaises(PlanningError):
            IsolatedGitStore(self.fx.root)

    def test_staging_exact_retry_is_idempotent(self):
        first = self.stage()
        second = self.store.stage(self.fx.view, expected=first["git_commit"])
        self.assertEqual(first["git_commit"], second["git_commit"])

    def test_no_unsigned_approval_for_advertisement(self):
        first = self.stage()
        with self.assertRaises(PlanningError):
            self.store.advertise(self.fx.view, {"approved": True}, self.remote, self.keys.signers["publication"], expected=first["git_commit"], previous_digest=None, now=NOW)


if __name__ == "__main__":
    unittest.main()
