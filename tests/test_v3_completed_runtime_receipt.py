import copy
import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_completed_runtime_receipt import verify_receipt
from v3_promotion_planner import PlanningError
from v3_actions_run_context import REPO, REPOSITORY_ID, WORKFLOW, JOB

class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.subject = {
            "repository": REPO, "repository_id": REPOSITORY_ID,
            "workflow_path": WORKFLOW, "commit": "a"*40,
            "run_id": "123", "run_attempt": 1, "job_id": "456",
            "job_name": JOB, "runner_name": "GitHub Actions 1",
            "runner_group_name": "GitHub Actions", "actor": "maintainer",
            "run_started_at": "2026-10-11T10:00:00Z",
            "job_started_at": "2026-10-11T10:01:00Z",
        }
        self.receipt = {
            "scope": "v3-readonly-github-runtime-consistency-test-only",
            "checked_identity": self.subject,
            "publishable": False, "approval_granted": False,
            "oidc_identity_verified": False,
            "protected_environment_approval_verified": False,
            "runtime_claims_cryptographically_attested": False,
        }
        self.sign()
        self.run = {
            "id": 123, "repository": {"id": REPOSITORY_ID},
            "path": WORKFLOW, "event": "workflow_dispatch",
            "head_branch": "main", "head_sha": "a"*40,
            "run_attempt": 1, "status": "completed", "conclusion": "success",
            "actor": {"login": "maintainer"},
            "triggering_actor": {"login": "maintainer"},
            "updated_at": "2026-10-11T10:05:00Z",
        }
        self.jobs = [{
            "id": 456, "run_id": 123, "name": JOB,
            "run_attempt": 1, "head_sha": "a"*40,
            "status": "completed", "conclusion": "success",
            "runner_name": "GitHub Actions 1",
            "runner_group_name": "GitHub Actions",
            "started_at": "2026-10-11T10:01:00Z",
            "completed_at": "2026-10-11T10:04:00Z",
        }]
        self.artifacts = [{
            "name": "v3-actions-context-123-1", "expired": False,
            "size_in_bytes": 1234,
            "workflow_run": {"id": 123, "head_sha": "a"*40},
        }]

    def sign(self):
        self.receipt["identity_sha256"] = hashlib.sha256(
            json.dumps(self.subject, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def check(self):
        return verify_receipt(self.receipt, self.run, self.jobs, self.artifacts)

    def test_completed_receipt_remains_untrusted(self):
        r = self.check()
        self.assertFalse(r["publishable"])
        self.assertFalse(r["oidc_verified"])
        self.assertFalse(r["artifact_bytes_authenticated_by_this_check"])

    def test_tampered_receipt_rejected(self):
        self.subject["actor"] = "attacker"
        with self.assertRaisesRegex(PlanningError, "digest mismatch"):
            self.check()

    def test_completed_failure_rejected(self):
        self.run["conclusion"] = "failure"
        with self.assertRaisesRegex(PlanningError, "run mismatches"):
            self.check()

    def test_replay_attempt_rejected(self):
        self.jobs[0]["run_attempt"] = 2
        with self.assertRaisesRegex(PlanningError, "job mismatches"):
            self.check()

    def test_unexpected_second_job_rejected(self):
        self.jobs.append(copy.deepcopy(self.jobs[0]))
        with self.assertRaisesRegex(PlanningError, "unexpected completed"):
            self.check()

    def test_wrong_runner_rejected(self):
        self.jobs[0]["runner_group_name"] = "untrusted"
        with self.assertRaisesRegex(PlanningError, "job mismatches"):
            self.check()

    def test_wrong_artifact_run_rejected(self):
        self.artifacts[0]["workflow_run"]["id"] = 999
        with self.assertRaisesRegex(PlanningError, "artifact metadata"):
            self.check()

    def test_expired_artifact_rejected(self):
        self.artifacts[0]["expired"] = True
        with self.assertRaisesRegex(PlanningError, "artifact metadata"):
            self.check()

    def test_impossible_timeline_rejected(self):
        self.jobs[0]["completed_at"] = "2026-10-11T10:06:00Z"
        with self.assertRaisesRegex(PlanningError, "timeline"):
            self.check()

    def test_forbidden_authority_claim_rejected(self):
        self.receipt["publishable"] = True
        with self.assertRaisesRegex(PlanningError, "forbidden authority"):
            self.check()

if __name__ == "__main__":
    unittest.main()
