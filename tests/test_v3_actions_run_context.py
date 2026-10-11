import copy
import datetime as dt
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_actions_run_context import verify_context, REPO, REPOSITORY_ID, WORKFLOW, JOB
from v3_promotion_planner import PlanningError

SHA = "a"*40
NOW = "2026-10-11T19:00:00Z"

class ContextTests(unittest.TestCase):
    def setUp(self):
        self.env = {
            "GITHUB_REPOSITORY": REPO, "GITHUB_REPOSITORY_ID": str(REPOSITORY_ID),
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": SHA, "GITHUB_RUN_ID": "123456",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_REF": REPO+"/"+WORKFLOW+"@refs/heads/main",
            "GITHUB_JOB": JOB, "GITHUB_ACTOR": "maintainer",
            "RUNNER_NAME": "GitHub Actions 123", "RUNNER_GROUP_NAME": "GitHub Actions",
        }
        self.run = {
            "id": 123456, "path": WORKFLOW, "event":"workflow_dispatch",
            "head_branch":"main", "head_sha":SHA, "run_attempt":1,
            "status":"in_progress", "conclusion":None,
            "actor":{"login":"maintainer"}, "triggering_actor":{"login":"maintainer"},
            "repository":{"id":REPOSITORY_ID},
            "run_started_at":"2026-10-11T18:58:00Z",
        }
        self.job = {
            "id":999, "name":JOB, "run_id":123456,"run_attempt":1,
            "head_sha":SHA,"status":"in_progress","conclusion":None,
            "runner_name":"GitHub Actions 123","runner_group_name":"GitHub Actions",
            "started_at":"2026-10-11T18:59:00Z",
        }
    def api(self,path,token):
        self.assertEqual(token,"test-token")
        if path == "/repos/"+REPO:
            return {"id":REPOSITORY_ID,"full_name":REPO}
        if path.endswith("/git/ref/heads/main"):
            return {"ref":"refs/heads/main","object":{"sha":SHA,"type":"commit"}}
        if path.endswith("/actions/runs/123456"):
            return self.run
        if "/jobs?" in path:
            return {"total_count":1,"jobs":[self.job]}
        self.fail(path)
    def check(self):
        return verify_context(self.env,"test-token",self.api,now=NOW)
    def test_valid_context_remains_untrusted(self):
        result=self.check()
        self.assertFalse(result["publishable"])
        self.assertFalse(result["oidc_identity_verified"])
        self.assertFalse(result["protected_environment_approval_verified"])
        self.assertEqual(result["checked_identity"]["job_id"],"999")
    def test_replay_attempt_fails(self):
        self.run["run_attempt"]=2
        with self.assertRaisesRegex(PlanningError,"run identity"):self.check()
    def test_wrong_workflow_fails(self):
        self.run["path"]=".github/workflows/promote-remote-stable.yml"
        with self.assertRaisesRegex(PlanningError,"run identity"):self.check()
    def test_forged_job_runner_fails(self):
        self.job["runner_name"]="other runner"
        with self.assertRaisesRegex(PlanningError,"job identity"):self.check()
    def test_wrong_actor_fails(self):
        self.run["actor"]["login"]="stranger"
        with self.assertRaisesRegex(PlanningError,"run identity"):self.check()
    def test_missing_env_fails(self):
        del self.env["GITHUB_JOB"]
        with self.assertRaisesRegex(PlanningError,"incomplete"):self.check()
    def test_stale_run_fails(self):
        self.run["run_started_at"]="2026-10-01T00:00:00Z"
        with self.assertRaisesRegex(PlanningError,"stale"):self.check()
    def test_duplicate_jobs_fail(self):
        def duplicate(path,token):
            if "/jobs?" in path:
                return {"total_count":2,"jobs":[self.job,copy.deepcopy(self.job)]}
            return self.api(path,token)
        with self.assertRaisesRegex(PlanningError,"duplicate"):
            verify_context(self.env,"test-token",duplicate,now=NOW)
    def test_extra_job_fails(self):
        def extra(path,token):
            if "/jobs?" in path:
                return {"total_count":2,"jobs":[self.job,dict(self.job,id=1000,name="unexpected")]}
            return self.api(path,token)
        with self.assertRaisesRegex(PlanningError,"extra"):
            verify_context(self.env,"test-token",extra,now=NOW)
    def test_main_commit_change_fails(self):
        def changed(path,token):
            if path.endswith("/git/ref/heads/main"):
                return {"ref":"refs/heads/main","object":{"sha":"b"*40,"type":"commit"}}
            return self.api(path,token)
        with self.assertRaisesRegex(PlanningError,"main commit changed"):
            verify_context(self.env,"test-token",changed,now=NOW)

if __name__=="__main__":
    unittest.main()
