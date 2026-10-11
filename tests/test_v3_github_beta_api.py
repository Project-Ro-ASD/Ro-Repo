import pathlib
import sys
import unittest

sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/"tools"))
from v3_github_beta_api import collect, audit
from v3_promotion_planner import PlanningError

REPO="Project-Ro-ASD/Ro-Repo"
def item(i):
    return {"id":i,"status":"completed","conclusion":"success"}

class CollectorTests(unittest.TestCase):
    def fixture(self,path,token):
        self.assertEqual(token,"test-token")
        if "/workflows/" in path:
            if "page=1" in path:return {"total_count":3,"workflow_runs":[item(10),item(11)]}
            return {"total_count":3,"workflow_runs":[item(12)]}
        return {"total_count":1,"jobs":[{"id":int(path.split("/runs/")[1].split("/")[0]),"name":"verify-remote-beta"}]}
    def test_paginated_collection(self):
        result=collect(REPO,"test-token",self.fixture,page_size=2)
        self.assertEqual(result["total_workflow_runs"],3)
        self.assertEqual(len(result["job_details"]),3)
        self.assertFalse(result["publishable"])
        self.assertFalse(result["archive_completeness_verified"])
    def test_duplicate_runs_rejected(self):
        def duplicate(path,token):
            if "/workflows/" in path:
                return {"total_count":2,"workflow_runs":[item(10),item(10)]}
            return {}
        with self.assertRaisesRegex(PlanningError,"duplicate"):collect(REPO,"token",duplicate)
    def test_truncated_pagination_rejected(self):
        def truncated(path,token):
            return {"total_count":3,"workflow_runs":[]}
        with self.assertRaisesRegex(PlanningError,"truncated"):collect(REPO,"token",truncated)
    def test_invalid_repo_rejected(self):
        with self.assertRaisesRegex(PlanningError,"repository"):collect("../oops","token",self.fixture)
    def test_missing_token_rejected(self):
        with self.assertRaisesRegex(PlanningError,"repository/token"):collect(REPO,"",self.fixture)
    def test_audit_never_promotes(self):
        collection={"publishable":False,"run_details":[],"job_details":[],"total_workflow_runs":0}
        with self.assertRaises(PlanningError):audit(collection,[],"2026-10-11T00:00:00Z")

if __name__=="__main__":unittest.main()
