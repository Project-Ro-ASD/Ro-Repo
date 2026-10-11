import copy
import pathlib
import sys
import unittest

sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/"tools"))
from v3_github_beta_audit import validate_history, assess
from v3_promotion_planner import PlanningError

def fixture(run_id, day, candidate):
    start=f"2026-10-{day}T12:00:00Z"
    stamp=lambda minute:f"2026-10-{day}T12:{minute:02d}:00Z"
    row={"publication_run":str(run_id),"published_at":stamp(5),
         "promotion_group":"ro-assist","candidate_sha256":candidate}
    run={"id":run_id,"path":".github/workflows/publish-remote-beta.yml",
         "event":"workflow_dispatch","status":"completed","conclusion":"success",
         "head_branch":"main","head_sha":"a"*40,"run_attempt":1,
         "run_started_at":start,"updated_at":stamp(15)}
    jobs={"run_id":run_id,"jobs":[
        {"name":n,"run_id":run_id,"status":"completed","conclusion":"success",
         "started_at":stamp(i),"completed_at":stamp(i+2)}
        for n,i in zip(("sign-beta-publication","publish-beta","verify-remote-beta"),(1,4,8))]}
    return row,run,jobs

class GitHubBetaTests(unittest.TestCase):
    def setUp(self):
        a=fixture(100,"01","a"*64)
        b=fixture(200,"08","a"*64)
        c=fixture(300,"09","b"*64)
        self.rows=[a[0],b[0],c[0]]
        self.runs=[a[1],b[1],c[1]]
        self.jobs=[a[2],b[2],c[2]]
        self.now="2026-10-10T12:00:00Z"
    def check(self):
        return validate_history(self.rows,self.runs,self.jobs,self.now)
    def test_first_seen_survives_new_snapshot(self):
        x=self.check()
        self.assertEqual(x[0]["published_at"],"2026-10-01T12:10:00Z")
        result=assess({"promotion_group":"ro-assist","candidate_sha256":"a"*64},
                      self.rows,self.runs,self.jobs,"normal-app","normal",self.now)
        self.assertEqual(result["first_publication_run"],"100")
        self.assertFalse(result["github_api_provenance_authenticated"])
        self.assertFalse(result["publishable"])
    def test_incomplete_github_run_and_job_evidence_rejected(self):
        # Removing a run but retaining its jobs must fail before signed
        # publication coverage is evaluated.
        self.runs.pop()
        with self.assertRaisesRegex(PlanningError,"run and job evidence sets disagree"):
            self.check()
    def test_signed_publication_missing_from_complete_github_evidence_rejected(self):
        # With complete and consistent GitHub runs/jobs, a missing signed
        # publication is a distinct archive-coverage failure.
        self.rows.pop()
        with self.assertRaisesRegex(PlanningError,"incomplete GitHub beta archive coverage"):
            self.check()
    def bundle(self):
        return {"scope":"v3-signed-beta-archive-bundle-untrusted",
                "promotion_group":"ro-assist",
                "signed_publications":[
                    {"publication_run":r["publication_run"],"published_at":r["published_at"],
                     "snapshot_id":"repo-f44-20261001-001","store_tree_sha256":"f"*64,
                     "candidate_sha256":r["candidate_sha256"]} for r in self.rows],
                "candidate_history":copy.deepcopy(self.rows),
                "archive_completeness_verified":False,
                "trusted_publication_times_verified":False,"publishable":False}

    def test_unrelated_beta_still_audited_but_not_candidate(self):
        # Run 50 is an earlier beta publication without selected RPMs.
        unrelated=fixture(50,"01","f"*64)
        self.runs.append(unrelated[1]);self.jobs.append(unrelated[2])
        bundle=self.bundle()
        bundle["signed_publications"].append({
            "publication_run":"50","published_at":unrelated[0]["published_at"],
            "snapshot_id":"repo-f44-20261001-001",
            "store_tree_sha256":"f"*64,"candidate_sha256":None})
        verified=validate_history(bundle,self.runs,self.jobs,self.now)
        self.assertEqual([r["publication_run"] for r in verified],["100","200","300"])
        bundle["signed_publications"].pop()
        with self.assertRaisesRegex(PlanningError,"coverage"):
            validate_history(bundle,self.runs,self.jobs,self.now)

    def test_signed_candidate_selection_cannot_be_forged(self):
        bundle=self.bundle()
        bundle["candidate_history"][0]["candidate_sha256"]="e"*64
        with self.assertRaisesRegex(PlanningError,"selection mismatch"):
            validate_history(bundle,self.runs,self.jobs,self.now)

    def test_unselected_run_still_requires_successful_remote_verification(self):
        bundle=self.bundle()
        bundle["signed_publications"][0]["candidate_sha256"]=None
        bundle["candidate_history"].pop(0)
        self.jobs[0]["jobs"][2]["conclusion"]="failure"
        with self.assertRaisesRegex(PlanningError,"unsuccessful"):
            validate_history(bundle,self.runs,self.jobs,self.now)

    def test_wrong_workflow_rejected(self):
        self.runs[0]["path"]=".github/workflows/another.yml"
        with self.assertRaisesRegex(PlanningError,"not trusted"):
            self.check()
    def test_failed_remote_verify_rejected(self):
        self.jobs[0]["jobs"][2]["conclusion"]="failure"
        with self.assertRaisesRegex(PlanningError,"unsuccessful"):
            self.check()
    def test_timestamp_earlier_than_run_rejected(self):
        self.rows[0]["published_at"]="2026-09-01T00:00:00Z"
        with self.assertRaisesRegex(PlanningError,"outside"):
            self.check()
    def test_run_rerun_rejected(self):
        self.runs[0]["run_attempt"]=2
        with self.assertRaisesRegex(PlanningError,"not trusted"):
            self.check()
    def test_out_of_order_jobs_rejected(self):
        self.jobs[0]["jobs"][2]["started_at"]="2026-10-01T12:02:00Z"
        with self.assertRaisesRegex(PlanningError,"ordering"):
            self.check()
    def test_duplicate_job_rejected(self):
        self.jobs[0]["jobs"][2]["name"]="publish-beta"
        with self.assertRaisesRegex(PlanningError,"incomplete"):
            self.check()

if __name__=="__main__":unittest.main()
