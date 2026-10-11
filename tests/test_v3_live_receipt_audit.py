import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_live_receipt_audit import collect_evidence, audit_live_run, _allowed_redirect
from v3_promotion_planner import PlanningError
from v3_actions_run_context import REPO

ROOT="/repos/"+REPO
RUN="123"

class LiveReceiptTests(unittest.TestCase):
    def setUp(self):
        self.run={"id":123,"status":"completed","conclusion":"success",
                  "event":"workflow_dispatch","head_branch":"main",
                  "run_attempt":1,"head_sha":"a"*40,"updated_at":"2026-10-11T12:00:00Z"}
        self.jobs=[{"id":321}]
        self.artifacts=[{"id":456}]
        self.downloaded=False
    def api(self,path,token):
        self.assertEqual(token,"test-token")
        if path==ROOT+"/actions/runs/"+RUN:
            return self.run
        if path.endswith("/jobs?per_page=100&page=1"):
            return {"total_count":len(self.jobs),"jobs":self.jobs}
        if path.endswith("/artifacts?per_page=100&page=1"):
            return {"total_count":len(self.artifacts),"artifacts":self.artifacts}
        self.fail("unexpected API "+path)
    def download(self,id,token,path):
        self.assertEqual(id,456)
        self.downloaded=True
        path.write_bytes(b"fake-fixture-zip")
    def test_live_validation_never_authorizes_publication(self):
        with patch("v3_live_receipt_audit.verify_artifact_zip",return_value={
            "artifact_id":456,"receipt_identity_sha256":"f"*64}) as verifier:
            result=audit_live_run(RUN,"test-token",self.api,self.download)
        verifier.assert_called_once()
        self.assertTrue(self.downloaded)
        self.assertFalse(result["publishable"])
        self.assertFalse(result["oidc_attestation_verified"])
    def test_failed_run_blocks_download(self):
        self.run["conclusion"]="failure"
        with self.assertRaisesRegex(PlanningError,"did not complete"):
            audit_live_run(RUN,"test-token",self.api,self.download)
        self.assertFalse(self.downloaded)
    def test_duplicate_artifacts_rejected(self):
        self.artifacts=[{"id":456},{"id":456}]
        with self.assertRaisesRegex(PlanningError,"duplicate"):
            collect_evidence(RUN,"test-token",self.api)
    def test_extra_artifact_rejected(self):
        self.artifacts=[{"id":456},{"id":789}]
        with self.assertRaisesRegex(PlanningError,"exactly one"):
            collect_evidence(RUN,"test-token",self.api)
    def test_invalid_run_id_blocks_api(self):
        with self.assertRaisesRegex(PlanningError,"identifier"):
            collect_evidence("../123","test-token",self.api)
    def test_changed_run_after_verification_rejected(self):
        calls=[0]
        def changed(path,token):
            if path==ROOT+"/actions/runs/"+RUN:
                calls[0]+=1
                if calls[0]>1:
                    return dict(self.run,head_sha="b"*40)
            return self.api(path,token)
        with patch("v3_live_receipt_audit.verify_artifact_zip",return_value={
            "artifact_id":456,"receipt_identity_sha256":"f"*64}):
            with self.assertRaisesRegex(PlanningError,"changed during verification"):
                audit_live_run(RUN,"test-token",changed,self.download)
    def test_redirect_rejects_insecure_or_foreign_hosts(self):
        for url in ("http://objects.githubusercontent.com/x",
                    "https://evil.example/x",
                    "https://objects.githubusercontent.com.evil.test/x",
                    "https://user@objects.githubusercontent.com/x"):
            with self.subTest(url=url):
                self.assertFalse(_allowed_redirect(url))
        self.assertTrue(_allowed_redirect("https://objects.githubusercontent.com/asset"))

if __name__=="__main__":
    unittest.main()
