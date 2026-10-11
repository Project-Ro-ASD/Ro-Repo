import copy
import hashlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_actions_zip_receipt import verify_artifact_zip, MEMBER
from v3_promotion_planner import PlanningError
from test_v3_completed_runtime_receipt import ReceiptTests

REPO = "Project-Ro-ASD/Ro-Repo"

class ArtifactByteTests(unittest.TestCase):
    def setUp(self):
        fixture = ReceiptTests()
        fixture.setUp()
        self.addCleanup(lambda: fixture.doCleanups())
        self.receipt = copy.deepcopy(fixture.receipt)
        self.run = copy.deepcopy(fixture.run)
        self.jobs = copy.deepcopy(fixture.jobs)
        self.artifacts = copy.deepcopy(fixture.artifacts)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.file = pathlib.Path(self.tmp.name)/"receipt.zip"
        self.zip_with([(MEMBER, json.dumps(self.receipt).encode())])

    def zip_with(self, entries):
        with zipfile.ZipFile(self.file, "w", zipfile.ZIP_DEFLATED) as z:
            for name, value in entries:
                z.writestr(name, value)
        digest = hashlib.sha256(self.file.read_bytes()).hexdigest()
        artifact = self.artifacts[0]
        artifact.update({
            "id": 777, "digest": "sha256:"+digest,
            "url": "https://api.github.com/repos/"+REPO+"/actions/artifacts/777",
            "archive_download_url": "https://api.github.com/repos/"+REPO+"/actions/artifacts/777/zip",
            "size_in_bytes": self.file.stat().st_size,
        })
        artifact["workflow_run"]["repository_id"] = 1159460821

    def check(self):
        return verify_artifact_zip(self.file, self.run, self.jobs, self.artifacts)

    def test_correct_zip_and_run_never_approve(self):
        result = self.check()
        self.assertTrue(result["artifact_zip_matches_supplied_github_api_digest"])
        self.assertFalse(result["publishable"])
        self.assertFalse(result["oidc_signature_verified"])

    def test_modified_zip_digest_rejected(self):
        self.file.write_bytes(self.file.read_bytes()+b"tampering")
        with self.assertRaisesRegex(PlanningError, "digest mismatch"):
            self.check()

    def test_wrong_artifact_digest_rejected(self):
        self.artifacts[0]["digest"]="sha256:"+"0"*64
        with self.assertRaisesRegex(PlanningError, "digest mismatch"):
            self.check()

    def test_unexpected_extra_member_rejected(self):
        self.zip_with([(MEMBER,json.dumps(self.receipt).encode()), ("extra", b"x")])
        with self.assertRaisesRegex(PlanningError, "members"):
            self.check()

    def test_path_traversal_rejected(self):
        self.zip_with([("../"+MEMBER,json.dumps(self.receipt).encode())])
        with self.assertRaisesRegex(PlanningError, "members"):
            self.check()

    def test_malformed_receipt_json_rejected(self):
        self.zip_with([(MEMBER,b"{not json}")])
        with self.assertRaisesRegex(PlanningError, "JSON"):
            self.check()

    def test_duplicate_json_keys_rejected(self):
        self.zip_with([(MEMBER,b'{"publishable":false,"publishable":true}')])
        with self.assertRaisesRegex(PlanningError, "duplicate"):
            self.check()

    def test_different_run_rejected(self):
        self.run["id"]=124
        with self.assertRaisesRegex(PlanningError, "run mismatches"):
            self.check()

    def test_wrong_artifact_owner_rejected(self):
        self.artifacts[0]["workflow_run"]["repository_id"]=999
        with self.assertRaisesRegex(PlanningError, "artifact identity"):
            self.check()

    def test_expired_artifact_rejected(self):
        self.artifacts[0]["expired"]=True
        with self.assertRaisesRegex(PlanningError, "artifact metadata"):
            self.check()

    def test_missing_zip_rejected(self):
        self.file.unlink()
        with self.assertRaisesRegex(PlanningError, "missing or unsafe"):
            self.check()

if __name__=="__main__":
    unittest.main()
