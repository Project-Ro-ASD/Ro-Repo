import copy
import hashlib
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/"tools"))
from v3_dnf_receipt import capture_baseline, make_receipt
from v3_group_validation import stable_set_digest
from v3_promotion_planner import PlanningError

H="a"*64
TX={"scope":"offline-v3-transaction-inputs","group":"ro-control","target_arch":"x86_64",
    "names":["ro-control"],"expected_baseline_evr":{"ro-control":"0:9.9.8-1.fc44"},
    "expected_candidate_evr":{"ro-control":"0:9.9.9-1.fc44"},"publishable":False,
    "candidate_targets":["ro-control-0:9.9.9-1.fc44.x86_64"]}
PLAN={"publishable":False,"promotion_group":"ro-control","candidate_sha256":H,
      "candidate_snapshot_id":"repo-f44-20261009-099","stable_base_snapshot_id":None,
      "resulting_stable_packages":[{"nevra":"ro-control-0:9.9.9-1.fc44.x86_64"}]}
MATRIX={"scope":"offline-v3-dnf-matrix-untrusted","publishable":False,"dnf_executed":False,
        "promotion_group":"ro-control","target_arch":"x86_64","candidate_sha256":H,
        "binary_packages":[{"name":"ro-control","nevra":TX["candidate_targets"][0]}]}
PREFLIGHT={"publishable":False,"local_header_checks_passed":True,
           "local_rpm_signature_checks_passed":True,"promotion_group":"ro-control",
           "candidate_sha256":H}
class Receipts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=pathlib.Path(self.temp.name)
        for name in ("clean-install.log","baseline-install.log","upgrade.log"):
            (self.root/name).write_text("real fixture transaction log "+name)
        self.checkpoint=None
    def tearDown(self): self.temp.cleanup()
    def rpm(self,root,names):
        return TX["expected_baseline_evr"] if str(root).endswith("before") else TX["expected_candidate_evr"]
    def baseline(self):
        with patch("v3_dnf_receipt._rpmdb",side_effect=self.rpm):
            return capture_baseline(TX,self.root/"before")
    def receipt(self,plan=None,tx=None,preflight=None,checkpoint=None):
        with patch("v3_dnf_receipt._rpmdb",side_effect=self.rpm):
            return make_receipt(plan or PLAN,MATRIX,tx or TX,preflight or PREFLIGHT,
                                checkpoint or self.baseline(),self.root/"clean",self.root/"after",self.root)
    def test_receipt_ties_log_hashes_to_exact_candidate(self):
        result=self.receipt()
        self.assertEqual(result["stable_set_sha256"],stable_set_digest(PLAN))
        self.assertEqual(set(result["log_sha256"]),{"clean-install.log","baseline-install.log","upgrade.log"})
        self.assertFalse(result["publishable"])
        self.assertFalse(result["ci_identity_authenticated"])
        self.assertEqual(result["checks_observed"],["clean-install","upgrade"])
    def test_missing_log_rejected(self):
        (self.root/"upgrade.log").unlink()
        with self.assertRaisesRegex(PlanningError,"missing or empty"):
            self.receipt()
    def test_bad_baseline_checkpoint_rejected(self):
        bad=self.baseline();bad["installed_evrs"]["ro-control"]="0:0.0-0"
        with self.assertRaisesRegex(PlanningError,"checkpoint"):
            self.receipt(checkpoint=bad)
    def test_wrong_candidate_rejected(self):
        bad=copy.deepcopy(PLAN);bad["candidate_sha256"]="b"*64
        with self.assertRaisesRegex(PlanningError,"candidate"):
            self.receipt(plan=bad)
    def test_unsigned_preflight_rejected(self):
        bad=copy.deepcopy(PREFLIGHT);bad["local_rpm_signature_checks_passed"]=False
        with self.assertRaisesRegex(PlanningError,"preflight"):
            self.receipt(preflight=bad)
    def test_false_baseline_version_rejected(self):
        with patch("v3_dnf_receipt._rpmdb",return_value={"ro-control":"0:9.9.9-1.fc44"}):
            with self.assertRaisesRegex(PlanningError,"RPMDB EVR mismatch"):
                capture_baseline(TX,self.root/"before")
if __name__=="__main__":unittest.main()
