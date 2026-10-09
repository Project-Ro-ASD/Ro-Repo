import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/"tools"))
from v3_dnf_bundle_verify import verify_bundle, _canonical
from v3_group_validation import stable_set_digest
from v3_promotion_planner import PlanningError

H="a"*64
REPO="Project-Ro-ASD/Ro-Repo"
RUN="123456"
COMMIT="c"*40
WORKFLOW="Project-Ro-ASD/Ro-Repo/.github/workflows/test.yml@refs/heads/main"

class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=pathlib.Path(self.tmp.name)
        self.group=self.root/"ro-control"
        self.group.mkdir()
        plan={"publishable":False,"promotion_group":"ro-control","candidate_sha256":H,
              "candidate_snapshot_id":"repo-f44-20261009-001","stable_base_snapshot_id":None,
              "resulting_stable_packages":[{"nevra":"ro-control-0:9.9.9-1.fc44.x86_64"}]}
        matrix={"scope":"offline-v3-dnf-matrix-untrusted","publishable":False,"dnf_executed":False,
                "promotion_group":"ro-control","candidate_sha256":H,"target_arch":"x86_64",
                "binary_packages":[{"name":"ro-control","nevra":"ro-control-0:9.9.9-1.fc44.x86_64"}]}
        tx={"scope":"offline-v3-transaction-inputs","publishable":False,"group":"ro-control",
            "target_arch":"x86_64","names":["ro-control"],
            "candidate_targets":["ro-control-0:9.9.9-1.fc44.x86_64"],
            "expected_candidate_evr":{"ro-control":"0:9.9.9-1.fc44"},
            "expected_baseline_evr":{"ro-control":"0:9.9.8-1.fc44"}}
        preflight={"promotion_group":"ro-control","candidate_sha256":H,"publishable":False,
                   "local_header_checks_passed":True,"local_rpm_signature_checks_passed":True}
        baseline={"scope":"v3-baseline-rpmdb-checkpoint-test-only","group":"ro-control","target_arch":"x86_64",
                  "installed_evrs":tx["expected_baseline_evr"],
                  "transaction_inputs_sha256":hashlib.sha256(_canonical(tx)).hexdigest(),"publishable":False}
        for fn,content in (("promotion-plan-v3.json",plan),("dnf-group-matrix.json",matrix),
                           ("transaction-inputs.json",tx),("preflight.json",preflight),
                           ("baseline-checkpoint.json",baseline)):
            self.write(fn,content)
        log_hashes={}
        for fn in ("clean-install.log","baseline-install.log","upgrade.log"):
            data=("DNF5 actual test output "+fn).encode()
            (self.group/fn).write_bytes(data)
            log_hashes[fn]=hashlib.sha256(data).hexdigest()
        receipt={"scope":"v3-dnf-test-receipt-untrusted","schema_version":1,
                 "promotion_group":"ro-control","architecture":"x86_64",
                 "candidate_sha256":H,"stable_set_sha256":stable_set_digest(plan),
                 "beta_snapshot_id":plan["candidate_snapshot_id"],"stable_base_snapshot_id":None,
                 "preflight_sha256":hashlib.sha256(_canonical(preflight)).hexdigest(),
                 "transaction_inputs_sha256":hashlib.sha256(_canonical(tx)).hexdigest(),
                 "rpmdb":{"baseline_before_upgrade":tx["expected_baseline_evr"],
                          "clean_install":tx["expected_candidate_evr"],
                          "after_upgrade":tx["expected_candidate_evr"]},
                 "log_sha256":log_hashes,
                 "ci_claims_unverified":{"github_repository":REPO,"github_run_id":RUN,
                                         "github_sha":COMMIT,"github_workflow_ref":WORKFLOW,
                                         "runner_image_digest":None},
                 "checks_observed":["clean-install","upgrade"],
                 "ci_identity_authenticated":False,"test_logs_authenticated":False,
                 "file_conflict_test_executed":False,"rpmlint_test_executed":False,
                 "plasma_test_executed":False,"qemu_test_executed":False,
                 "publishable":False}
        self.write("dnf-receipt.json",receipt)
    def tearDown(self):self.tmp.cleanup()
    def write(self,name,data): (self.group/name).write_bytes(_canonical(data)+b"\n")
    def check(self):
        return verify_bundle(self.root,["ro-control"],repository=REPO,run_id=RUN,commit=COMMIT,workflow_ref=WORKFLOW)
    def test_valid_bundle_is_not_authenticated(self):
        result=self.check()
        self.assertEqual(len(result["groups"]),1)
        self.assertTrue(result["groups"][0]["local_integrity_passed"])
        self.assertFalse(result["ci_authenticity_verified"])
        self.assertFalse(result["publishable"])
    def test_modified_log_rejected(self):
        (self.group/"upgrade.log").write_text("tampered")
        with self.assertRaisesRegex(PlanningError,"log was changed"):self.check()
    def test_modified_candidate_rejected(self):
        p=json.loads((self.group/"promotion-plan-v3.json").read_text());p["candidate_sha256"]="b"*64
        self.write("promotion-plan-v3.json",p)
        with self.assertRaises(PlanningError):self.check()
    def test_wrong_run_rejected(self):
        with self.assertRaisesRegex(PlanningError,"CI claims"):
            verify_bundle(self.root,["ro-control"],repository=REPO,run_id="999",commit=COMMIT,workflow_ref=WORKFLOW)
    def test_missing_group_or_extra_files_rejected(self):
        (self.group/"extra.json").write_text("{}")
        with self.assertRaisesRegex(PlanningError,"missing, extra"):self.check()
    def test_false_authentication_rejected(self):
        r=json.loads((self.group/"dnf-receipt.json").read_text());r["ci_identity_authenticated"]=True
        self.write("dnf-receipt.json",r)
        with self.assertRaisesRegex(PlanningError,"overstate"):self.check()
    def test_symlinked_evidence_rejected(self):
        p=self.group/"upgrade.log";p.unlink();p.symlink_to(self.group/"clean-install.log")
        with self.assertRaisesRegex(PlanningError,"unsafe"):self.check()

if __name__=="__main__":unittest.main()
