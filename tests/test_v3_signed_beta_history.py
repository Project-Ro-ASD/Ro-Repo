import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_signed_beta_history import signed_history, assess
from v3_promotion_planner import PlanningError, plan

A="a"*64
B="b"*64
REG={"producers":[{"components":[
  {"component":"ro-assist","promotion_group":"ro-assist","package_names":["ro-assist"],"architectures":["x86_64"]},
  {"component":"dolphin","promotion_group":"dolphin","package_names":["dolphin"],"architectures":["x86_64"]}]}]}
def pkg(name,release):
    return [{"nevra":f"{name}-0:{release}-1.fc44.{arch}",
             "architecture":arch,"filename":f"{name}-{release}-1.fc44.{arch}.rpm",
             "producer_artifact_sha256":A,"producer_manifest_digest":B,
             "published_signed_artifact_sha256":A} for arch in ("src","x86_64")]
def snapshot(identity,packages):
    return {"schema_version":1,"snapshot_id":identity,"fedora_release":44,"packages":packages}
S1=snapshot("repo-f44-20261001-001",pkg("ro-assist","1.0"))
S2=snapshot("repo-f44-20261009-001",pkg("ro-assist","1.0")+pkg("dolphin","1.0"))
S3=snapshot("repo-f44-20261010-001",pkg("ro-assist","2.0")+pkg("dolphin","1.0"))
def pub(run,snap,date):
    return {"schema_version":1,"channel":"beta","publication_run":run,
            "published_at":date,"snapshot_id":snap,"store_tree_sha256":A}
N="2026-10-10T10:00:00Z"

class SignedHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=pathlib.Path(self.tmp.name)
        self.p=self.root/"pubs";self.s=self.root/"snapshots"
        self.p.mkdir();self.s.mkdir()
        self.snap={x["snapshot_id"]:x for x in (S1,S2,S3)}
        self.pubs={}
        for run,snap,date in (("10",S1,"2026-10-01T12:00:00Z"),
                              ("11",S2,"2026-10-09T12:00:00Z"),
                              ("12",S3,"2026-10-10T09:00:00Z")):
            (self.p/run).mkdir()
            (self.s/snap["snapshot_id"]).mkdir(exist_ok=True)
            self.pubs[run]=pub(run,snap["snapshot_id"],date)
    def tearDown(self):self.tmp.cleanup()
    def read(self,folder,name,keyring):
        if name=="publication-v1.json":
            return self.pubs[folder.name]
        return self.snap[folder.name]
    def history(self):
        with patch("v3_signed_beta_history._keyring",return_value=self.root/"keyring"),patch("v3_signed_beta_history._signature",side_effect=self.read):
            return signed_history(self.p,self.s,REG,"ro-assist","pinned-key",A,N)
    def test_repeat_snapshot_keeps_earliest_same_candidate(self):
        rows=self.history()
        self.assertEqual(len(rows),3)
        self.assertEqual(rows[0]["candidate_sha256"],rows[1]["candidate_sha256"])
        self.assertNotEqual(rows[1]["candidate_sha256"],rows[2]["candidate_sha256"])
        candidate=plan(S2,None,REG,"ro-assist")
        with patch("v3_signed_beta_history._keyring",return_value=self.root/"keyring"),patch("v3_signed_beta_history._signature",side_effect=self.read):
            result=assess(candidate,self.p,self.s,REG,"pinned-key",A,"normal-app","normal",N)
        self.assertEqual(result["first_publication_run"],"10")
        self.assertFalse(result["publishable"])
        self.assertFalse(result["trusted_publication_times_verified"])
    def test_wrong_run_identity_rejected(self):
        self.pubs["10"]["publication_run"]="99"
        with self.assertRaisesRegex(PlanningError,"publication identity mismatch"):self.history()
    def test_future_publication_rejected(self):
        self.pubs["12"]["published_at"]="2026-11-01T12:00:00Z"
        with self.assertRaisesRegex(PlanningError,"future-dated"):self.history()
    def test_missing_archive_entry_rejected(self):
        (self.p/"bad").mkdir()
        with self.assertRaisesRegex(PlanningError,"unexpected beta history"):self.history()
    def test_snapshot_identity_mismatch_rejected(self):
        self.snap[S1["snapshot_id"]]=dict(S1,snapshot_id="repo-f44-20261002-001")
        with self.assertRaisesRegex(PlanningError,"snapshot mismatch"):self.history()
    def test_wrong_candidate_digest_fails_closed(self):
        candidate=plan(S2,None,REG,"ro-assist")
        candidate["candidate_sha256"]="f"*64
        with patch("v3_signed_beta_history._keyring",return_value=self.root/"keyring"),patch("v3_signed_beta_history._signature",side_effect=self.read):
            with self.assertRaisesRegex(PlanningError,"no beta publication evidence"):
                assess(candidate,self.p,self.s,REG,"key",A,"normal-app","normal",N)
    def test_bad_pinned_key_rejected(self):
        from v3_signed_beta_history import _keyring
        key=self.root/"key.asc"
        key.write_text("test-key")
        with self.assertRaisesRegex(PlanningError,"pin mismatch"):
            _keyring(key,"f"*64,self.root)

if __name__=="__main__":
    unittest.main()
