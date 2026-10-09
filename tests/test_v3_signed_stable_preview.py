import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/"tools"))
from v3_signed_stable_preview import create_preview, _pinned_key
from v3_promotion_planner import PlanningError

class SignedStablePreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=pathlib.Path(self.temp.name)
        self.candidate=self.root/"candidate"
        self.candidate.mkdir()
        self.home=self.root/"gnupg";self.home.mkdir()
        self.key=self.root/"public-key.asc";self.key.write_text("fake")
        self.password=self.root/"passphrase";self.password.write_text("")
        self.kw=dict(gnupghome=self.home,metadata_signing_key="A"*40,
                     rpm_signing_key="B"*40,rpm_public_key=self.key,rpm_key_sha256="b"*64,
                     metadata_public_key=self.key,metadata_key_sha256="a"*64,
                     passphrase_file=self.password,workflow_run="10")
    def tearDown(self):self.temp.cleanup()
    def preview(self,**kw):
        return create_preview(self.candidate,self.root/"output","repo-f44-20261010-099",**(self.kw|kw))
    def test_wrong_pinned_key_fails_without_output(self):
        with self.assertRaisesRegex(PlanningError,"SHA256"):self.preview()
        self.assertFalse((self.root/"output").exists())
    def test_reject_existing_output(self):
        (self.root/"output").mkdir()
        with self.assertRaisesRegex(PlanningError,"unsafe"):self.preview()
    def test_reject_output_inside_source(self):
        with self.assertRaisesRegex(PlanningError,"inside candidate"):
            create_preview(self.candidate,self.candidate/"inside","repo-f44-20261010-099",**self.kw)
    def test_reject_bad_snapshot_id(self):
        with self.assertRaisesRegex(PlanningError,"snapshot identifier"):
            create_preview(self.candidate,self.root/"output","../stable",**self.kw)
    def test_reject_invalid_workflow_run(self):
        with self.assertRaisesRegex(PlanningError,"workflow run"):self.preview(workflow_run="latest")
    def test_symlinked_public_key_rejected(self):
        alias=self.root/"link-key";alias.symlink_to(self.key)
        with self.assertRaisesRegex(PlanningError,"unpinned"):
            _pinned_key(alias,"a"*64,"metadata")
if __name__=="__main__": unittest.main()
