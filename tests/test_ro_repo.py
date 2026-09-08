import datetime as dt, hashlib, json, pathlib, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
import ro_repo

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=pathlib.Path(self.tmp.name); self.artifacts=self.root/"artifacts"; self.artifacts.mkdir()
        self.rpm=self.artifacts/"ro-control-1.0-1.fc44.x86_64.rpm"; self.rpm.write_bytes(b"producer-rpm")
        self.srpm=self.artifacts/"ro-control-1.0-1.fc44.src.rpm"; self.srpm.write_bytes(b"source-rpm")
        self.manifest={"schema_version":1,"component":"ro-control","source_repository":"Project-Ro-ASD/ro-Control","source_commit":"a"*40,"release_tag":"v1.0","release_id":10,"workflow_run":20,"fedora_release":44,"artifacts":[
          {"filename":self.rpm.name,"name":"ro-control","epoch":0,"version":"1.0","release":"1.fc44","architecture":"x86_64","source_rpm":self.srpm.name,"producer_artifact_sha256":ro_repo.digest(self.rpm)},
          {"filename":self.srpm.name,"name":"ro-control","epoch":0,"version":"1.0","release":"1.fc44","architecture":"src","source_rpm":None,"producer_artifact_sha256":ro_repo.digest(self.srpm)}],"provenance":{"provider":"github","subject_digest":"b"*64},"attestation":{"provider":"github","verification":"github-attestation"}}
        self.mp=self.root/"manifest.json"; self.mp.write_text(json.dumps(self.manifest)); self.config=pathlib.Path(__file__).parents[1]/"config/producers-v1.yaml"
    def tearDown(self): self.tmp.cleanup()
    def headers(self,path):
        source=path.name.endswith("src.rpm"); return {"name":"ro-control","epoch":0,"version":"1.0","release":"1.fc44","architecture":"src" if source else "x86_64","source_rpm":None if source else self.srpm.name,"nevra":"ro-control-0:1.0-1.fc44."+("src" if source else "x86_64")}
    def test_valid_component_and_acceptance(self):
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers): ro_repo.verify_component(self.mp,self.artifacts,self.config); ro_repo.accept(self.mp,self.artifacts,self.root/"accepted",self.config)
        self.assertTrue(list((self.root/"accepted").rglob("acceptance-evidence-v1.json")))
    def test_digest_mutation_is_rejected(self):
        self.rpm.write_bytes(b"mutated")
        with self.assertRaisesRegex(ro_repo.ContractError,"digest mismatch"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_missing_srpm_is_rejected(self):
        self.manifest["artifacts"]=self.manifest["artifacts"][:1]; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"missing matching SRPM"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_fedora_collision_is_default_deny(self):
        names=self.root/"names"; names.write_text("ro-control\n")
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"collision denied"): ro_repo.verify_component(self.mp,self.artifacts,self.config,names)
    def test_promotion_wait_is_enforced(self):
        p={"schema_version":1,"snapshot_id":"repo-f44-20260908-001","from":"beta","to":"stable","risk_class":"normal-app","promotion_group":"ro-control","beta_started_at":dt.datetime.now(dt.timezone.utc).isoformat(),"evidence":["tests.json"],"approved_by":"maintainer","approved_at":dt.datetime.now(dt.timezone.utc).isoformat(),"emergency":False,"reason":""}; path=self.root/"promotion.json"; path.write_text(json.dumps(p))
        with self.assertRaisesRegex(ro_repo.ContractError,"7 days"): ro_repo.promote(self.root,path,"test")

    def test_latest_release_id_is_rejected(self):
        self.manifest["release_id"]="latest"; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"latest is forbidden"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_wrong_fedora_release_is_rejected(self):
        self.manifest["fedora_release"]=43; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaises(ro_repo.ContractError): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_architecture_denied(self):
        self.manifest["artifacts"][0]["architecture"]="ppc64le"; self.mp.write_text(json.dumps(self.manifest))
        def mock_headers(path): h=self.headers(path); h["architecture"]=h["architecture"] if path.name.endswith("src.rpm") else "ppc64le"; return h
        with mock.patch.object(ro_repo,"rpm_header",side_effect=mock_headers), self.assertRaisesRegex(ro_repo.ContractError,"architecture denied"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_invalid_commit_sha_rejected(self):
        self.manifest["source_commit"]="a"*39; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"SHA"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_package_name_denied(self):
        self.manifest["component"]="evil-pkg"; self.manifest["artifacts"][0]["name"]="evil-pkg"; self.mp.write_text(json.dumps(self.manifest))
        def mock_headers(path): h=self.headers(path); h["name"]="evil-pkg"; return h
        with mock.patch.object(ro_repo,"rpm_header",side_effect=mock_headers), self.assertRaisesRegex(ro_repo.ContractError,"package name denied"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_promotion_emergency_bypass(self):
        out=self.root/"out"; pub=out/"publication/rpm/fedora/44/beta"; pub.mkdir(parents=True)
        from ro_repo import save; save(pub/"publication-v1.json",{"schema_version":1,"channel":"beta","snapshot_id":"repo-f44-20260908-001","published_at":"2026-09-08T00:00:00Z","publication_run":"test"})
        p={"schema_version":1,"snapshot_id":"repo-f44-20260908-001","from":"beta","to":"stable","risk_class":"normal-app","promotion_group":"ro-control","beta_started_at":dt.datetime.now(dt.timezone.utc).isoformat(),"evidence":["dependency-solve","clean-install","upgrade","file-conflict","rpmlint","smoke"],"approved_by":"maintainer","approved_at":dt.datetime.now(dt.timezone.utc).isoformat(),"emergency":True,"reason":"CVE-2026-0001"}; path=self.root/"promotion.json"; path.write_text(json.dumps(p))
        with mock.patch.object(ro_repo,"verify_snapshot"), mock.patch.object(ro_repo,"publish"): ro_repo.promote(out,path,"test")
    def test_promotion_critical_system_requires_14_days(self):
        p={"schema_version":1,"snapshot_id":"repo-f44-20260908-001","from":"beta","to":"stable","risk_class":"critical-system","promotion_group":"ro-control","beta_started_at":(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=10)).isoformat(),"evidence":["dependency-solve","clean-install","upgrade","file-conflict","rpmlint","smoke","boot","reboot","recovery","qemu"],"approved_by":"maintainer","approved_at":dt.datetime.now(dt.timezone.utc).isoformat(),"emergency":False,"reason":""}; path=self.root/"promotion.json"; path.write_text(json.dumps(p))
        with self.assertRaisesRegex(ro_repo.ContractError,"14 days"): ro_repo.promote(self.root,path,"test")
    def test_promotion_missing_evidence_rejected(self):
        out=self.root/"out"; pub=out/"publication/rpm/fedora/44/beta"; pub.mkdir(parents=True)
        from ro_repo import save; save(pub/"publication-v1.json",{"schema_version":1,"channel":"beta","snapshot_id":"repo-f44-20260908-001","published_at":"2026-09-08T00:00:00Z","publication_run":"test"})
        p={"schema_version":1,"snapshot_id":"repo-f44-20260908-001","from":"beta","to":"stable","risk_class":"normal-app","promotion_group":"ro-control","beta_started_at":(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=8)).isoformat(),"evidence":["smoke"],"approved_by":"maintainer","approved_at":dt.datetime.now(dt.timezone.utc).isoformat(),"emergency":False,"reason":""}; path=self.root/"promotion.json"; path.write_text(json.dumps(p))
        with self.assertRaisesRegex(ro_repo.ContractError,"evidence"): ro_repo.promote(out,path,"test")
    def test_rollback_no_previous_raises(self):
        with self.assertRaises(ro_repo.ContractError): ro_repo.rollback(self.root,"beta")
    def test_duplicate_filename_rejected(self):
        self.manifest["artifacts"].append(self.manifest["artifacts"][0]); self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"duplicate"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_snapshot_lifecycle_separation(self):
        snap=self.root/"snapshot"; snap.mkdir(); m={"schema_version":1,"snapshot_id":"snapshot","target_channel":"stable","created_at":"2026-09-08T00:00:00Z","fedora_release":44,"parent_snapshot":None,"packages":[],"repositories":{},"rpm_signing_fingerprint":"X","metadata_signing_fingerprint":"X","creation_provenance":{"tool":"test","run":"local"}}
        (snap/"repository-snapshot-v1.json").write_text(json.dumps(m))
        with self.assertRaisesRegex(ro_repo.ContractError,"lifecycle"): ro_repo.verify_snapshot(snap)

if __name__ == "__main__": unittest.main()
