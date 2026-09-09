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
    def write_attestation(self, directory, name, path, commit=None, workflow=True):
        data = [{
            "verificationResult": {
                "statement": {
                    "subject": [{"name": name, "digest": {"sha256": ro_repo.digest(path)}}],
                    "predicate": {
                        "buildDefinition": {
                            "externalParameters": {
                                "repository": "https://github.com/Project-Ro-ASD/ro-Control",
                                "workflow": "Project-Ro-ASD/ro-Control/.github/workflows/release.yml"
                            }
                        },
                        "invocation": {
                            "configSource": {
                                "digest": {"sha1": commit or self.manifest["source_commit"]}
                            }
                        }
                    }
                }
            }
        }]
        if not workflow:
            data[0]["verificationResult"]["statement"]["predicate"]["buildDefinition"]["externalParameters"].pop("workflow")
        (directory / f"{name}.json").write_text(json.dumps(data))
    def test_valid_component_and_acceptance(self):
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers): ro_repo.verify_component(self.mp,self.artifacts,self.config); ro_repo.accept(self.mp,self.artifacts,self.root/"accepted",self.config,test_only_allow_unattested=True)
        self.assertTrue(list((self.root/"accepted").rglob("acceptance-evidence-v1.json")))
    def test_attestation_exact_match_acceptance(self):
        attest=self.root/"attestations"; attest.mkdir()
        self.write_attestation(attest,self.rpm.name,self.rpm)
        self.write_attestation(attest,self.srpm.name,self.srpm)
        self.write_attestation(attest,self.mp.name,self.mp)
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers):
            ro_repo.accept(self.mp,self.artifacts,self.root/"accepted",self.config,attestations_dir=attest)
        evidence=json.loads(next((self.root/"accepted").rglob("acceptance-evidence-v1.json")).read_text())
        self.assertEqual(evidence["verified_provenance"], "github_attestation_exact_match")
        self.assertIn(self.rpm.name, evidence["verified_attestation"])
    def test_attestation_commit_mismatch_rejected(self):
        attest=self.root/"attestations"; attest.mkdir()
        self.write_attestation(attest,self.rpm.name,self.rpm,commit="b"*40)
        self.write_attestation(attest,self.srpm.name,self.srpm)
        self.write_attestation(attest,self.mp.name,self.mp)
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"attestation validation failed"):
            ro_repo.accept(self.mp,self.artifacts,self.root/"accepted",self.config,attestations_dir=attest)
    def test_attestation_workflow_identity_missing_rejected(self):
        attest=self.root/"attestations"; attest.mkdir()
        self.write_attestation(attest,self.rpm.name,self.rpm,workflow=False)
        self.write_attestation(attest,self.srpm.name,self.srpm)
        self.write_attestation(attest,self.mp.name,self.mp)
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"attestation validation failed"):
            ro_repo.accept(self.mp,self.artifacts,self.root/"accepted",self.config,attestations_dir=attest)
    def test_digest_mutation_is_rejected(self):
        self.rpm.write_bytes(b"mutated")
        with self.assertRaisesRegex(ro_repo.ContractError,"digest mismatch"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_missing_srpm_is_rejected(self):
        self.manifest["artifacts"]=self.manifest["artifacts"][:1]; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError, "schema validation failed"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_fedora_collision_is_default_deny(self):
        names=self.root/"names"; names.write_text("ro-control\n")
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"collision denied"): ro_repo.verify_component(self.mp,self.artifacts,self.config,names)
    def test_latest_release_id_is_rejected(self):
        self.manifest["release_id"]="latest"; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"latest is forbidden"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_wrong_fedora_release_is_rejected(self):
        self.manifest["fedora_release"]=43; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaises(ro_repo.ContractError): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_architecture_denied(self):
        self.manifest["artifacts"][0]["architecture"]="ppc64le"; self.mp.write_text(json.dumps(self.manifest))
        def mock_headers(path): h=self.headers(path); h["architecture"]=h["architecture"] if path.name.endswith("src.rpm") else "ppc64le"; return h
        with mock.patch.object(ro_repo,"rpm_header",side_effect=mock_headers), self.assertRaisesRegex(ro_repo.ContractError, "schema validation failed"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_invalid_commit_sha_rejected(self):
        self.manifest["source_commit"]="a"*39; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError, "schema validation failed"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_package_name_denied(self):
        self.manifest["component"]="evil-pkg"; self.manifest["artifacts"][0]["name"]="evil-pkg"; self.mp.write_text(json.dumps(self.manifest))
        def mock_headers(path): h=self.headers(path); h["name"]="evil-pkg"; return h
        with mock.patch.object(ro_repo,"rpm_header",side_effect=mock_headers), self.assertRaisesRegex(ro_repo.ContractError,"package name denied"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_rollback_no_previous_raises(self):
        with self.assertRaises(ro_repo.ContractError): ro_repo.rollback(self.root,"beta")
    def test_duplicate_filename_rejected(self):
        self.manifest["artifacts"].append(self.manifest["artifacts"][0]); self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"duplicate"): ro_repo.verify_component(self.mp,self.artifacts,self.config)
    def test_snapshot_lifecycle_separation(self):
        snap=self.root/"snapshot"; snap.mkdir(); m={"schema_version":1,"snapshot_id":"snapshot","target_channel":"stable","created_at":"2026-09-08T00:00:00Z","fedora_release":44,"parent_snapshot":None,"packages":[],"repositories":{},"rpm_signing_fingerprint":"X","metadata_signing_fingerprint":"X","creation_provenance":{"tool":"test","run":"local"}}
        (snap/"repository-snapshot-v1.json").write_text(json.dumps(m))
        with self.assertRaisesRegex(ro_repo.ContractError,"schema validation failed"): ro_repo.verify_snapshot(snap)

    def test_snapshot_role_aware_signature(self):
        snap=self.root/"repo-f44-20260908-001"; snap.mkdir()
        (snap/"keys").mkdir()
        (snap/"keys/RPM-GPG-KEY-TEST").touch()
        m={"schema_version":1,"snapshot_id":"repo-f44-20260908-001","created_at":"2026-09-08T00:00:00Z","fedora_release":44,"parent_snapshot":None,
           "packages":[{"architecture":"x86_64", "filename":"pkg.rpm", "nevra": "pkg-0:1-1.x86_64",
                        "producer_artifact_sha256": "a"*64, "published_signed_artifact_sha256": ro_repo.digest(self.rpm), "producer_manifest_digest": "b"*64}],
           "repositories":{"x86_64": {"repomd_sha256": "a"*64, "repomd_signature_sha256": "b"*64},
                           "aarch64": {"repomd_sha256": "a"*64, "repomd_signature_sha256": "b"*64},
                           "source": {"repomd_sha256": "a"*64, "repomd_signature_sha256": "b"*64}},
           "rpm_signing_fingerprint":"A"*40,"metadata_signing_fingerprint":"B"*40,"creation_provenance":{"tool":"ro-repo-v2","run":"local"}}
        (snap/"repository-snapshot-v1.json").write_text(json.dumps(m))
        (snap/"repository-snapshot-v1.json.asc").touch()
        for arch in ["x86_64", "aarch64", "source"]:
            (snap/f"rpm/{arch}/repodata").mkdir(parents=True)
            (snap/f"rpm/{arch}/repodata/repomd.xml").write_text("a")
            (snap/f"rpm/{arch}/repodata/repomd.xml.asc").write_text("b")
        (snap/"rpm/x86_64/pkg.rpm").write_bytes(self.rpm.read_bytes())

        # mock digest to bypass hash checks
        self_rpm_digest = ro_repo.digest(self.rpm)
        def mock_digest(p):
            name = p if isinstance(p, str) else p.name
            if name.endswith("repomd.xml.asc"): return "b"*64
            if name.endswith("repomd.xml"): return "a"*64
            if name.endswith("pkg.rpm"): return self_rpm_digest
            return "c"*64
        with mock.patch("ro_repo.digest", side_effect=mock_digest), \
             mock.patch("ro_repo.run") as m_run:

            # 1. Metadata key missing / wrong key used for repomd
            m_run.return_value.stdout = f"[GNUPG:] VALIDSIG {'C'*40} 2026\n"
            with self.assertRaisesRegex(ro_repo.ContractError, "wrong key used for"):
                ro_repo.verify_snapshot(snap)

            # 2. RPM signed with wrong key (rpmkeys fails)
            def side_effect(args, *a, **kw):
                class R: stdout = f"[GNUPG:] VALIDSIG {'B'*40} 2026\n"
                if "rpmkeys" in args and "--checksig" in args:
                    raise ro_repo.ContractError("checksig failed")
                return R()
            m_run.side_effect = side_effect
            with self.assertRaisesRegex(ro_repo.ContractError, "RPM signature validation failed"):
                ro_repo.verify_snapshot(snap)

            # 3. Success (both keys match)
            def side_effect_success(args, *a, **kw):
                class R: stdout = f"[GNUPG:] VALIDSIG {'B'*40} 2026\n"
                return R()
            m_run.side_effect = side_effect_success
            ro_repo.verify_snapshot(snap)

if __name__ == "__main__": unittest.main()
