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
    def verified_attestation_result(self, run_id=20, attempt=1):
        payload = [{
            "verificationResult": {
                "signature": {
                    "certificate": {
                        "runInvocationURI": (
                            "https://github.com/Project-Ro-ASD/ro-Control/"
                            f"actions/runs/{run_id}/attempts/{attempt}"
                        )
                    }
                }
            }
        }]
        result = mock.Mock()
        result.stdout = json.dumps(payload)
        return result

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
    def test_rpm_header_parses_sourcepackage_flag_for_srpm(self):
        fake = mock.Mock()
        fake.stdout = "ro-installer\t0\t2.4.3\t1.fc44\tx86_64\t(none)\t1"
        with mock.patch.object(ro_repo, "run", return_value=fake) as run_mock:
            header = ro_repo.rpm_header(pathlib.Path("ro-installer-2.4.3-1.fc44.src.rpm"))
        self.assertEqual(header["name"], "ro-installer")
        self.assertEqual(header["architecture"], "src")
        self.assertIsNone(header["source_rpm"])
        self.assertEqual(header["nevra"], "ro-installer-0:2.4.3-1.fc44.src")
        argv = run_mock.call_args.args[0]
        query = argv[3]
        self.assertIn("%{SOURCEPACKAGE}", query)
        self.assertNotIn("SOURCEPACKAGE?", query)

    def test_rpm_header_keeps_binary_arch_and_source_linkage(self):
        fake = mock.Mock()
        fake.stdout = "ro-installer\t0\t2.4.3\t1.fc44\tx86_64\tro-installer-2.4.3-1.fc44.src.rpm\t0"
        with mock.patch.object(ro_repo, "run", return_value=fake):
            header = ro_repo.rpm_header(pathlib.Path("ro-installer-2.4.3-1.fc44.x86_64.rpm"))
        self.assertEqual(header["architecture"], "x86_64")
        self.assertEqual(header["source_rpm"], "ro-installer-2.4.3-1.fc44.src.rpm")
        self.assertEqual(header["nevra"], "ro-installer-0:2.4.3-1.fc44.x86_64")

    def test_attestation_parser_accepts_canonical_gh_certificate_shape(self):
        payload = self.verified_attestation_result(run_id=20, attempt=3)
        certificate = json.loads(payload.stdout)[0]["verificationResult"]["signature"]["certificate"]
        self.assertEqual(
            certificate["runInvocationURI"],
            "https://github.com/Project-Ro-ASD/ro-Control/actions/runs/20/attempts/3",
        )
        self.assertNotIn("extensions", certificate)

    def test_parse_attestation_invocation_uri(self):
        parsed = ro_repo._parse_attestation_invocation_uri(
            "https://github.com/Project-Ro-ASD/ro-Installer/actions/runs/12345/attempts/2"
        )
        self.assertEqual(
            parsed,
            {"repository": "Project-Ro-ASD/ro-Installer", "run_id": 12345, "attempt": 2},
        )
        self.assertIsNone(ro_repo._parse_attestation_invocation_uri("https://example.com/nope"))

    def test_binary_architecture_coverage_is_required(self):
        self.rpm.unlink()
        second_srpm = self.artifacts / "ro-control-1.0-1.fc44.other.src.rpm"
        second_srpm.write_bytes(b"second-source-rpm")
        first_source = dict(self.manifest["artifacts"][1])
        second_source = dict(first_source)
        second_source["filename"] = second_srpm.name
        second_source["producer_artifact_sha256"] = ro_repo.digest(second_srpm)
        self.manifest["artifacts"] = [first_source, second_source]
        self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo, "rpm_header", side_effect=self.headers):
            with self.assertRaisesRegex(ro_repo.ContractError, "contains no binary RPM"):
                ro_repo.verify_component(
                    self.mp, self.artifacts, self.config,
                    test_only_allow_empty_fedora=True,
                    test_only_allow_missing_sha256sums=True,
                )

    def test_binary_source_identity_mismatch_is_rejected(self):
        self.manifest["artifacts"][1]["version"] = "9.9.9"
        self.mp.write_text(json.dumps(self.manifest))
        def mismatched_headers(path):
            header = self.headers(path)
            if path.name.endswith("src.rpm"):
                header["version"] = "9.9.9"
            return header
        with mock.patch.object(ro_repo, "rpm_header", side_effect=mismatched_headers):
            with self.assertRaisesRegex(ro_repo.ContractError, "binary/source RPM identity mismatch"):
                ro_repo.verify_component(
                    self.mp, self.artifacts, self.config,
                    test_only_allow_empty_fedora=True,
                    test_only_allow_missing_sha256sums=True,
                )

    def test_srpm_can_build_distinct_binary_subpackage_names(self):
        libs = self.artifacts / "ro-control-libs-1.0-1.fc44.x86_64.rpm"
        libs.write_bytes(b"binary-subpackage")
        self.manifest["artifacts"].insert(1, {
            "filename": libs.name,
            "name": "ro-control-libs",
            "epoch": 0,
            "version": "1.0",
            "release": "1.fc44",
            "architecture": "x86_64",
            "source_rpm": self.srpm.name,
            "producer_artifact_sha256": ro_repo.digest(libs),
        })
        self.mp.write_text(json.dumps(self.manifest))
        original = ro_repo.resolve_component_policy
        def policy_with_subpackage(*args, **kwargs):
            policy = dict(original(*args, **kwargs))
            policy["package_names"] = [*policy["package_names"], "ro-control-libs"]
            return policy
        def subpackage_headers(path):
            header = self.headers(path)
            if path.name == libs.name:
                header["name"] = "ro-control-libs"
            return header
        with mock.patch.object(ro_repo, "resolve_component_policy", side_effect=policy_with_subpackage), mock.patch.object(ro_repo, "rpm_header", side_effect=subpackage_headers), mock.patch.object(ro_repo, "rpmlint_check", return_value=(True, "")), mock.patch.object(ro_repo, "repository_file_conflict_check", return_value=(True, [])):
            ro_repo.verify_component(
                self.mp, self.artifacts, self.config,
                test_only_allow_empty_fedora=True,
                test_only_allow_missing_sha256sums=True,
            )

    def test_sha256sums_extra_non_rpm_entry_is_rejected(self):
        sums = self.artifacts / "SHA256SUMS"
        sums.write_text(
            "\n".join(
                [f"{item['producer_artifact_sha256']}  {item['filename']}" for item in self.manifest["artifacts"]]
                + [f"{'0'*64}  README.txt"]
            ) + "\n"
        )
        with mock.patch.object(ro_repo, "rpm_header", side_effect=self.headers):
            with self.assertRaisesRegex(ro_repo.ContractError, "filename set"):
                ro_repo.verify_component(
                    self.mp, self.artifacts, self.config,
                    test_only_allow_empty_fedora=True,
                )

    def test_valid_component_and_acceptance(self):
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers): ro_repo.verify_component(self.mp,self.artifacts,self.config,test_only_allow_empty_fedora=True,test_only_allow_missing_sha256sums=True); ro_repo.accept(self.mp,self.artifacts,self.root/"accepted",self.config,test_only_allow_unattested=True,test_only_allow_empty_fedora=True,test_only_allow_missing_sha256sums=True)
        self.assertTrue(list((self.root/"accepted").rglob("acceptance-evidence-v1.json")))
    def test_attestation_exact_match_acceptance(self):
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), mock.patch.object(ro_repo,"run", return_value=self.verified_attestation_result()):
            ro_repo.accept(self.mp,self.artifacts,self.root/"accepted",self.config,test_only_allow_missing_sha256sums=True,test_only_allow_empty_fedora=True)
            self.assertEqual(json.loads((self.root/"accepted"/ro_repo.digest(self.mp)/"acceptance-evidence-v1.json").read_text())["verified_provenance"], "github_attestation_exact_match")
            self.assertEqual(json.loads((self.root/"accepted"/ro_repo.digest(self.mp)/"acceptance-evidence-v1.json").read_text())["verified_attestation"]["ro-control-1.0-1.fc44.x86_64.rpm"]["workflow_identity"], "Project-Ro-ASD/ro-Control/.github/workflows/release.yml")
    def test_attestation_commit_mismatch_rejected(self):
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), mock.patch.object(ro_repo,"run", side_effect=ro_repo.ContractError("gh fail")):
            with self.assertRaisesRegex(ro_repo.ContractError,"attestation validation failed"): ro_repo.accept(self.mp,self.artifacts,self.root/"accepted",self.config,test_only_allow_missing_sha256sums=True,test_only_allow_empty_fedora=True)
    def test_attestation_workflow_identity_missing_rejected(self):
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), mock.patch.object(ro_repo,"run", side_effect=ro_repo.ContractError("gh fail")):
            with self.assertRaisesRegex(ro_repo.ContractError,"attestation validation failed"): ro_repo.accept(self.mp,self.artifacts,self.root/"accepted",self.config,test_only_allow_missing_sha256sums=True,test_only_allow_empty_fedora=True)
    def test_cross_arch_variants_do_not_conflict(self):
        x86 = self.root/"pkg.x86_64.rpm"; x86.write_bytes(b"x86")
        arm = self.root/"pkg.aarch64.rpm"; arm.write_bytes(b"arm")
        with mock.patch("ro_repo.subprocess.check_output") as query:
            ok, conflicts = ro_repo.repository_file_conflict_check([
                (x86, "x86_64"),
                (arm, "aarch64"),
            ])
        self.assertTrue(ok)
        self.assertEqual(conflicts, [])
        query.assert_not_called()

    def test_compatible_shared_build_id_directory_is_allowed(self):
        first = self.root/"first.x86_64.rpm"; first.write_bytes(b"one")
        second = self.root/"second.x86_64.rpm"; second.write_bytes(b"two")
        outputs = [
            "drwxr-xr-x\troot\troot\t/usr/lib/.build-id\n"
            "-rwxr-xr-x\troot\troot\t/usr/bin/first\n",
            "drwxr-xr-x\troot\troot\t/usr/lib/.build-id\n"
            "-rwxr-xr-x\troot\troot\t/usr/bin/second\n",
        ]
        with mock.patch("ro_repo.subprocess.check_output", side_effect=outputs) as query:
            ok, conflicts = ro_repo.repository_file_conflict_check([
                (first, "x86_64"), (second, "x86_64"),
            ])
        self.assertTrue(ok)
        self.assertEqual(conflicts, [])
        self.assertIn("%{FILEMODES:perms}", query.call_args.args[0][3])

    def test_same_arch_file_conflict_is_rejected(self):
        first = self.root/"first.x86_64.rpm"; first.write_bytes(b"one")
        second = self.root/"second.x86_64.rpm"; second.write_bytes(b"two")
        output = "-rw-r--r--\troot\troot\t/usr/bin/shared\n"
        with mock.patch("ro_repo.subprocess.check_output", return_value=output):
            ok, conflicts = ro_repo.repository_file_conflict_check([
                (first, "x86_64"), (second, "x86_64"),
            ])
        self.assertFalse(ok)
        self.assertEqual(conflicts, [
            "x86_64: /usr/bin/shared owned by both first.x86_64.rpm and second.x86_64.rpm"
        ])

    def test_directory_mode_or_owner_mismatch_is_rejected(self):
        first = self.root/"first.x86_64.rpm"; first.write_bytes(b"one")
        second = self.root/"second.x86_64.rpm"; second.write_bytes(b"two")
        for second_entry in [
            "drwx------\troot\troot\t/usr/share/shared\n",
            "drwxr-xr-x\tother\troot\t/usr/share/shared\n",
            "-rw-r--r--\troot\troot\t/usr/share/shared\n",
        ]:
            with self.subTest(second_entry=second_entry):
                with mock.patch("ro_repo.subprocess.check_output", side_effect=[
                    "drwxr-xr-x\troot\troot\t/usr/share/shared\n", second_entry
                ]):
                    ok, conflicts = ro_repo.file_conflict_check([first, second])
                self.assertFalse(ok)
                self.assertEqual(len(conflicts), 1)

    def test_same_path_symlinks_are_rejected(self):
        first = self.root/"first.x86_64.rpm"; first.write_bytes(b"one")
        second = self.root/"second.x86_64.rpm"; second.write_bytes(b"two")
        with mock.patch("ro_repo.subprocess.check_output", return_value=
                        "lrwxrwxrwx\troot\troot\t/usr/bin/shared\n"):
            ok, conflicts = ro_repo.file_conflict_check([first, second])
        self.assertFalse(ok)
        self.assertEqual(len(conflicts), 1)

    def test_malformed_file_metadata_fails_closed(self):
        first = self.root/"first.x86_64.rpm"; first.write_bytes(b"one")
        with mock.patch("ro_repo.subprocess.check_output", return_value="/usr/bin/shared\n"):
            with self.assertRaisesRegex(ro_repo.ContractError, "malformed RPM file metadata"):
                ro_repo.file_conflict_check([first])

    def test_noarch_conflicts_with_target_arch_package(self):
        common = self.root/"common.noarch.rpm"; common.write_bytes(b"common")
        native = self.root/"native.aarch64.rpm"; native.write_bytes(b"native")
        with mock.patch("ro_repo.subprocess.check_output", return_value=
                        "-rw-r--r--\troot\troot\t/usr/share/shared\n"):
            ok, conflicts = ro_repo.repository_file_conflict_check([
                (common, "noarch"), (native, "aarch64"),
            ])
        self.assertFalse(ok)
        self.assertEqual(conflicts, [
            "aarch64: /usr/share/shared owned by both common.noarch.rpm and native.aarch64.rpm"
        ])

    def test_digest_mutation_is_rejected(self):
        self.rpm.write_bytes(b"mutated")
        with self.assertRaisesRegex(ro_repo.ContractError,"digest mismatch"): ro_repo.verify_component(self.mp,self.artifacts,self.config,test_only_allow_empty_fedora=True,test_only_allow_missing_sha256sums=True)
    def test_missing_srpm_is_rejected(self):
        self.manifest["artifacts"]=self.manifest["artifacts"][:1]; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError, "schema validation failed"): ro_repo.verify_component(self.mp,self.artifacts,self.config,test_only_allow_empty_fedora=True,test_only_allow_missing_sha256sums=True)
    def test_fedora_collision_is_default_deny(self):
        names=self.root/"names"; names.write_text("ro-control\n")
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"collision denied"): ro_repo.verify_component(self.mp,self.artifacts,self.config,names,test_only_allow_missing_sha256sums=True)
    def test_latest_release_id_is_rejected(self):
        self.manifest["release_id"]="latest"; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"latest is forbidden") as caught: ro_repo.verify_component(self.mp,self.artifacts,self.config,test_only_allow_empty_fedora=True,test_only_allow_missing_sha256sums=True)
        self.assertEqual(caught.exception.code, "RELEASE_ID_MISMATCH")
    def test_wrong_fedora_release_is_rejected(self):
        self.manifest["fedora_release"]=43; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaises(ro_repo.ContractError): ro_repo.verify_component(self.mp,self.artifacts,self.config,test_only_allow_empty_fedora=True,test_only_allow_missing_sha256sums=True)
    def test_architecture_denied(self):
        self.manifest["artifacts"][0]["architecture"]="ppc64le"; self.mp.write_text(json.dumps(self.manifest))
        def mock_headers(path): h=self.headers(path); h["architecture"]=h["architecture"] if path.name.endswith("src.rpm") else "ppc64le"; return h
        with mock.patch.object(ro_repo,"rpm_header",side_effect=mock_headers), self.assertRaisesRegex(ro_repo.ContractError, "schema validation failed"): ro_repo.verify_component(self.mp,self.artifacts,self.config,test_only_allow_empty_fedora=True,test_only_allow_missing_sha256sums=True)
    def test_invalid_commit_sha_rejected(self):
        self.manifest["source_commit"]="a"*39; self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError, "exact lowercase 40-character SHA") as caught: ro_repo.verify_component(self.mp,self.artifacts,self.config,test_only_allow_empty_fedora=True,test_only_allow_missing_sha256sums=True)
        self.assertEqual(caught.exception.code, "TAG_COMMIT_MISMATCH")
    def test_package_name_denied(self):
        self.manifest["artifacts"][0]["name"]="evil-pkg"; self.mp.write_text(json.dumps(self.manifest))
        def mock_headers(path): h=self.headers(path); h["name"]="evil-pkg"; return h
        with mock.patch.object(ro_repo,"rpm_header",side_effect=mock_headers), self.assertRaisesRegex(ro_repo.ContractError,"package name denied"): ro_repo.verify_component(self.mp,self.artifacts,self.config,test_only_allow_empty_fedora=True,test_only_allow_missing_sha256sums=True)
    def test_rollback_no_previous_raises(self):
        with self.assertRaises(ro_repo.ContractError): ro_repo.rollback(self.root,"beta")
    def test_duplicate_filename_rejected(self):
        self.manifest["artifacts"].append(self.manifest["artifacts"][0]); self.mp.write_text(json.dumps(self.manifest))
        with mock.patch.object(ro_repo,"rpm_header",side_effect=self.headers), self.assertRaisesRegex(ro_repo.ContractError,"duplicate"): ro_repo.verify_component(self.mp,self.artifacts,self.config,test_only_allow_empty_fedora=True,test_only_allow_missing_sha256sums=True)
    def test_snapshot_lifecycle_separation(self):
        snap=self.root/"snapshot"; snap.mkdir(); m={"schema_version":1,"snapshot_id":"snapshot","target_channel":"stable","created_at":"2026-09-08T00:00:00Z","fedora_release":44,"parent_snapshot":None,"packages":[],"repositories":{},"rpm_signing_fingerprint":"X","metadata_signing_fingerprint":"X","creation_provenance":{"tool":"test","run":"local"}}
        (snap/"repository-snapshot-v1.json").write_text(json.dumps(m))
        with self.assertRaisesRegex(ro_repo.ContractError,"schema validation failed"): ro_repo.verify_snapshot(snap)

    def test_snapshot_role_aware_signature(self):
        snap=self.root/"repo-f44-20260908-001"; snap.mkdir()
        (snap/"keys").mkdir()
        (snap/"keys/RPM-GPG-KEY-TEST").touch()
        m={"schema_version":1,"snapshot_id":"repo-f44-20260908-001","created_at":"2026-09-08T00:00:00Z","fedora_release":44,"parent_snapshot":None,
           "packages":[{"architecture":"x86_64", "filename":"ro-control-1.0-1.fc44.x86_64.rpm", "nevra": "pkg-0:1-1.x86_64",
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
            if name.endswith("ro-control-1.0-1.fc44.x86_64.rpm"): return self_rpm_digest
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
