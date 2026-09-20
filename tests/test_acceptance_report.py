import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
import ro_repo


class AcceptanceReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.rpm = self.artifacts / "ro-control-1.0-1.fc44.x86_64.rpm"
        self.srpm = self.artifacts / "ro-control-1.0-1.fc44.src.rpm"
        self.rpm.write_bytes(b"producer-rpm")
        self.srpm.write_bytes(b"source-rpm")
        self.manifest = {
            "schema_version": 1,
            "component": "ro-control",
            "source_repository": "Project-Ro-ASD/ro-Control",
            "source_commit": "a" * 40,
            "release_tag": "v1.0",
            "release_id": 10,
            "workflow_run": 20,
            "fedora_release": 44,
            "artifacts": [
                {"filename": self.rpm.name, "name": "ro-control", "epoch": 0,
                 "version": "1.0", "release": "1.fc44", "architecture": "x86_64",
                 "source_rpm": self.srpm.name,
                 "producer_artifact_sha256": ro_repo.digest(self.rpm)},
                {"filename": self.srpm.name, "name": "ro-control", "epoch": 0,
                 "version": "1.0", "release": "1.fc44", "architecture": "src",
                 "source_rpm": None,
                 "producer_artifact_sha256": ro_repo.digest(self.srpm)},
            ],
            "provenance": {"provider": "github", "subject_digest": "b" * 64},
            "attestation": {"provider": "github", "verification": "github-attestation"},
        }
        self.manifest_path = self.root / "manifest.json"
        self.config = pathlib.Path(__file__).parents[1] / "config/producers-v1.yaml"
        self.fedora_names = self.root / "fedora-names.txt"
        self.fedora_names.write_text("bash\n", encoding="utf-8")
        self.report = self.root / "acceptance-report-v1.json"
        self.write_manifest()

    def tearDown(self):
        self.tmp.cleanup()

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def headers(self, path):
        source = path.name.endswith("src.rpm")
        return {
            "name": "ro-control", "epoch": 0, "version": "1.0", "release": "1.fc44",
            "architecture": "src" if source else "x86_64",
            "source_rpm": None if source else self.srpm.name,
            "nevra": "unused",
        }

    def verify(self, **kwargs):
        return ro_repo.verify_component(
            self.manifest_path, self.artifacts, kwargs.pop("config", self.config),
            kwargs.pop("fedora_names", self.fedora_names),
            test_only_allow_missing_sha256sums=True, **kwargs,
        )

    def assert_error_code(self, code, operation):
        with self.assertRaises(ro_repo.ContractError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_successful_acceptance_report_and_schema(self):
        accepted = self.root / "accepted"
        (self.artifacts / "SHA256SUMS").write_text(
            "\n".join(
                f"{item['producer_artifact_sha256']}  {item['filename']}"
                for item in self.manifest["artifacts"]
            ) + "\n",
            encoding="utf-8",
        )
        argv = [
            "ro-repo", "accept-package", "--manifest", str(self.manifest_path),
            "--artifacts", str(self.artifacts), "--accepted", str(accepted),
            "--fedora-names", str(self.fedora_names), "--report", str(self.report),
            "--test-only-allow-unattested",
        ]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(ro_repo, "rpm_header", side_effect=self.headers):
            self.assertEqual(ro_repo.main(), 0)
        data = json.loads(self.report.read_text(encoding="utf-8"))
        self.assertEqual(data["result"], "accepted")
        self.assertIsNone(data["error_code"])
        ro_repo.validate_schema(data, "acceptance-report-v1")
        self.assertTrue(list(accepted.rglob("acceptance-evidence-v1.json")))

    def test_non_allowlisted_cli_rejects_reports_and_leaves_no_object(self):
        self.manifest["source_repository"] = "example/not-allowed"
        self.write_manifest()
        accepted = self.root / "accepted"
        argv = [
            "ro-repo", "accept-package", "--manifest", str(self.manifest_path),
            "--artifacts", str(self.artifacts), "--accepted", str(accepted),
            "--fedora-names", str(self.fedora_names), "--report", str(self.report),
            "--test-only-allow-unattested",
        ]
        with mock.patch.object(sys, "argv", argv):
            self.assertNotEqual(ro_repo.main(), 0)
        data = json.loads(self.report.read_text(encoding="utf-8"))
        self.assertEqual(data["result"], "rejected")
        self.assertEqual(data["error_code"], "PRODUCER_NOT_ALLOWLISTED")
        self.assertFalse(accepted.exists())

    def test_digest_mismatch_code(self):
        self.rpm.write_bytes(b"mutated")
        self.assert_error_code("ARTIFACT_DIGEST_MISMATCH", lambda: self.verify())

    def test_rpm_header_mismatch_code(self):
        def wrong_header(path):
            header = self.headers(path)
            if path == self.rpm:
                header["version"] = "2.0"
            return header
        with mock.patch.object(ro_repo, "rpm_header", side_effect=wrong_header):
            self.assert_error_code("RPM_HEADER_MISMATCH", lambda: self.verify())

    def test_fedora_release_mismatch_code(self):
        self.manifest["fedora_release"] = 43
        self.write_manifest()
        self.assert_error_code("FEDORA_RELEASE_MISMATCH", lambda: self.verify())

    def test_architecture_denied_code(self):
        config = json.loads(self.config.read_text(encoding="utf-8"))
        config["producers"][0]["architectures"] = ["aarch64"]
        config_path = self.root / "producers.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        with mock.patch.object(ro_repo, "rpm_header", side_effect=self.headers):
            self.assert_error_code("ARCHITECTURE_DENIED", lambda: self.verify(config=config_path))

    def test_missing_srpm_code(self):
        missing = "ro-control-1.0-1.fc44.missing.src.rpm"
        self.manifest["artifacts"][0]["source_rpm"] = missing
        self.write_manifest()
        def missing_header(path):
            header = self.headers(path)
            if path == self.rpm:
                header["source_rpm"] = missing
            return header
        with mock.patch.object(ro_repo, "rpm_header", side_effect=missing_header):
            self.assert_error_code("SRPM_MISSING", lambda: self.verify())

    def test_package_collision_code(self):
        self.fedora_names.write_text("ro-control\n", encoding="utf-8")
        with mock.patch.object(ro_repo, "rpm_header", side_effect=self.headers):
            self.assert_error_code("FEDORA_PACKAGE_COLLISION", lambda: self.verify())

    def test_existing_acceptance_object_code(self):
        accepted = self.root / "accepted"
        with mock.patch.object(ro_repo, "rpm_header", side_effect=self.headers):
            ro_repo.accept(self.manifest_path, self.artifacts, accepted, self.config,
                           self.fedora_names, test_only_allow_unattested=True,
                           test_only_allow_missing_sha256sums=True)
            self.assert_error_code(
                "ACCEPTANCE_OBJECT_EXISTS",
                lambda: ro_repo.accept(
                    self.manifest_path, self.artifacts, accepted, self.config,
                    self.fedora_names, test_only_allow_unattested=True,
                    test_only_allow_missing_sha256sums=True,
                ),
            )
        self.assertEqual(len(list(accepted.glob("*/acceptance-evidence-v1.json"))), 1)

    def test_report_redacts_secret_environment_values(self):
        secret = "never-print-this-token"
        error = ro_repo.ContractError(
            f"failure included {secret}", code="INTERNAL_ACCEPTANCE_ERROR", stage="acceptance",
            received=secret,
        )
        identity = ro_repo.acceptance_identity(self.manifest_path)
        identity["release_tag"] = secret
        with mock.patch.dict(os.environ, {"GH_TOKEN": secret}):
            ro_repo.write_acceptance_report(
                self.report, "rejected", identity, error,
            )
        serialized = self.report.read_text(encoding="utf-8")
        self.assertNotIn(secret, serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_identity_error_codes(self):
        cases = [
            ({"source_commit": "b" * 40}, "TAG_COMMIT_MISMATCH"),
            ({"release_id": 999}, "RELEASE_ID_MISMATCH"),
            ({"release_tag": "v2.0"}, "MANIFEST_IDENTITY_MISMATCH"),
        ]
        for expected, code in cases:
            with self.subTest(code=code):
                self.assert_error_code(code, lambda expected=expected: ro_repo.verify_expected_identity(self.manifest_path, expected))


if __name__ == "__main__":
    unittest.main()
