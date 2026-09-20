import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
import ro_repo


class ProductionSigningTests(unittest.TestCase):
    signing_fingerprint = "A" * 40

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.accepted_root = self.root / "accepted"
        self.accepted_object = self.accepted_root / ("f" * 64)
        self.artifacts = self.accepted_object / "artifacts"
        self.artifacts.mkdir(parents=True)
        self.rpm = self.artifacts / "ro-control-1.0-1.fc44.x86_64.rpm"
        self.srpm = self.artifacts / "ro-control-1.0-1.fc44.src.rpm"
        self.rpm.write_bytes(b"producer-rpm")
        self.srpm.write_bytes(b"producer-srpm")
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
        self.manifest_path = self.accepted_object / "component-artifact-manifest-v1.json"
        self.write_manifest()
        self.evidence_path = self.accepted_object / "acceptance-evidence-v1.json"
        self.evidence = {
            "schema_version": 1,
            "accepted_at": "2026-09-20T00:00:00Z",
            "manifest_digest": ro_repo.digest(self.manifest_path),
            "source_repository": self.manifest["source_repository"],
            "source_commit": self.manifest["source_commit"],
            "release_tag": self.manifest["release_tag"],
            "release_id": self.manifest["release_id"],
            "workflow_run": self.manifest["workflow_run"],
            "verified_provenance": "github_attestation_exact_match",
            "verified_attestation": {},
            "checks": [],
            "diagnostics": {},
        }
        self.write_evidence()
        self.passphrase = self.root / "passphrase"
        self.passphrase.write_text("test-passphrase", encoding="utf-8")
        self.passphrase.chmod(0o600)
        self.gnupghome = self.root / "gnupg"
        self.gnupghome.mkdir(mode=0o700)
        self.test_public_key = self.root / "test-public.asc"
        self.test_public_key.write_text("test-only-public-key", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def write_evidence(self):
        self.evidence_path.write_text(json.dumps(self.evidence), encoding="utf-8")

    def test_valid_accepted_object_succeeds(self):
        accepted_object, evidence, manifest, entries = ro_repo.verify_accepted_object(self.accepted_root)
        self.assertEqual(accepted_object, self.accepted_object)
        self.assertEqual(evidence["manifest_digest"], ro_repo.digest(self.manifest_path))
        self.assertEqual(manifest["release_id"], 10)
        self.assertEqual(set(entries), {self.rpm.name, self.srpm.name})

    def test_mutated_rpm_rejected(self):
        self.rpm.write_bytes(b"mutated")
        with self.assertRaisesRegex(ro_repo.ContractError, "digest mismatch"):
            ro_repo.verify_accepted_object(self.accepted_root)

    def test_extra_rpm_rejected(self):
        (self.artifacts / "extra.rpm").write_bytes(b"extra")
        with self.assertRaisesRegex(ro_repo.ContractError, "RPM set mismatch"):
            ro_repo.verify_accepted_object(self.accepted_root)

    def test_missing_rpm_rejected(self):
        self.srpm.unlink()
        with self.assertRaisesRegex(ro_repo.ContractError, "RPM set mismatch"):
            ro_repo.verify_accepted_object(self.accepted_root)

    def test_manifest_digest_mismatch_rejected(self):
        self.evidence["manifest_digest"] = "0" * 64
        self.write_evidence()
        with self.assertRaisesRegex(ro_repo.ContractError, "manifest digest mismatch"):
            ro_repo.verify_accepted_object(self.accepted_root)

    def test_acceptance_identity_mismatch_rejected(self):
        self.evidence["source_commit"] = "b" * 40
        self.write_evidence()
        with self.assertRaisesRegex(ro_repo.ContractError, "identity mismatch"):
            ro_repo.verify_accepted_object(self.accepted_root)

    def test_unattested_production_acceptance_rejected(self):
        self.evidence["verified_provenance"] = "unattested_test_only_override"
        self.write_evidence()
        with self.assertRaisesRegex(ro_repo.ContractError, "unattested"):
            ro_repo.verify_accepted_object(self.accepted_root)
        ro_repo.verify_accepted_object(self.accepted_root, test_only_allow_unattested=True)

    def test_signing_subkey_validation(self):
        exact = {"type": "sub", "fingerprint": self.signing_fingerprint,
                 "capabilities": "s", "secret_available": False}
        with mock.patch.object(ro_repo, "run", return_value=mock.Mock(stdout="key-list")), \
             mock.patch.object(ro_repo, "gpg_fingerprint_records", return_value=[exact]):
            self.assertEqual(
                ro_repo.require_signing_subkey(self.gnupghome, self.signing_fingerprint),
                self.signing_fingerprint,
            )
        primary = dict(exact, type="pub")
        with mock.patch.object(ro_repo, "run", return_value=mock.Mock(stdout="key-list")), \
             mock.patch.object(ro_repo, "gpg_fingerprint_records", return_value=[primary]):
            with self.assertRaisesRegex(ro_repo.ContractError, "not a primary"):
                ro_repo.require_signing_subkey(self.gnupghome, self.signing_fingerprint)
        with self.assertRaisesRegex(ro_repo.ContractError, "exact 40-hex"):
            ro_repo.require_signing_subkey(self.gnupghome, "DEADBEEF")

    def test_wrong_role_public_key_rejected(self):
        records = [
            {"type": "pub", "fingerprint": "B" * 40, "capabilities": "c", "secret_available": False},
            {"type": "sub", "fingerprint": "C" * 40, "capabilities": "s", "secret_available": False},
        ]
        with mock.patch.object(ro_repo, "run", return_value=mock.Mock(stdout="key-list")), \
             mock.patch.object(ro_repo, "gpg_fingerprint_records", return_value=records):
            with self.assertRaisesRegex(ro_repo.ContractError, "not isolated"):
                ro_repo.validate_role_public_key(self.test_public_key, self.signing_fingerprint, self.gnupghome)

    def test_offline_primary_and_extra_secret_roles_rejected(self):
        expected = {"type": "ssb", "fingerprint": self.signing_fingerprint,
                    "capabilities": "s", "secret_available": True}
        primary = {"type": "sec", "fingerprint": "B" * 40,
                   "capabilities": "c", "secret_available": True}
        extra = {"type": "ssb", "fingerprint": "C" * 40,
                 "capabilities": "s", "secret_available": True}
        with mock.patch.object(ro_repo, "require_signing_subkey", return_value=self.signing_fingerprint), \
             mock.patch.object(ro_repo, "run", return_value=mock.Mock(stdout="secret-list")), \
             mock.patch.object(ro_repo, "gpg_fingerprint_records", return_value=[primary, expected]):
            with self.assertRaisesRegex(ro_repo.ContractError, "offline primary"):
                ro_repo.require_secret_signing_subkey(self.gnupghome, self.signing_fingerprint)
        with mock.patch.object(ro_repo, "require_signing_subkey", return_value=self.signing_fingerprint), \
             mock.patch.object(ro_repo, "run", return_value=mock.Mock(stdout="secret-list")), \
             mock.patch.object(ro_repo, "gpg_fingerprint_records", return_value=[expected, extra]):
            with self.assertRaisesRegex(ro_repo.ContractError, "only the expected"):
                ro_repo.require_secret_signing_subkey(self.gnupghome, self.signing_fingerprint)

    def test_atomic_signing_output_and_evidence_hash_binding(self):
        output = self.root / "signed"
        def fake_sign(source, target, gnupghome, key_id, passphrase_file):
            shutil.copy2(source, target)
            with target.open("ab") as stream:
                stream.write(b"-signed")
        with mock.patch.object(ro_repo, "require_secret_signing_subkey", return_value=self.signing_fingerprint), \
             mock.patch.object(ro_repo, "validate_role_public_key", return_value="B" * 40), \
             mock.patch.object(ro_repo, "_sign_rpm_exact", side_effect=fake_sign), \
             mock.patch.object(ro_repo, "verify_signed_rpms"):
            evidence = ro_repo.sign_accepted_component(
                self.accepted_root, output, self.gnupghome, self.signing_fingerprint,
                123, self.passphrase, test_only_public_key=self.test_public_key,
            )
        ro_repo.validate_schema(evidence, "rpm-signing-evidence-v1")
        self.assertTrue((output / "rpm-signing-evidence-v1.json").is_file())
        for item in evidence["artifacts"]:
            self.assertNotEqual(item["producer_artifact_sha256"], item["signed_artifact_sha256"])
            self.assertEqual(item["signed_artifact_sha256"], ro_repo.digest(output / item["filename"]))

    def test_rpm6_exact_selector_uses_only_passphrase_file_path(self):
        source = self.root / "source.rpm"
        target = self.root / "target.rpm"
        source.write_bytes(b"rpm")
        with mock.patch.object(ro_repo.shutil, "which", return_value="/usr/bin/rpmsign"), \
             mock.patch.object(ro_repo, "run", return_value=mock.Mock()) as run:
            ro_repo._sign_rpm_exact(
                source, target, self.gnupghome, self.signing_fingerprint, self.passphrase,
            )
        args, env = run.call_args.args
        self.assertEqual(args[1:4], ["--addsign", "--key-id", self.signing_fingerprint])
        self.assertTrue(any(str(self.passphrase) in argument for argument in args))
        self.assertNotIn("test-passphrase", " ".join(args))
        self.assertEqual(env["GNUPGHOME"], str(self.gnupghome))

    def test_partial_output_removed_on_failure(self):
        output = self.root / "failed-output"
        def fail_sign(source, target, gnupghome, key_id, passphrase_file):
            shutil.copy2(source, target)
            raise ro_repo.ContractError("simulated signing failure")
        with mock.patch.object(ro_repo, "require_secret_signing_subkey", return_value=self.signing_fingerprint), \
             mock.patch.object(ro_repo, "validate_role_public_key", return_value="B" * 40), \
             mock.patch.object(ro_repo, "_sign_rpm_exact", side_effect=fail_sign):
            with self.assertRaisesRegex(ro_repo.ContractError, "simulated"):
                ro_repo.sign_accepted_component(
                    self.accepted_root, output, self.gnupghome, self.signing_fingerprint,
                    123, self.passphrase, test_only_public_key=self.test_public_key,
                )
        self.assertFalse(output.exists())

    def test_evidence_contains_no_secret_values(self):
        secret_values = ["passphrase-value", "token-value", "private-key-text"]
        evidence = {
            "schema_version": 1,
            "signed_at": "2026-09-20T00:00:00Z",
            "workflow_run": 123,
            "acceptance_manifest_digest": "a" * 64,
            "rpm_signing_fingerprint": self.signing_fingerprint,
            "artifacts": [{
                "filename": "pkg.rpm", "architecture": "x86_64", "nevra": "pkg-0:1-1.x86_64",
                "producer_artifact_sha256": "b" * 64,
                "signed_artifact_sha256": "c" * 64,
            }],
        }
        serialized = json.dumps(evidence)
        for secret in secret_values:
            self.assertNotIn(secret, serialized)
        ro_repo.validate_schema(evidence, "rpm-signing-evidence-v1")

    def test_production_workflow_secret_hygiene(self):
        workflow = (pathlib.Path(__file__).parents[1] / ".github/workflows/accept-component.yml").read_text(encoding="utf-8")
        self.assertIn("RO_REPO_RPM_SIGNING_SUBKEY_B64", workflow)
        self.assertIn("RO_REPO_RPM_SIGNING_PASSPHRASE", workflow)
        self.assertNotIn("RO_REPO_METADATA_SIGNING", workflow)
        self.assertNotRegex(workflow, r"echo\s+\$RO_REPO_RPM_SIGNING")
        self.assertIn("set +x", workflow)
        self.assertIn("unset RO_REPO_RPM_SIGNING_SUBKEY_B64 RO_REPO_RPM_SIGNING_PASSPHRASE", workflow)


if __name__ == "__main__":
    unittest.main()
