import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
import ro_repo


class ProductionSnapshotTests(unittest.TestCase):
    rpm_fingerprint = "A" * 40

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.run_id = 123
        self.component = self.root / "components" / str(self.run_id)
        self.accepted_object = self.component / "accepted" / ("f" * 64)
        self.accepted_artifacts = self.accepted_object / "artifacts"
        self.signed = self.component / "signed"
        self.accepted_artifacts.mkdir(parents=True)
        self.signed.mkdir(parents=True)

        self.rpm = self.accepted_artifacts / "ro-control-1.0-1.fc44.x86_64.rpm"
        self.srpm = self.accepted_artifacts / "ro-control-1.0-1.fc44.src.rpm"
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
                {
                    "filename": self.rpm.name, "name": "ro-control", "epoch": 0,
                    "version": "1.0", "release": "1.fc44", "architecture": "x86_64",
                    "source_rpm": self.srpm.name,
                    "producer_artifact_sha256": ro_repo.digest(self.rpm),
                },
                {
                    "filename": self.srpm.name, "name": "ro-control", "epoch": 0,
                    "version": "1.0", "release": "1.fc44", "architecture": "src",
                    "source_rpm": None,
                    "producer_artifact_sha256": ro_repo.digest(self.srpm),
                },
            ],
            "provenance": {"provider": "github", "subject_digest": "b" * 64},
            "attestation": {"provider": "github", "verification": "github-attestation"},
        }
        self.manifest_path = self.accepted_object / "component-artifact-manifest-v1.json"
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.acceptance = {
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
        (self.accepted_object / "acceptance-evidence-v1.json").write_text(
            json.dumps(self.acceptance), encoding="utf-8"
        )

        signed_artifacts = []
        for source in (self.rpm, self.srpm):
            target = self.signed / source.name
            target.write_bytes(source.read_bytes() + b"-signed")
            item = next(x for x in self.manifest["artifacts"] if x["filename"] == source.name)
            signed_artifacts.append({
                "filename": source.name,
                "architecture": item["architecture"],
                "nevra": f"{item['name']}-{item['epoch']}:{item['version']}-{item['release']}.{item['architecture']}",
                "producer_artifact_sha256": item["producer_artifact_sha256"],
                "signed_artifact_sha256": ro_repo.digest(target),
            })
        self.signing = {
            "schema_version": 1,
            "signed_at": "2026-09-20T00:01:00Z",
            "workflow_run": self.run_id,
            "acceptance_manifest_digest": self.acceptance["manifest_digest"],
            "rpm_signing_fingerprint": self.rpm_fingerprint,
            "artifacts": signed_artifacts,
        }
        (self.signed / "rpm-signing-evidence-v1.json").write_text(
            json.dumps(self.signing), encoding="utf-8"
        )
        self.source_runs = self.root / "snapshot-input-v1.json"
        self.source_runs.write_text(json.dumps({
            "schema_version": 1,
            "runs": [{"run_id": self.run_id}],
        }), encoding="utf-8")
        self.rpm_public = self.root / "rpm-public.asc"
        self.rpm_public.write_text("test", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def header(self, path):
        source = path.name.endswith(".src.rpm")
        return {
            "name": "ro-control", "epoch": 0, "version": "1.0",
            "release": "1.fc44", "architecture": "src" if source else "x86_64",
            "source_rpm": None if source else self.srpm.name,
            "nevra": "ro-control-0:1.0-1.fc44." + ("src" if source else "x86_64"),
        }

    def verify_bundle(self):
        with mock.patch.object(ro_repo, "validate_role_public_key"), \
             mock.patch.object(ro_repo, "verify_signed_rpms"), \
             mock.patch.object(ro_repo, "rpm_header", side_effect=self.header):
            return ro_repo.verify_signed_component_bundle(
                self.root / "components", self.source_runs, self.rpm_fingerprint,
                rpm_public_key=self.rpm_public,
            )

    def test_exact_signed_component_bundle_succeeds(self):
        source_runs, components = self.verify_bundle()
        self.assertEqual(source_runs["runs"], [{"run_id": self.run_id}])
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["signing_run"], self.run_id)
        self.assertEqual(len(components[0]["packages"]), 2)

    def test_signed_bytes_mutation_is_rejected(self):
        (self.signed / self.rpm.name).write_bytes(b"mutated-after-signing")
        with self.assertRaisesRegex(ro_repo.ContractError, "signed RPM digest mismatch"):
            self.verify_bundle()

    def test_signing_run_mismatch_is_rejected(self):
        self.signing["workflow_run"] = 999
        (self.signed / "rpm-signing-evidence-v1.json").write_text(
            json.dumps(self.signing), encoding="utf-8"
        )
        with self.assertRaisesRegex(ro_repo.ContractError, "workflow run mismatch"):
            self.verify_bundle()

    def test_wrong_rpm_signing_fingerprint_is_rejected(self):
        self.signing["rpm_signing_fingerprint"] = "B" * 40
        (self.signed / "rpm-signing-evidence-v1.json").write_text(
            json.dumps(self.signing), encoding="utf-8"
        )
        with self.assertRaisesRegex(ro_repo.ContractError, "fingerprint mismatch"):
            self.verify_bundle()

    def test_duplicate_source_run_rejected_by_schema(self):
        data = {"schema_version": 1, "runs": [{"run_id": 1}, {"run_id": 1}]}
        with self.assertRaisesRegex(ro_repo.ContractError, "schema validation failed"):
            ro_repo.validate_schema(data, "snapshot-input-v1")

    def test_snapshot_workflow_uses_metadata_secrets_only(self):
        workflow = (
            pathlib.Path(__file__).parents[1]
            / ".github/workflows/build-candidate-snapshot.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("RO_REPO_METADATA_SIGNING_SUBKEY_B64", workflow)
        self.assertIn("RO_REPO_METADATA_SIGNING_PASSPHRASE", workflow)
        self.assertNotIn("RO_REPO_RPM_SIGNING_SUBKEY_B64", workflow)
        self.assertNotIn("RO_REPO_RPM_SIGNING_PASSPHRASE", workflow)
        self.assertIn("repo-production-signing", workflow)
        self.assertIn("accepted-component-$run_id", workflow)
        self.assertIn("signed-component-$run_id", workflow)
        self.assertIn('".github/workflows/accept-component.yml"', workflow)


if __name__ == "__main__":
    unittest.main()
