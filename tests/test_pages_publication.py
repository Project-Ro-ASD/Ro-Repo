import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
import ro_repo


class PagesPublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.snapshot_id = "repo-f44-20260920-001"
        self.snapshot = self.root / self.snapshot_id
        self.snapshot.mkdir()

        sha = "a" * 64
        manifest = {
            "schema_version": 1,
            "snapshot_id": self.snapshot_id,
            "created_at": "2026-09-20T16:36:00Z",
            "fedora_release": 44,
            "parent_snapshot": None,
            "packages": [
                {
                    "nevra": "ro-assist-0:0.2.4-1.fc44.x86_64",
                    "architecture": "x86_64",
                    "filename": "ro-assist-0.2.4-1.fc44.x86_64.rpm",
                    "producer_artifact_sha256": sha,
                    "published_signed_artifact_sha256": sha,
                    "producer_manifest_digest": sha,
                }
            ],
            "repositories": {
                arch: {
                    "repomd_sha256": sha,
                    "repomd_signature_sha256": sha,
                }
                for arch in ("x86_64", "aarch64", "source")
            },
            "rpm_signing_fingerprint": "A" * 40,
            "metadata_signing_fingerprint": "B" * 40,
            "creation_provenance": {
                "tool": "ro-repo-v2",
                "run": "35523196901",
            },
        }
        ro_repo.save(self.snapshot / "repository-snapshot-v1.json", manifest)
        (self.snapshot / "repository-snapshot-v1.json.asc").write_text(
            "signature", encoding="utf-8"
        )
        (self.snapshot / "payload.bin").write_bytes(b"immutable candidate bytes")
        self.manifest = manifest

    def tearDown(self):
        self.tmp.cleanup()

    def test_stage_pages_snapshot_is_immutable_and_idempotent(self):
        site = self.root / "site"
        first = ro_repo.stage_pages_snapshot(self.snapshot, site)
        self.assertTrue(first["created"])
        self.assertTrue((site / ".nojekyll").is_file())

        target = site / "snapshots/fedora/44" / self.snapshot_id
        self.assertTrue(target.is_dir())
        self.assertEqual(
            ro_repo.directory_tree_digest(target),
            ro_repo.directory_tree_digest(self.snapshot),
        )

        second = ro_repo.stage_pages_snapshot(self.snapshot, site)
        self.assertFalse(second["created"])
        self.assertEqual(first["tree_sha256"], second["tree_sha256"])

    def test_stage_pages_snapshot_rejects_existing_different_bytes(self):
        site = self.root / "site"
        ro_repo.stage_pages_snapshot(self.snapshot, site)
        (self.snapshot / "payload.bin").write_bytes(b"different bytes")
        with self.assertRaisesRegex(
            ro_repo.ContractError,
            "immutable Pages snapshot already exists with different bytes",
        ):
            ro_repo.stage_pages_snapshot(self.snapshot, site)

    def test_directory_tree_digest_rejects_symlinks(self):
        (self.snapshot / "link").symlink_to("payload.bin")
        with self.assertRaisesRegex(ro_repo.ContractError, "symlink forbidden"):
            ro_repo.directory_tree_digest(self.snapshot)

    def test_verify_production_candidate_binds_exact_run_and_evidence(self):
        evidence = {
            "schema_version": 1,
            "snapshot_id": self.snapshot_id,
            "created_at": "2026-09-20T16:36:00Z",
            "workflow_run": 35523196901,
            "source_signing_runs": [35518631417],
            "repository_snapshot_sha256": ro_repo.digest(
                self.snapshot / "repository-snapshot-v1.json"
            ),
            "rpm_signing_fingerprint": self.manifest["rpm_signing_fingerprint"],
            "metadata_signing_fingerprint": self.manifest[
                "metadata_signing_fingerprint"
            ],
            "components": [
                {
                    "signing_run": 35518631417,
                    "source_repository": "Project-Ro-ASD/ro-Assist",
                    "source_commit": "d" * 40,
                    "release_tag": "v0.2.4",
                    "release_id": 392457957,
                    "producer_workflow_run": 35516261384,
                    "acceptance_manifest_digest": "c" * 64,
                }
            ],
        }
        ro_repo.save(self.snapshot / "snapshot-build-evidence-v1.json", evidence)
        (self.snapshot / "snapshot-build-evidence-v1.json.asc").write_text(
            "signature", encoding="utf-8"
        )
        verify_home = self.root / "verify-gnupg"
        verify_home.mkdir()

        with mock.patch.object(
            ro_repo, "verify_snapshot", return_value=self.manifest
        ), mock.patch.object(ro_repo, "verify_gpg_signature"):
            manifest, returned = ro_repo.verify_production_candidate(
                self.snapshot, verify_home, "35523196901"
            )
        self.assertEqual(manifest["snapshot_id"], self.snapshot_id)
        self.assertEqual(returned["workflow_run"], 35523196901)

        with mock.patch.object(
            ro_repo, "verify_snapshot", return_value=self.manifest
        ), self.assertRaisesRegex(
            ro_repo.ContractError, "workflow run mismatch"
        ):
            ro_repo.verify_production_candidate(
                self.snapshot, verify_home, "35523196902"
            )

    def test_pages_workflow_is_dispatchable_and_has_no_signing_secrets(self):
        workflow_path = (
            pathlib.Path(__file__).parents[1]
            / ".github/workflows/publish-pages-snapshot.yml"
        )
        text = workflow_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)

        self.assertIn("workflow_dispatch", data["on"])
        self.assertEqual(data["permissions"]["contents"], "write")
        self.assertEqual(data["permissions"]["actions"], "read")
        self.assertIn("publish-pages-storage", data["jobs"])
        self.assertIn("pages-storage", text)
        self.assertIn(
            "candidate-snapshot-${{ inputs.snapshot_id }}-${{ inputs.candidate_run }}",
            text,
        )
        self.assertIn(".github/workflows/build-candidate-snapshot.yml", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("RO_REPO_METADATA_SIGNING_SUBKEY_B64", text)
        self.assertNotIn("RO_REPO_RPM_SIGNING_SUBKEY_B64", text)


if __name__ == "__main__":
    unittest.main()
