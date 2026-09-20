import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
import ro_repo


class RemoteBetaPublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.snapshot_id = "repo-f44-20260920-001"
        self.site = self.root / "pages-site"
        self.snapshot = self.site / "snapshots/fedora/44" / self.snapshot_id
        self.snapshot.mkdir(parents=True)

        sha = "a" * 64
        self.manifest = {
            "schema_version": 1,
            "snapshot_id": self.snapshot_id,
            "created_at": "2026-09-20T16:36:15Z",
            "fedora_release": 44,
            "parent_snapshot": None,
            "packages": [
                {
                    "nevra": "ro-assist-0:0.2.4-1.fc44.x86_64",
                    "architecture": "x86_64",
                    "filename": "ro-assist.rpm",
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
            "creation_provenance": {"tool": "ro-repo-v2", "run": "35523196901"},
        }
        ro_repo.save(self.snapshot / "repository-snapshot-v1.json", self.manifest)

        for arch in ("x86_64", "aarch64", "source"):
            repo = self.snapshot / "rpm" / arch
            (repo / "repodata").mkdir(parents=True)
            (repo / "repodata/repomd.xml").write_text(
                f"{arch}-repomd", encoding="utf-8"
            )
            (repo / "repodata/repomd.xml.asc").write_text(
                f"{arch}-signature", encoding="utf-8"
            )
        (self.snapshot / "rpm/x86_64/ro-assist.rpm").write_bytes(b"signed-rpm")

        self.publication = self.root / "signed-publication"
        self.publication.mkdir()
        ro_repo.save(
            self.publication / "publication-v1.json",
            {
                "schema_version": 1,
                "channel": "beta",
                "snapshot_id": self.snapshot_id,
                "published_at": "2026-09-20T18:30:00Z",
                "publication_run": "400",
            },
        )
        (self.publication / "publication-v1.json.asc").write_text(
            "signed-publication", encoding="utf-8"
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_stage_remote_beta_copies_exact_snapshot_repository_bytes(self):
        with mock.patch.object(
            ro_repo, "verify_signed_remote_publication",
            return_value=ro_repo.load(self.publication / "publication-v1.json"),
        ):
            result = ro_repo.stage_remote_channel(
                self.publication, self.site, "beta", self.root / "gnupg"
            )

        self.assertTrue(result["changed"])
        self.assertEqual(result["snapshot_id"], self.snapshot_id)
        beta = self.site / "rpm/fedora/44/beta"
        for arch in ("x86_64", "aarch64", "source"):
            self.assertEqual(
                ro_repo.directory_tree_digest(beta / arch),
                ro_repo.directory_tree_digest(self.snapshot / "rpm" / arch),
            )
        self.assertEqual(
            ro_repo.load(beta / "publication-v1.json")["snapshot_id"],
            self.snapshot_id,
        )
        self.assertTrue(
            (self.site / "publications/fedora/44/beta/400/publication-v1.json").is_file()
        )

    def test_stage_remote_beta_is_idempotent_for_same_signed_publication(self):
        with mock.patch.object(
            ro_repo, "verify_signed_remote_publication",
            return_value=ro_repo.load(self.publication / "publication-v1.json"),
        ):
            first = ro_repo.stage_remote_channel(
                self.publication, self.site, "beta", self.root / "gnupg"
            )
            second = ro_repo.stage_remote_channel(
                self.publication, self.site, "beta", self.root / "gnupg"
            )
        self.assertTrue(first["changed"])
        self.assertFalse(second["changed"])

    def test_publication_history_run_cannot_change_bytes(self):
        with mock.patch.object(
            ro_repo, "verify_signed_remote_publication",
            return_value=ro_repo.load(self.publication / "publication-v1.json"),
        ):
            ro_repo.stage_remote_channel(
                self.publication, self.site, "beta", self.root / "gnupg"
            )
            (self.publication / "publication-v1.json.asc").write_text(
                "different-signature", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ro_repo.ContractError,
                "publication history run already exists with different bytes",
            ):
                ro_repo.stage_remote_channel(
                    self.publication, self.site, "beta", self.root / "gnupg"
                )

    def test_publish_beta_installs_git_before_writable_pages_checkout(self):
        path = (
            pathlib.Path(__file__).parents[1]
            / ".github/workflows/publish-remote-beta.yml"
        )
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        steps = data["jobs"]["publish-beta"]["steps"]
        names = [step.get("name") for step in steps]

        install_index = names.index("Install Git before writable Pages checkout")
        checkout_index = names.index("Checkout persistent Pages storage")
        self.assertLess(install_index, checkout_index)

        install_step = steps[install_index]
        self.assertIn("dnf -y install git", install_step["run"])

    def test_remote_beta_workflow_separates_signing_and_publish_authority(self):
        path = (
            pathlib.Path(__file__).parents[1]
            / ".github/workflows/publish-remote-beta.yml"
        )
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)

        self.assertIn("workflow_dispatch", data["on"])
        jobs = data["jobs"]
        self.assertEqual(
            jobs["sign-beta-publication"]["environment"]["name"],
            "repo-production-signing",
        )
        self.assertEqual(
            jobs["publish-beta"]["environment"]["name"],
            "repo-beta",
        )
        self.assertEqual(jobs["publish-beta"]["permissions"]["contents"], "write")

        sign_text = json.dumps(jobs["sign-beta-publication"], sort_keys=True)
        publish_text = json.dumps(jobs["publish-beta"], sort_keys=True)
        self.assertIn("RO_REPO_METADATA_SIGNING_SUBKEY_B64", sign_text)
        self.assertIn("RO_REPO_METADATA_SIGNING_PASSPHRASE", sign_text)
        self.assertNotIn("RO_REPO_METADATA_SIGNING_SUBKEY_B64", publish_text)
        self.assertNotIn("RO_REPO_METADATA_SIGNING_PASSPHRASE", publish_text)

        self.assertIn("verify-remote-beta", jobs)
        self.assertIn("repo.ro-asd.org/rpm/fedora/44/beta", text)


if __name__ == "__main__":
    unittest.main()
