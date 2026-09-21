import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
import ro_repo


class RemoteBetaRollbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.site = self.root / "pages-site"
        self.snapshot_id = "repo-f44-20260920-001"
        self.snapshot = self.site / "snapshots/fedora/44" / self.snapshot_id
        self.snapshot.mkdir(parents=True)

        sha = "a" * 64
        manifest = {
            "schema_version": 1,
            "snapshot_id": self.snapshot_id,
            "created_at": "2026-09-20T16:36:15Z",
            "fedora_release": 44,
            "parent_snapshot": None,
            "packages": [],
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
        ro_repo.save(self.snapshot / "repository-snapshot-v1.json", manifest)
        for arch in ("x86_64", "aarch64", "source"):
            repo = self.snapshot / "rpm" / arch
            (repo / "repodata").mkdir(parents=True)
            (repo / "repodata/repomd.xml").write_text(
                f"{arch}-repomd", encoding="utf-8"
            )
            (repo / "repodata/repomd.xml.asc").write_text(
                f"{arch}-sig", encoding="utf-8"
            )

        self.history = self.site / "publications/fedora/44/beta"
        self.history.mkdir(parents=True)
        self._write_publication("100", "2026-09-20T18:45:39Z")
        self._write_publication("200", "2026-09-20T18:50:39Z")

        beta = self.site / "rpm/fedora/44/beta"
        beta.mkdir(parents=True)
        for arch in ("x86_64", "aarch64", "source"):
            import shutil
            shutil.copytree(self.snapshot / "rpm" / arch, beta / arch)
        import shutil
        shutil.copy2(self.history / "200/publication-v1.json", beta / "publication-v1.json")
        shutil.copy2(self.history / "200/publication-v1.json.asc", beta / "publication-v1.json.asc")

    def tearDown(self):
        self.tmp.cleanup()

    def _write_publication(self, run, published_at):
        path = self.history / run
        path.mkdir()
        ro_repo.save(
            path / "publication-v1.json",
            {
                "schema_version": 1,
                "channel": "beta",
                "snapshot_id": self.snapshot_id,
                "published_at": published_at,
                "publication_run": run,
            },
        )
        (path / "publication-v1.json.asc").write_text(
            f"signature-{run}", encoding="utf-8"
        )

    def test_rollback_selects_earlier_signed_history_and_writes_evidence(self):
        with mock.patch.object(
            ro_repo, "verify_signed_remote_publication",
            side_effect=lambda pub, snap, channel, home: ro_repo.load(
                pathlib.Path(pub) / "publication-v1.json"
            ),
        ):
            evidence = ro_repo.rollback_remote_channel(
                self.site,
                "beta",
                "100",
                "300",
                "bad beta regression",
                self.root / "gnupg",
            )

        current = ro_repo.load(
            self.site / "rpm/fedora/44/beta/publication-v1.json"
        )
        self.assertEqual(current["publication_run"], "100")
        self.assertEqual(evidence["from_publication_run"], "200")
        self.assertEqual(evidence["to_publication_run"], "100")
        self.assertEqual(evidence["rollback_run"], "300")
        self.assertEqual(evidence["reason"], "bad beta regression")

        evidence_path = self.site / "rollbacks/fedora/44/beta/300.json"
        self.assertEqual(ro_repo.load(evidence_path), evidence)

    def test_rollback_evidence_keeps_distinct_from_and_to_manifest_digests(self):
        with mock.patch.object(
            ro_repo, "verify_signed_remote_publication",
            side_effect=lambda pub, snap, channel, home: ro_repo.load(
                pathlib.Path(pub) / "publication-v1.json"
            ),
        ):
            before = ro_repo.digest(
                self.site / "rpm/fedora/44/beta/publication-v1.json"
            )
            target = ro_repo.digest(
                self.history / "100/publication-v1.json"
            )
            self.assertNotEqual(before, target)

            evidence = ro_repo.rollback_remote_channel(
                self.site,
                "beta",
                "100",
                "301",
                "digest audit canary",
                self.root / "gnupg",
            )

        self.assertEqual(evidence["from_publication_sha256"], before)
        self.assertEqual(evidence["to_publication_sha256"], target)
        self.assertNotEqual(
            evidence["from_publication_sha256"],
            evidence["to_publication_sha256"],
        )

    def test_rollback_rejects_current_publication_as_target(self):
        with self.assertRaisesRegex(
            ro_repo.ContractError, "already the current beta"
        ):
            ro_repo.rollback_remote_channel(
                self.site,
                "beta",
                "200",
                "300",
                "no-op",
                self.root / "gnupg",
            )

    def test_rollback_requires_existing_history(self):
        with self.assertRaisesRegex(
            ro_repo.ContractError, "history entry is missing"
        ):
            ro_repo.rollback_remote_channel(
                self.site,
                "beta",
                "999",
                "300",
                "missing target",
                self.root / "gnupg",
            )

    def test_rollback_requires_nonempty_reason(self):
        with self.assertRaisesRegex(
            ro_repo.ContractError, "reason must be non-empty"
        ):
            ro_repo.rollback_remote_channel(
                self.site,
                "beta",
                "100",
                "300",
                "   ",
                self.root / "gnupg",
            )

    def test_rollback_workflow_has_no_signing_authority(self):
        path = (
            pathlib.Path(__file__).parents[1]
            / ".github/workflows/rollback-remote-beta.yml"
        )
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        jobs = data["jobs"]

        self.assertIn("workflow_dispatch", data["on"])
        self.assertEqual(
            jobs["rollback-beta"]["environment"]["name"], "repo-beta"
        )
        self.assertNotIn("repo-production-signing", text)
        self.assertNotIn("RO_REPO_METADATA_SIGNING_SUBKEY_B64", text)
        self.assertNotIn("RO_REPO_METADATA_SIGNING_PASSPHRASE", text)
        self.assertNotIn("secrets.", text)
        self.assertIn("verify-remote-beta-after-rollback", jobs)


if __name__ == "__main__":
    unittest.main()
