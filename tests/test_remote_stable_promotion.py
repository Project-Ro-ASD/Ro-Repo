import datetime as dt
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
import ro_repo


class RemoteStablePromotionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.site = self.root / "pages-site"
        self.snapshot_id = "repo-f44-20260920-001"

        beta = self.site / "rpm/fedora/44/beta"
        beta.mkdir(parents=True)

        self.snapshot = self.site / "snapshots/fedora/44" / self.snapshot_id
        self.snapshot.mkdir(parents=True)

        sha = "a" * 64
        ro_repo.save(
            self.snapshot / "repository-snapshot-v1.json",
            {
                "schema_version": 1,
                "snapshot_id": self.snapshot_id,
                "created_at": "2026-09-20T16:36:15Z",
                "fedora_release": 44,
                "parent_snapshot": None,
                "packages": [
                    {
                        "architecture": "x86_64",
                        "filename": "ro-assist-0.2.4-1.fc44.x86_64.rpm",
                        "nevra": "ro-assist-0:0.2.4-1.fc44.x86_64",
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
            },
        )

        self.beta_path = beta / "publication-v1.json"
        self.validation = self.root / "promotion-validation-v1.json"
        self.output = self.root / "promotion-manifest-v1.json"

    def tearDown(self):
        self.tmp.cleanup()

    def write_beta(self, age_days=8, publication_run="35530066972"):
        published = (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=age_days)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        ro_repo.save(
            self.beta_path,
            {
                "schema_version": 1,
                "channel": "beta",
                "snapshot_id": self.snapshot_id,
                "published_at": published,
                "publication_run": publication_run,
            },
        )
        return published

    def write_validation(
        self,
        beta_started_at,
        validation_run="400",
        beta_publication_run="35530066972",
        tests=None,
    ):
        if tests is None:
            tests = [
                "dependency-solve",
                "clean-install",
                "upgrade",
                "file-conflict",
                "rpmlint",
                "smoke",
            ]
        ro_repo.save(
            self.validation,
            {
                "schema_version": 1,
                "scope": "remote-beta-promotion",
                "snapshot_id": self.snapshot_id,
                "validation_run": validation_run,
                "beta_publication_run": beta_publication_run,
                "beta_started_at": beta_started_at,
                "tested_at": dt.datetime.now(dt.timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "architecture": "x86_64",
                "remote_base": "https://repo.ro-asd.org/rpm/fedora/44/beta/x86_64",
                "result": "pass",
                "tests": [{"name": name, "result": "pass"} for name in tests],
                "baseline": {
                    "repository": "Project-Ro-ASD/ro-Assist",
                    "release_tag": "v0.2.1",
                    "filename": "ro-assist-0.2.1.x86_64.rpm",
                    "sha256": "4ec9a878fa112de2465b8fdcbf4682d8e699ada0d6a1af76f639bdcf68eddca1",
                },
            },
        )

    def test_normal_app_promotion_passes_after_seven_days(self):
        started = self.write_beta(age_days=8)
        self.write_validation(started)

        promotion = ro_repo.prepare_remote_stable_promotion(
            self.site,
            self.validation,
            self.snapshot_id,
            "400",
            "maintainer",
            self.output,
        )

        self.assertEqual(promotion["snapshot_id"], self.snapshot_id)
        self.assertEqual(promotion["risk_class"], "normal-app")
        self.assertEqual(promotion["promotion_groups"], ["ro-assist"])
        self.assertFalse(promotion["emergency"])
        self.assertEqual(len(promotion["evidence"]), 6)
        self.assertTrue(self.output.is_file())

    def test_normal_app_promotion_rejected_before_seven_days(self):
        started = self.write_beta(age_days=1)
        self.write_validation(started)

        with self.assertRaises(ro_repo.ContractError) as caught:
            ro_repo.prepare_remote_stable_promotion(
                self.site,
                self.validation,
                self.snapshot_id,
                "400",
                "maintainer",
                self.output,
            )

        self.assertEqual(caught.exception.code, "BETA_DWELL_NOT_MET")
        self.assertEqual(caught.exception.stage, "promotion-dwell")

    def test_validation_must_match_current_beta_publication_run(self):
        started = self.write_beta(age_days=8, publication_run="500")
        self.write_validation(
            started,
            validation_run="400",
            beta_publication_run="35530066972",
        )

        with self.assertRaisesRegex(
            ro_repo.ContractError,
            "not for the current beta publication",
        ):
            ro_repo.prepare_remote_stable_promotion(
                self.site,
                self.validation,
                self.snapshot_id,
                "400",
                "maintainer",
                self.output,
            )

    def test_validation_run_is_exact_identity(self):
        started = self.write_beta(age_days=8)
        self.write_validation(started, validation_run="401")

        with self.assertRaisesRegex(
            ro_repo.ContractError,
            "validation run identity mismatch",
        ):
            ro_repo.prepare_remote_stable_promotion(
                self.site,
                self.validation,
                self.snapshot_id,
                "400",
                "maintainer",
                self.output,
            )

    def test_missing_required_evidence_is_rejected(self):
        started = self.write_beta(age_days=8)
        self.write_validation(
            started,
            tests=[
                "dependency-solve",
                "clean-install",
                "upgrade",
                "file-conflict",
                "rpmlint",
            ],
        )

        with self.assertRaisesRegex(
            ro_repo.ContractError,
            "promotion validation evidence missing: smoke",
        ):
            ro_repo.prepare_remote_stable_promotion(
                self.site,
                self.validation,
                self.snapshot_id,
                "400",
                "maintainer",
                self.output,
            )

    def test_validation_workflow_is_read_only_and_secret_free(self):
        path = (
            pathlib.Path(__file__).parents[1]
            / ".github/workflows/validate-remote-beta-promotion.yml"
        )
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)

        self.assertIn("workflow_dispatch", data["on"])
        self.assertEqual(data["permissions"]["contents"], "read")
        self.assertNotIn("environment", json.dumps(data["jobs"]))
        self.assertNotIn("secrets.", text)
        self.assertNotIn("contents: write", text)

    def test_stable_workflow_separates_signing_and_publish_authority(self):
        path = (
            pathlib.Path(__file__).parents[1]
            / ".github/workflows/promote-remote-stable.yml"
        )
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        jobs = data["jobs"]

        self.assertEqual(
            jobs["sign-stable-publication"]["environment"]["name"],
            "repo-production-signing",
        )
        self.assertEqual(
            jobs["publish-stable"]["environment"]["name"],
            "repo-stable",
        )
        self.assertEqual(
            jobs["publish-stable"]["permissions"]["contents"],
            "write",
        )

        signer = json.dumps(jobs["sign-stable-publication"], sort_keys=True)
        publisher = json.dumps(jobs["publish-stable"], sort_keys=True)

        self.assertIn("RO_REPO_METADATA_SIGNING_SUBKEY_B64", signer)
        self.assertIn("RO_REPO_METADATA_SIGNING_PASSPHRASE", signer)
        self.assertNotIn("RO_REPO_METADATA_SIGNING_SUBKEY_B64", publisher)
        self.assertNotIn("RO_REPO_METADATA_SIGNING_PASSPHRASE", publisher)
        self.assertIn("verify-remote-stable", jobs)
        self.assertNotIn("emergency", text.lower())


if __name__ == "__main__":
    unittest.main()
