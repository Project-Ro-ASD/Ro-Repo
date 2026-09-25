import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
import ro_repo


class StoreCatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

        self.snapshot_id = "repo-f44-20260921-001"
        self.snapshot = self.root / self.snapshot_id
        self.snapshot.mkdir()

        self.editorial = self.root / "store" / "editorial.json"
        icons = self.editorial.parent / "icons"
        icons.mkdir(parents=True)

        self.icon = icons / "ro-assist.svg"
        self.icon.write_text("<svg>ro-assist</svg>", encoding="utf-8")

        ro_repo.save(
            self.editorial,
            {
                "schemaVersion": 1,
                "apps": {
                    "ro-assist": {
                        "name": "Ro Assist",
                        "summary": "Test application",
                        "visible": True,
                        "icon": "icons/ro-assist.svg",
                    },
                    "ro-hidden": {
                        "name": "Hidden application",
                        "visible": False,
                    },
                },
            },
        )

        sha = "a" * 64

        self.manifest = {
            "schema_version": 1,
            "snapshot_id": self.snapshot_id,
            "packages": [
                {
                    "nevra": "ro-assist-0:0.2.5-1.fc44.x86_64",
                    "architecture": "x86_64",
                    "filename": "ro-assist.rpm",
                    "producer_artifact_sha256": sha,
                    "published_signed_artifact_sha256": sha,
                    "producer_manifest_digest": sha,
                },
                {
                    "nevra": "ro-assist-0:0.2.5-1.fc44.aarch64",
                    "architecture": "aarch64",
                    "filename": "ro-assist-aarch64.rpm",
                    "producer_artifact_sha256": sha,
                    "published_signed_artifact_sha256": sha,
                    "producer_manifest_digest": sha,
                },
                {
                    "nevra": "ro-hidden-0:1.0-1.fc44.x86_64",
                    "architecture": "x86_64",
                    "filename": "ro-hidden.rpm",
                    "producer_artifact_sha256": sha,
                    "published_signed_artifact_sha256": sha,
                    "producer_manifest_digest": sha,
                },
                {
                    "nevra": "ro-asd-defaults-0:1.0-1.fc44.x86_64",
                    "architecture": "x86_64",
                    "filename": "ro-asd-defaults.rpm",
                    "producer_artifact_sha256": sha,
                    "published_signed_artifact_sha256": sha,
                    "producer_manifest_digest": sha,
                },
            ],
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_catalog_exports_only_visible_curated_apps(self):
        output = self.root / "catalog.json"

        with mock.patch.object(
            ro_repo,
            "verify_snapshot",
            return_value=self.manifest,
        ):
            result = ro_repo.catalog(
                self.snapshot,
                self.editorial,
                output,
                self.root / "gnupg",
            )

        self.assertEqual(result["schemaVersion"], 2)
        self.assertEqual(result["snapshotId"], self.snapshot_id)
        self.assertEqual(len(result["apps"]), 1)

        app = result["apps"][0]

        self.assertEqual(app["id"], "ro-assist")
        self.assertEqual(app["packageName"], "ro-assist")
        self.assertEqual(app["installPackage"], "ro-assist")
        self.assertEqual(app["packageType"], "rpm")
        self.assertEqual(app["latestVersion"], "0.2.5")
        self.assertEqual(app["latestRelease"], "1.fc44")
        self.assertEqual(app["epoch"], 0)
        self.assertEqual(app["architectures"], ["aarch64", "x86_64"])
        self.assertEqual(
            app["iconSha256"],
            ro_repo.digest(self.icon),
        )

        names = {item["packageName"] for item in result["apps"]}
        self.assertNotIn("ro-hidden", names)
        self.assertNotIn("ro-asd-defaults", names)

    def test_catalog_rejects_asset_path_traversal(self):
        data = ro_repo.load(self.editorial)
        data["apps"]["ro-assist"]["icon"] = "../outside.svg"
        ro_repo.save(self.editorial, data)

        (self.root / "outside.svg").write_text(
            "<svg>outside</svg>",
            encoding="utf-8",
        )

        with mock.patch.object(
            ro_repo,
            "verify_snapshot",
            return_value=self.manifest,
        ):
            with self.assertRaisesRegex(
                ro_repo.ContractError,
                "unsafe store asset path",
            ):
                ro_repo.catalog(
                    self.snapshot,
                    self.editorial,
                    self.root / "bad-catalog.json",
                    self.root / "gnupg",
                )


    def test_catalog_rejects_symlinked_icon_asset(self):
        outside = self.root / "outside-icon.svg"
        outside.write_text("<svg>outside</svg>", encoding="utf-8")

        self.icon.unlink()
        self.icon.symlink_to(outside)

        with mock.patch.object(
            ro_repo,
            "verify_snapshot",
            return_value=self.manifest,
        ):
            with self.assertRaisesRegex(
                ro_repo.ContractError,
                "symlink forbidden in store asset path",
            ):
                ro_repo.catalog(
                    self.snapshot,
                    self.editorial,
                    self.root / "symlink-catalog.json",
                    self.root / "gnupg",
                )



class SignedStorePublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

        self.snapshot_id = "repo-f44-20260921-001"
        self.site = self.root / "pages-site"
        self.snapshot = (
            self.site
            / "snapshots"
            / "fedora"
            / "44"
            / self.snapshot_id
        )
        self.snapshot.mkdir(parents=True)

        sha = "a" * 64

        self.manifest = {
            "schema_version": 1,
            "snapshot_id": self.snapshot_id,
            "created_at": "2026-09-21T12:17:55Z",
            "fedora_release": 44,
            "parent_snapshot": None,
            "packages": [
                {
                    "nevra": "ro-assist-0:0.2.5-1.fc44.x86_64",
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
            "creation_provenance": {
                "tool": "ro-repo-v2",
                "run": "35598643758",
            },
        }

        ro_repo.save(
            self.snapshot / "repository-snapshot-v1.json",
            self.manifest,
        )

        for arch in ("x86_64", "aarch64", "source"):
            repo = self.snapshot / "rpm" / arch
            repo.mkdir(parents=True)
            (repo / "repo-marker").write_text(
                arch,
                encoding="utf-8",
            )

        self.publication = self.root / "signed-publication"
        store = self.publication / "store"
        icons = store / "icons"
        icons.mkdir(parents=True)

        icon = icons / "ro-assist.svg"
        icon.write_text("<svg>signed-icon</svg>", encoding="utf-8")

        ro_repo.save(
            store / "catalog.json",
            {
                "schemaVersion": 2,
                "snapshotId": self.snapshot_id,
                "apps": [
                    {
                        "id": "ro-assist",
                        "packageName": "ro-assist",
                        "installPackage": "ro-assist",
                        "packageType": "rpm",
                        "latestVersion": "0.2.5",
                        "latestRelease": "1.fc44",
                        "epoch": 0,
                        "architectures": ["x86_64"],
                        "icon": "icons/ro-assist.svg",
                        "iconSha256": ro_repo.digest(icon),
                    }
                ],
            },
        )

        (store / "catalog.json.asc").write_text(
            "signed-catalog",
            encoding="utf-8",
        )

        store_tree_sha256 = ro_repo.directory_tree_digest(store)

        ro_repo.save(
            self.publication / "publication-v1.json",
            {
                "schema_version": 1,
                "channel": "beta",
                "snapshot_id": self.snapshot_id,
                "published_at": "2026-09-21T12:23:47Z",
                "publication_run": "400",
                "store_tree_sha256": store_tree_sha256,
            },
        )

        (self.publication / "publication-v1.json.asc").write_text(
            "signed-publication",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_signed_store_catalog_is_bound_to_publication(self):
        with mock.patch.object(
            ro_repo,
            "verify_gpg_signature",
        ) as verify:
            result = ro_repo.verify_signed_remote_publication(
                self.publication,
                self.snapshot,
                "beta",
                self.root / "gnupg",
            )

        self.assertEqual(result["snapshot_id"], self.snapshot_id)
        self.assertEqual(verify.call_count, 2)

    def test_store_tree_tampering_is_rejected(self):
        icon = self.publication / "store/icons/ro-assist.svg"
        icon.write_text("<svg>tampered</svg>", encoding="utf-8")

        with mock.patch.object(
            ro_repo,
            "verify_gpg_signature",
        ):
            with self.assertRaisesRegex(
                ro_repo.ContractError,
                "Ro-Store publication tree digest mismatch",
            ):
                ro_repo.verify_signed_remote_publication(
                    self.publication,
                    self.snapshot,
                    "beta",
                    self.root / "gnupg",
                )

    def test_stage_remote_channel_copies_exact_store_tree(self):
        with mock.patch.object(
            ro_repo,
            "verify_signed_remote_publication",
            return_value=ro_repo.load(
                self.publication / "publication-v1.json"
            ),
        ):
            result = ro_repo.stage_remote_channel(
                self.publication,
                self.site,
                "beta",
                self.root / "gnupg",
            )

        self.assertTrue(result["changed"])

        published_store = self.site / "rpm/fedora/44/beta/store"

        self.assertEqual(
            ro_repo.directory_tree_digest(published_store),
            ro_repo.directory_tree_digest(
                self.publication / "store"
            ),
        )

        self.assertTrue(
            (
                self.site
                / "publications/fedora/44/beta/400/store/catalog.json"
            ).is_file()
        )


    def test_legacy_publication_rejects_dangling_store_symlink(self):
        legacy = self.root / "legacy-publication"
        legacy.mkdir()

        ro_repo.save(
            legacy / "publication-v1.json",
            {
                "schema_version": 1,
                "channel": "beta",
                "snapshot_id": self.snapshot_id,
                "published_at": "2026-09-21T12:23:47Z",
                "publication_run": "401",
            },
        )

        (legacy / "publication-v1.json.asc").write_text(
            "signed-publication",
            encoding="utf-8",
        )

        (legacy / "store").symlink_to(
            legacy / "missing-store",
            target_is_directory=True,
        )

        with mock.patch.object(
            ro_repo,
            "verify_gpg_signature",
        ):
            with self.assertRaisesRegex(
                ro_repo.ContractError,
                "legacy publication contains unbound Ro-Store metadata",
            ):
                ro_repo.verify_signed_remote_publication(
                    legacy,
                    self.snapshot,
                    "beta",
                    self.root / "gnupg",
                )



class StorePublicationBuilderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

        self.snapshot_id = "repo-f44-20260921-001"
        self.snapshot = self.root / self.snapshot_id
        self.snapshot.mkdir()

        sha = "a" * 64

        self.manifest = {
            "schema_version": 1,
            "snapshot_id": self.snapshot_id,
            "created_at": "2026-09-21T12:17:55Z",
            "fedora_release": 44,
            "parent_snapshot": None,
            "packages": [
                {
                    "nevra": "ro-assist-0:0.2.5-1.fc44.x86_64",
                    "architecture": "x86_64",
                    "filename": "ro-assist-0.2.5-1.fc44.x86_64.rpm",
                    "producer_artifact_sha256": sha,
                    "published_signed_artifact_sha256": sha,
                    "producer_manifest_digest": sha,
                },
                {
                    "nevra": "ro-assist-0:0.2.5-1.fc44.aarch64",
                    "architecture": "aarch64",
                    "filename": "ro-assist-0.2.5-1.fc44.aarch64.rpm",
                    "producer_artifact_sha256": sha,
                    "published_signed_artifact_sha256": sha,
                    "producer_manifest_digest": sha,
                },
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
                "run": "35598643758",
            },
        }

        ro_repo.save(
            self.snapshot / "repository-snapshot-v1.json",
            self.manifest,
        )

        self.passphrase = self.root / "passphrase"
        self.passphrase.write_text("", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def fake_sign(path, gnupghome, key_id, passphrase_file):
        pathlib.Path(str(path) + ".asc").write_text(
            "test-signature",
            encoding="utf-8",
        )

    def test_beta_builder_generates_signed_store_publication(self):
        output = self.root / "beta-output"

        with (
            mock.patch.object(
                ro_repo,
                "require_secret_signing_subkey",
                return_value="B" * 40,
            ),
            mock.patch.object(
                ro_repo,
                "_validate_passphrase_file",
                return_value=self.passphrase,
            ),
            mock.patch.object(
                ro_repo,
                "_sign_file_exact",
                side_effect=self.fake_sign,
            ),
            mock.patch.object(
                ro_repo,
                "verify_snapshot",
                return_value=self.manifest,
            ),
        ):
            result = ro_repo.build_signed_remote_publication(
                self.snapshot,
                "beta",
                output,
                "500",
                self.root / "gnupg",
                "B" * 40,
                self.passphrase,
            )

        publication = output / "beta"
        store = publication / "store"

        self.assertTrue((store / "catalog.json").is_file())
        self.assertTrue((store / "catalog.json.asc").is_file())
        self.assertTrue((store / "icons/ro-assist.svg").is_file())

        catalog = ro_repo.load(store / "catalog.json")

        self.assertEqual(catalog["snapshotId"], self.snapshot_id)
        self.assertEqual(len(catalog["apps"]), 1)
        self.assertEqual(
            catalog["apps"][0]["packageName"],
            "ro-assist",
        )
        self.assertEqual(
            catalog["apps"][0]["latestVersion"],
            "0.2.5",
        )

        self.assertEqual(
            result["store_tree_sha256"],
            ro_repo.directory_tree_digest(store),
        )

    def test_stable_builder_reuses_exact_beta_store(self):
        beta_output = self.root / "beta-output"

        common_patches = (
            mock.patch.object(
                ro_repo,
                "require_secret_signing_subkey",
                return_value="B" * 40,
            ),
            mock.patch.object(
                ro_repo,
                "_validate_passphrase_file",
                return_value=self.passphrase,
            ),
            mock.patch.object(
                ro_repo,
                "_sign_file_exact",
                side_effect=self.fake_sign,
            ),
            mock.patch.object(
                ro_repo,
                "verify_snapshot",
                return_value=self.manifest,
            ),
        )

        with common_patches[0], common_patches[1], common_patches[2], common_patches[3]:
            ro_repo.build_signed_remote_publication(
                self.snapshot,
                "beta",
                beta_output,
                "500",
                self.root / "gnupg",
                "B" * 40,
                self.passphrase,
            )

        beta_publication = beta_output / "beta"
        beta_manifest = ro_repo.load(
            beta_publication / "publication-v1.json"
        )

        stable_output = self.root / "stable-output"

        with (
            mock.patch.object(
                ro_repo,
                "require_secret_signing_subkey",
                return_value="B" * 40,
            ),
            mock.patch.object(
                ro_repo,
                "_validate_passphrase_file",
                return_value=self.passphrase,
            ),
            mock.patch.object(
                ro_repo,
                "_sign_file_exact",
                side_effect=self.fake_sign,
            ),
            mock.patch.object(
                ro_repo,
                "verify_signed_remote_publication",
                return_value=beta_manifest,
            ) as verify_beta,
            mock.patch.object(ro_repo, "catalog") as regenerate_catalog,
        ):
            result = ro_repo.build_signed_remote_publication(
                self.snapshot,
                "stable",
                stable_output,
                "600",
                self.root / "gnupg",
                "B" * 40,
                self.passphrase,
                reuse_store_from=beta_publication,
            )

        verify_beta.assert_called_once()
        regenerate_catalog.assert_not_called()

        beta_store = beta_publication / "store"
        stable_store = stable_output / "stable/store"

        self.assertEqual(
            ro_repo.directory_tree_digest(beta_store),
            ro_repo.directory_tree_digest(stable_store),
        )

        self.assertEqual(
            result["store_tree_sha256"],
            beta_manifest["store_tree_sha256"],
        )

    def test_stable_builder_refuses_catalog_regeneration(self):
        with self.assertRaisesRegex(
            ro_repo.ContractError,
            "stable publication requires exact beta Ro-Store reuse",
        ):
            ro_repo.build_signed_remote_publication(
                self.snapshot,
                "stable",
                self.root / "stable-output",
                "600",
                self.root / "gnupg",
                "B" * 40,
                self.passphrase,
            )


    def test_beta_builder_rejects_symlinked_icons_directory(self):
        fake_root = self.root / "fake-root"
        store_root = fake_root / "store"
        store_root.mkdir(parents=True)

        # build_signed_remote_publication() validates JSON schemas via ROOT.
        # Keep the real schemas available while replacing only the test store tree.
        shutil.copytree(
            ro_repo.ROOT / "schemas",
            fake_root / "schemas",
        )

        ro_repo.save(
            store_root / "editorial.json",
            {
                "schemaVersion": 1,
                "apps": {
                    "ro-assist": {
                        "name": "Ro Assist",
                        "visible": True,
                    }
                },
            },
        )

        outside_icons = self.root / "outside-icons"
        outside_icons.mkdir()
        (outside_icons / "unexpected.svg").write_text(
            "<svg>outside</svg>",
            encoding="utf-8",
        )

        (store_root / "icons").symlink_to(
            outside_icons,
            target_is_directory=True,
        )

        output = self.root / "symlink-icons-output"

        with (
            mock.patch.object(ro_repo, "ROOT", fake_root),
            mock.patch.object(
                ro_repo,
                "require_secret_signing_subkey",
                return_value="B" * 40,
            ),
            mock.patch.object(
                ro_repo,
                "_validate_passphrase_file",
                return_value=self.passphrase,
            ),
            mock.patch.object(
                ro_repo,
                "_sign_file_exact",
                side_effect=self.fake_sign,
            ),
            mock.patch.object(
                ro_repo,
                "verify_snapshot",
                return_value=self.manifest,
            ),
        ):
            with self.assertRaisesRegex(
                ro_repo.ContractError,
                "symlink forbidden for Ro-Store icons directory",
            ):
                ro_repo.build_signed_remote_publication(
                    self.snapshot,
                    "beta",
                    output,
                    "700",
                    self.root / "gnupg",
                    "B" * 40,
                    self.passphrase,
                )



if __name__ == "__main__":
    unittest.main()
