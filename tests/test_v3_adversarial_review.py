"""Decision regressions found by adversarial review of PR #71.

GPG substitution uses actual temporary keys/signatures. Integration I/O tests
mock the RPM executable boundary only; they do not claim application acceptance.
"""
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from v3_authorization import request, verify_signed
from v3_integration import prepare, tree_inventory
from v3_policy_profile import canonical, require_complete, sha
from v3_promotion_planner import PlanningError, plan
from v3_publication_rehearsal import initialize, begin, finish, audit
from test_v3_integration import make_proposal, REGISTRY
from test_v3_promotion_planner import assist, rpm, snapshot


class FullSetPolicyReviewTests(unittest.TestCase):
    def test_retained_group_requires_all_registered_architectures(self):
        registry = json.loads((ROOT / "config/producers-v2.json").read_text())
        old = [rpm("ro-control", "1.0", arch) for arch in ("src", "x86_64")]
        value = plan(snapshot("repo-f44-20261011-002", assist()),
                     snapshot("repo-f44-20261001-001", old), registry, "ro-assist")
        with self.assertRaisesRegex(PlanningError, "architecture"):
            require_complete(value, registry)


class SignedBoundaryReviewTests(unittest.TestCase):
    @staticmethod
    def command(argv):
        return subprocess.run(argv, capture_output=True, check=True).stdout

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="v3-review-gpg-")
        cls.base = pathlib.Path(cls.temporary.name)
        cls.homes, cls.public = [], []
        for name in ("trusted", "attacker"):
            home = cls.base / name
            home.mkdir(mode=0o700)
            cls.command(["gpg", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback",
                         "--passphrase", "", "--quick-generate-key", name + " <test@invalid>", "ed25519", "sign", "1d"])
            cls.homes.append(home)
            cls.public.append(cls.command(["gpg", "--homedir", str(home), "--armor", "--export"]))

    @classmethod
    def tearDownClass(cls):
        for home in cls.homes:
            cls.command(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"])
        cls.temporary.cleanup()

    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(dir=self.base))
        self.key = self.work / "approval-public.asc"
        self.key.write_bytes(self.public[0])
        self.key_sha = hashlib.sha256(self.public[0]).hexdigest()
        self.tree = self.work / "result"
        self.tree.mkdir()
        (self.tree / "content").write_bytes(b"complete local view")
        self.value = make_proposal(result=sha(tree_inventory(self.tree)))
        self.now = "2026-10-11T12:00:00Z"
        self.root = self.work / "rehearsal"
        initialize(self.root)

    def sign_file(self, path, signer=0):
        self.command(["gpg", "--homedir", str(self.homes[signer]), "--batch", "--yes", "--armor",
                      "--detach-sign", str(path)])

    def approval(self, signer=0):
        directory = self.work / "approval"
        directory.mkdir()
        value = {**request(self.value, "try-1"), "actor": "test-maintainer",
                 "approved_at": self.now, "expires_at": "2026-10-11T13:00:00Z"}
        file = directory / "authorization-v3.json"
        file.write_bytes(canonical(value))
        self.sign_file(file, signer)
        return directory

    def start(self, directory):
        return begin(self.root, self.value, self.tree, directory, "try-1",
                     key=self.key, key_sha256=self.key_sha, now=self.now)

    def test_pinned_key_cannot_be_replaced_between_hash_and_import(self):
        import v3_signed_beta_history as history
        original = history._verify
        def substitute(command):
            if "--import" in command:
                self.key.write_bytes(self.public[1])
            return original(command)
        with mock.patch.object(history, "_verify", side_effect=substitute):
            with self.assertRaises(PlanningError):
                verify_signed(self.value, self.approval(signer=1), "try-1", self.key,
                              self.key_sha, now=self.now)

    def test_completed_begin_must_recheck_historical_tree(self):
        directory = self.approval()
        self.start(directory)
        finish(self.root, "try-1", now=self.now)
        (self.root / "snapshots" / self.value["result_stable_sha256"] / "content").write_bytes(b"tampered")
        with self.assertRaises(PlanningError):
            self.start(directory)

    def test_broken_audit_chain_blocks_completion(self):
        self.start(self.approval())
        path = self.root / "state.json"
        state = json.loads(path.read_text())
        state["audit"][0]["phase"] = "forged-attempt"
        path.write_bytes(canonical(state))
        with self.assertRaises(PlanningError):
            finish(self.root, "try-1", now=self.now)

    def test_corrupted_previous_snapshot_blocks_new_attempt(self):
        self.start(self.approval())
        finish(self.root, "try-1", now=self.now)
        (self.root / "snapshots" / self.value["result_stable_sha256"] / "content").write_bytes(b"tampered")
        new_tree = self.work / "new-view"
        new_tree.mkdir()
        (new_tree / "content").write_bytes(b"new view")
        value = copy.deepcopy(self.value)
        value["previous_stable_snapshot_id"] = "repo-f44-20261011-001"
        value["previous_stable_sha256"] = self.value["result_stable_sha256"]
        value["result_stable_sha256"] = sha(tree_inventory(new_tree))
        value["proposal_sha256"] = sha({k: v for k, v in value.items() if k != "proposal_sha256"})
        directory = self.work / "next-approval"
        directory.mkdir()
        file = directory / "authorization-v3.json"
        file.write_bytes(canonical({**request(value, "try-2"), "actor": "test-maintainer",
                                   "approved_at": self.now, "expires_at": "2026-10-11T13:00:00Z"}))
        self.sign_file(file)
        with self.assertRaises(PlanningError):
            begin(self.root, value, new_tree, directory, "try-2", key=self.key, key_sha256=self.key_sha, now=self.now)

    def signed_snapshot(self, name, packages, parent=None):
        root = self.work / name
        root.mkdir()
        packages = copy.deepcopy(packages)
        for item in packages:
            data = ("RPM executable boundary fixture: " + item["filename"]).encode()
            item["published_signed_artifact_sha256"] = hashlib.sha256(data).hexdigest()
            folders = ["source"] if item["architecture"] == "src" else [item["architecture"]]
            for folder in folders:
                path = root / "rpm" / folder / item["filename"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        repositories = {}
        for arch in ("source", "x86_64", "aarch64"):
            file = root / "rpm" / arch / "repodata/repomd.xml"
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"<repomd/>")
            self.sign_file(file)
            repositories[arch] = {"repomd_sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
                                  "repomd_signature_sha256": hashlib.sha256(pathlib.Path(str(file) + ".asc").read_bytes()).hexdigest()}
        keyinfo = self.command(["gpg", "--homedir", str(self.homes[0]), "--with-colons", "--list-keys"]).decode()
        fingerprint = next(line.split(":")[9] for line in keyinfo.splitlines() if line.startswith("fpr:"))
        manifest = {"schema_version": 1, "snapshot_id": name, "created_at": self.now,
                    "fedora_release": 44, "parent_snapshot": parent, "packages": packages,
                    "repositories": repositories, "rpm_signing_fingerprint": "A" * 40,
                    "metadata_signing_fingerprint": fingerprint,
                    "creation_provenance": {"tool": "ro-repo-v2", "run": "1"}}
        file = root / "repository-snapshot-v1.json"
        file.write_bytes(canonical(manifest))
        self.sign_file(file)
        build = {"schema_version": 1, "snapshot_id": name, "created_at": self.now, "workflow_run": 1,
                 "source_signing_runs": [1], "repository_snapshot_sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
                 "rpm_signing_fingerprint": manifest["rpm_signing_fingerprint"],
                 "metadata_signing_fingerprint": fingerprint,
                 "components": [{"acceptance_manifest_digest": packages[0]["producer_manifest_digest"],
                                 "source_repository": "Project-Ro-ASD/test-only", "source_commit": "a" * 40,
                                 "release_tag": "test", "release_id": 1, "producer_workflow_run": 1, "signing_run": 1}]}
        file = root / "snapshot-build-evidence-v1.json"
        file.write_bytes(canonical(build))
        self.sign_file(file)
        return root, manifest

    def test_result_signature_toctou_cannot_bind_unsigned_manifest(self):
        import v3_full_set_dnf as dnf
        beta, manifest = self.signed_snapshot("repo-f44-20261010-001", assist())
        result, _ = self.signed_snapshot("repo-f44-20261011-002", manifest["packages"])
        p = plan(manifest, None, REGISTRY, "ro-assist")
        history = {"candidate_remote_verify_times": [{"publication_run": "101", "published_at": "2026-10-01T12:00:00Z",
                   "promotion_group": "ro-assist", "candidate_sha256": p["candidate_sha256"]}]}
        original = dnf._signed_view
        def mutate_after_signature(root, ring):
            verified = original(root, ring)
            file = result / "repository-snapshot-v1.json"
            changed = json.loads(file.read_text())
            changed["creation_provenance"]["run"] = "unsigned-substitution"
            file.write_bytes(canonical(changed))
            return verified
        with mock.patch("v3_integration.verify_rpms", return_value={"publishable": False}), \
             mock.patch("v3_integration.verify_evidence", return_value=history), \
             mock.patch.object(dnf, "_signed_view", side_effect=mutate_after_signature):
            with self.assertRaisesRegex(PlanningError, "changed|digest|signature"):
                prepare(beta, None, REGISTRY, "ro-assist", self.work / "proposal", publications=self.work,
                        snapshots=self.work, collection={}, metadata_key=self.key, metadata_key_sha256=self.key_sha,
                        rpm_key=self.key, rpm_key_sha256=self.key_sha, now=self.now, result_snapshot=result)

    def test_dnf_baseline_must_match_plan_identity(self):
        import v3_full_set_dnf as dnf
        candidate = snapshot("repo-f44-20261011-003", assist())
        expected = snapshot("repo-f44-20261001-001", assist())
        p = plan(candidate, expected, REGISTRY, "ro-assist")
        current, beta, baseline = (self.work / name for name in ("current", "beta", "wrong-baseline"))
        for path in (current, beta, baseline):
            path.mkdir()
            (path / "content").write_bytes(b"fixture")
        wrong = snapshot("repo-f44-20261002-002", assist())
        def signed_view(root, ring):
            return wrong if root.name == baseline.name else candidate
        def command(argv, **kwargs):
            if argv[:2] == ["dnf", "--version"]:
                return "dnf5 test boundary"
            if "repoquery" in argv:
                return "ro-assist\n"
            if argv[:2] == ["rpm", "--root"]:
                return "0:0.2.5-1.fc44.x86_64"
            return ""
        read_text = pathlib.Path.read_text
        def distro_or_file(path, *args, **kwargs):
            if path == pathlib.Path("/etc/os-release"):
                return "ID=fedora\nVERSION_ID=44\n"
            return read_text(path, *args, **kwargs)
        with mock.patch.object(dnf, "_signed_view", side_effect=signed_view), \
             mock.patch.object(dnf, "_run", side_effect=command), \
             mock.patch.object(pathlib.Path, "read_text", autospec=True, side_effect=distro_or_file), \
             mock.patch("ro_repo.verify_signed_rpms"), mock.patch("ro_repo.file_conflict_check", return_value=(True, [])), \
             mock.patch.object(dnf.platform, "machine", return_value="x86_64"):
            with self.assertRaisesRegex(PlanningError, "baseline|base"):
                dnf.validate(current, baseline, beta, p, "x86_64", self.work / "dnf-evidence",
                             rpm_key=self.key, rpm_key_sha256=self.key_sha,
                             metadata_key=self.key, metadata_key_sha256=self.key_sha)

    def live_fixture(self):
        root = self.work / "pages"
        directory = root / "rpm/fedora/44/stable"
        directory.mkdir(parents=True)
        file = directory / "publication-v1.json"
        publication = {"schema_version": 1, "channel": "stable", "publication_run": "1",
                       "published_at": self.now, "snapshot_id": "repo-f44-20261011-002", "store_tree_sha256": "a" * 64}
        file.write_bytes(canonical(publication))
        self.sign_file(file)
        self.command(["git", "-C", str(root), "init", "-b", "pages-storage"])
        self.command(["git", "-C", str(root), "add", "."])
        self.command(["git", "-C", str(root), "-c", "user.name=Review fixture", "-c", "user.email=test@invalid",
                      "commit", "-m", "local pinned stable fixture"])
        commit = self.command(["git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip()
        return root, file, publication, commit

    def run_live(self, root, commit, stable_id):
        from v3_integration import prepare_live
        def staged_prepare(*args, **kwargs):
            directory = pathlib.Path(args[4])
            directory.mkdir()
            (directory / "test-only-composition").write_text("fixture")
            return self.value
        with mock.patch("v3_github_source_pins.verify_registry_pin", return_value={}), \
             mock.patch("v3_github_source_pins.audit_with_live_pins", return_value={}), \
             mock.patch("v3_github_source_pins._refs_match"), \
             mock.patch("v3_live_receipt_audit.audit_live_run", return_value={}), \
             mock.patch("v3_github_beta_api.collect", return_value={}), \
             mock.patch("v3_integration.prepare", side_effect=staged_prepare):
            return prepare_live(root, REGISTRY, "ro-assist", self.work / "live-proposal", token="test-only",
                                request_json=lambda *a: {}, main_sha="a" * 40, pages_sha=commit,
                                metadata_key=self.key, metadata_key_sha256=self.key_sha,
                                rpm_key=self.key, rpm_key_sha256=self.key_sha,
                                beta_snapshot_id="repo-f44-20261011-003", stable_snapshot_id=stable_id,
                                source_receipt_run="1", download_zip=lambda *a: None, now=self.now)

    def test_live_stable_pointer_must_match_pinned_git_bytes(self):
        root, file, publication, commit = self.live_fixture()
        publication["snapshot_id"] = "repo-f44-20261001-001"
        file.write_bytes(canonical(publication))
        self.sign_file(file)
        with self.assertRaises(PlanningError):
            self.run_live(root, commit, publication["snapshot_id"])

    def test_live_bootstrap_cannot_hide_tracked_stable_directory(self):
        import shutil
        root, file, publication, commit = self.live_fixture()
        shutil.rmtree(file.parent)
        with self.assertRaises(PlanningError):
            self.run_live(root, commit, None)


if __name__ == "__main__":
    unittest.main()
