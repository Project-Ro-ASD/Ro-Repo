"""Exact disposable project URLs; no live GitHub/Pages requests or writes."""
import importlib.util
import pathlib
import shutil
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_backend_support import Fixture, Keys, NOW
from v3_backend_trust import test_workspace
from v3_immutable_view import (DisposablePagesProject, HTTPSReader, IsolatedStore,
                               immutable_url, production_publish)
from v3_promotion_planner import PlanningError

REPOSITORY = "minitheguitarist/ro-v3-disposable-pages"
BASE = "https://minitheguitarist.github.io/ro-v3-disposable-pages"
DIGEST = "a" * 64
ARCHES = ("x86_64", "aarch64", "source")
BAD_URLS = (
    "http://minitheguitarist.github.io/ro-v3-disposable-pages",
    "https://other.github.io/ro-v3-disposable-pages",
    "https://minitheguitarist.github.io.evil.test/ro-v3-disposable-pages",
    "https://minitheguitarist.github.io@evil.test/ro-v3-disposable-pages",
    "https://user:password@minitheguitarist.github.io/ro-v3-disposable-pages",
    "https://minitheguitarist.github.io:443/ro-v3-disposable-pages",
    "https://minitheguitarist.github.io:8443/ro-v3-disposable-pages",
    "https://minitheguitarist.github.io:invalid/ro-v3-disposable-pages",
    "https://minitheguitarist.github.io./ro-v3-disposable-pages",
    "https://MINITHEGUITARIST.github.io/ro-v3-disposable-pages",
    "https://minitheguitarist.github.io/ro-v3-disposable-other",
    "https://minitheguitarist.github.io/Ro-v3-disposable-pages",
    "https://minitheguitarist.github.io/other/../ro-v3-disposable-pages",
    "https://minitheguitarist.github.io//ro-v3-disposable-pages",
    "https://minitheguitarist.github.io/%72o-v3-disposable-pages",
    "https://repo.ro-asd.org",
    "https://repo.ro-asd.org/ro-v3-disposable-pages",
    "https://minitheguitarist.github.io",
    BASE + "-other", BASE + "/nested", BASE + "/./", BASE + "/..",
    BASE + "/../other", BASE + "/%2e%2e/other", BASE + "/%2E%2E/other",
    BASE + "%2f..%2fother", BASE + "%252f..%252fother",
    BASE + "/%5c..%5cother", BASE + "\\..\\other", BASE + "//",
    BASE + "?", BASE + "?next=https://evil.test", BASE + "#", BASE + "#other",
    " " + BASE, BASE + " ", "\n" + BASE, BASE + "\n", BASE + "\t", BASE + "\x00",
)


def runner_module():
    spec = importlib.util.spec_from_file_location("disposable_acceptance", pathlib.Path(__file__).with_name(
        "v3-pages-disposable-acceptance.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DisposableURLTests(unittest.TestCase):
    def setUp(self):
        self.root = test_workspace()
        self.addCleanup(shutil.rmtree, self.root)
        self.project = DisposablePagesProject(self.root, REPOSITORY, True)

    def test_scope_requires_exact_repository_explicit_authorization_and_test_root(self):
        for repo in ("Project-Ro-ASD/Ro-Repo", "other/ro-v3-disposable-pages",
                     "minitheguitarist/ro-v3-disposable-other", REPOSITORY + "/", REPOSITORY.upper()):
            with self.subTest(repo=repo), self.assertRaises(PlanningError):
                DisposablePagesProject(self.root, repo, True)
        for authorized in (False, None, 1, "true"):
            with self.subTest(authorized=authorized), self.assertRaises(PlanningError):
                DisposablePagesProject(self.root, REPOSITORY, authorized)
        with tempfile.TemporaryDirectory() as root, self.assertRaises(PlanningError):
            DisposablePagesProject(root, REPOSITORY, True)

    def test_exact_project_and_one_trailing_slash_generate_same_urls(self):
        for origin in (BASE, BASE + "/"):
            for arch in ARCHES:
                with self.subTest(origin=origin, arch=arch):
                    expected = BASE + "/v3/views/" + DIGEST + "/rpm/" + arch
                    self.assertEqual(immutable_url(origin, DIGEST, arch, disposable_project=self.project), expected)
            reader = HTTPSReader(origin, DIGEST, "attempt-1", disposable_project=self.project)
            self.assertEqual(reader.base, BASE + "/v3/views/" + DIGEST + "/")
            self.assertEqual(reader.publication_url, BASE + "/v3/publications/attempt-1.json")
            self.assertEqual(reader.advertisement_url, BASE + "/v3/stable.json")

    def test_project_paths_remain_blocked_without_scope(self):
        for origin in (BASE, BASE + "/", "https://repo.ro-asd.org/project"):
            with self.subTest(origin=origin):
                with self.assertRaises(PlanningError):
                    immutable_url(origin, DIGEST, "x86_64")
                with self.assertRaises(PlanningError):
                    HTTPSReader(origin, DIGEST, "attempt-1")
        for scope in (True, {}, REPOSITORY):
            with self.subTest(scope=scope), self.assertRaises(PlanningError):
                immutable_url(BASE, DIGEST, "x86_64", disposable_project=scope)

    def test_host_repo_traversal_query_fragment_and_normalization_attacks_are_rejected(self):
        with patch("urllib.request.build_opener") as opener:
            for origin in BAD_URLS:
                with self.subTest(origin=origin):
                    with self.assertRaises(PlanningError):
                        immutable_url(origin, DIGEST, "x86_64", disposable_project=self.project)
                    with self.assertRaises(PlanningError):
                        HTTPSReader(origin, DIGEST, "attempt-1", disposable_project=self.project)
            opener.assert_not_called()

    def test_scope_rechecks_test_only_marker(self):
        (self.root / ".test-only").write_text("publishable=true\n")
        with self.assertRaises(PlanningError):
            immutable_url(BASE, DIGEST, "source", disposable_project=self.project)
        with self.assertRaises(PlanningError):
            HTTPSReader(BASE, DIGEST, "attempt-1", disposable_project=self.project)

    def test_identity_validation_and_production_activation_guard_remain(self):
        for result, arch in (("b" * 63, "x86_64"), ("A" * 64, "x86_64"),
                             (DIGEST, "../source"), (DIGEST, "noarch")):
            with self.subTest(result=result, arch=arch), self.assertRaises(PlanningError):
                immutable_url(BASE, result, arch, disposable_project=self.project)
        for attempt in ("../escape", "//evil.test", "attempt?x", "attempt#x"):
            with self.subTest(attempt=attempt), self.assertRaises(PlanningError):
                HTTPSReader(BASE, DIGEST, attempt, disposable_project=self.project)
        with self.assertRaises(PlanningError):
            production_publish(disposable_project=self.project, publishable=True)

    def test_root_origin_outputs_are_unchanged(self):
        for origin in ("https://repo.ro-asd.org", "https://repo.ro-asd.org/", "https://repo.ro-asd.org:443"):
            for arch in ARCHES:
                self.assertEqual(immutable_url(origin, DIGEST, arch),
                                 origin.rstrip("/") + "/v3/views/" + DIGEST + "/rpm/" + arch)
            reader = HTTPSReader(origin, DIGEST, "attempt-1")
            self.assertEqual(reader.base, origin.rstrip("/") + "/v3/views/" + DIGEST + "/")
            self.assertEqual(reader.publication_url, origin.rstrip("/") + "/v3/publications/attempt-1.json")
            self.assertEqual(reader.advertisement_url, origin.rstrip("/") + "/v3/stable.json")

    def test_reader_keeps_member_escaping_redirect_and_size_guards(self):
        reader = HTTPSReader(BASE, DIGEST, "attempt-1", disposable_project=self.project, max_bytes=4)
        with patch("urllib.request.build_opener") as build:
            for path in ("../outside", "rpm/../../outside", "/outside", "//evil.test/file", "rpm\\..\\outside"):
                with self.subTest(path=path), self.assertRaises(PlanningError):
                    reader.read(path)
            build.assert_not_called()
            build.return_value.open.return_value.__enter__.return_value.read.return_value = b"small"
            with self.assertRaises(PlanningError):
                reader.read("file")
            handler = build.call_args.args[0]
            with self.assertRaises(PlanningError):
                handler.redirect_request(None, None, 302, "Found", {}, "https://evil.test")
            build.return_value.open.return_value.__enter__.return_value.read.return_value = b"ok"
            reader.read("%2e%2e/file?next=https://evil.test#fragment")
            request = build.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, reader.base + "%252e%252e/file%3Fnext%3Dhttps%3A//evil.test%23fragment")
            self.assertIsNone(request.get_header("Authorization"))

    def test_runner_rejects_invalid_url_or_repository_before_provider_access(self):
        runner = runner_module()
        fake_keys = SimpleNamespace(close=Mock())
        fake_fixture = SimpleNamespace(root=self.root, close=Mock())
        for repo, origin in [(REPOSITORY, url) for url in BAD_URLS] + [("Project-Ro-ASD/Ro-Repo", BASE)]:
            argv = ["acceptance", "--operator-authorized", "--repository", repo, "--repository-id", "123",
                    "--node-id", "R_test", "--origin", origin, "--output", str(self.root / "cloud.json")]
            with self.subTest(repo=repo, origin=origin), patch.object(sys, "argv", argv), \
                    patch.dict("os.environ", {"RO_V3_DISPOSABLE_APP_TOKEN": "test-only",
                                              "RO_V3_DISPOSABLE_APP_TOKEN_EXPIRY": str(int(time.time()) + 300)}), \
                    patch.object(runner, "Keys", return_value=fake_keys), \
                    patch.object(runner, "Fixture", return_value=fake_fixture), \
                    patch.object(runner, "ProviderTransport") as transport, \
                    patch.object(runner.GitHubStorage, "disposable_acceptance") as storage, \
                    patch.object(runner.IsolatedStore, "stage") as stage:
                with self.assertRaises(PlanningError):
                    runner.main()
                transport.assert_not_called()
                storage.assert_not_called()
                stage.assert_not_called()
                self.assertFalse((self.root / "cloud.json").exists())


class DisposableStagingURLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Keys()

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    def setUp(self):
        with tempfile.TemporaryDirectory() as source:
            for arch in ARCHES:
                path = pathlib.Path(source) / "rpm" / arch / "repodata" / "repomd.xml"
                path.parent.mkdir(parents=True)
                path.write_bytes(b"SYNTHETIC metadata: " + arch.encode())
            self.fx = Fixture(self.keys, result_source=source)
        self.addCleanup(self.fx.close)
        self.project = DisposablePagesProject(self.fx.root, REPOSITORY, True)
        self.store = IsolatedStore(self.fx.root)
        self.signer = self.keys.signers["publication"]

    def stage(self, origin=BASE, **kwargs):
        return self.store.stage(self.fx.result, self.fx.approval, self.signer, origin=origin,
            audit_key_sha256=self.keys.signers["audit"].key_sha256, now=NOW, **kwargs)

    def test_invalid_or_unscoped_urls_never_sign_or_stage(self):
        with patch.object(self.signer, "envelope") as sign:
            with self.assertRaises(PlanningError):
                self.stage()
            for origin in BAD_URLS:
                with self.subTest(origin=origin), self.assertRaises(PlanningError):
                    self.stage(origin, disposable_project=self.project)
            wrong_root = DisposablePagesProject(self.keys.root, REPOSITORY, True)
            with self.assertRaises(PlanningError):
                self.stage(disposable_project=wrong_root)
            sign.assert_not_called()
            self.assertEqual(list(self.store.views.iterdir()), [])

    def assert_public_reads(self, view, reader, build):
        objects = {reader.base + item["path"]: (view.path / "payload" / item["path"]).read_bytes()
                   for item in view.result.inventory}
        objects[reader.publication_url] = view.envelope
        objects[reader.advertisement_url] = b"test-only advertisement"
        def open_request(request, *, timeout):
            self.assertEqual(timeout, 30)
            self.assertIsNone(request.get_header("Authorization"))
            response = Mock()
            response.read.return_value = objects[request.full_url]
            context = Mock()
            context.__enter__ = Mock(return_value=response)
            context.__exit__ = Mock(return_value=False)
            return context
        build.return_value.open.side_effect = open_request
        self.assertEqual(reader.publication(), view.envelope)
        for item in view.result.inventory:
            self.assertEqual(reader.read(item["path"]), objects[reader.base + item["path"]])
        self.assertEqual(reader.advertisement(), b"test-only advertisement")

    def test_signed_baseurls_and_all_reader_addresses_agree(self):
        view = self.stage(BASE + "/", disposable_project=self.project)
        reader = HTTPSReader(BASE, view.sha256, self.fx.attempt, disposable_project=self.project)
        for arch in ARCHES:
            self.assertEqual(view.descriptor["baseurls"][arch], reader.base + "rpm/" + arch)
        self.assertIs(view.descriptor["publishable"], False)
        self.assertEqual(view.descriptor["scope"], "v3-immutable-publication-test-only")
        with patch("urllib.request.build_opener") as build:
            self.assert_public_reads(view, reader, build)

    def test_reopen_requires_same_scope_and_exact_signed_project_urls(self):
        from ro_repo import ContractError, validate_schema
        view = self.stage(disposable_project=self.project)
        with self.assertRaises(ContractError):
            validate_schema(view.descriptor, "immutable-publication-v3")
        with self.assertRaises(PlanningError):
            self.store.reopen(self.fx.result, self.fx.approval, self.signer, now=NOW)
        reopened = self.store.reopen(self.fx.result, self.fx.approval, self.signer, now=NOW,
                                     disposable_project=self.project)
        self.assertEqual(reopened.envelope, view.envelope)
        for url in (view.descriptor["baseurls"]["x86_64"] + "?", "https://repo.ro-asd.org/v3/views/" + view.sha256 + "/rpm/x86_64"):
            descriptor = {**view.descriptor, "baseurls": {**view.descriptor["baseurls"], "x86_64": url}}
            (view.path / "publication.json").write_bytes(self.signer.envelope("publication", descriptor))
            with self.subTest(url=url), self.assertRaises(PlanningError):
                self.store.reopen(self.fx.result, self.fx.approval, self.signer, now=NOW,
                                  disposable_project=self.project)

    def test_production_root_staging_descriptor_is_unchanged(self):
        view = self.stage("https://repo.ro-asd.org")
        for arch in ARCHES:
            self.assertEqual(view.descriptor["baseurls"][arch],
                             "https://repo.ro-asd.org/v3/views/" + view.sha256 + "/rpm/" + arch)
        self.assertIs(view.descriptor["publishable"], False)

    def test_cloud_runner_shares_scope_between_real_stage_and_reader_with_mocked_provider(self):
        runner = runner_module()
        storage, transport, identity = Mock(), Mock(), Mock()
        storage.base = "/repos/" + REPOSITORY
        commit = "b" * 40
        storage.head.return_value = "c" * 40
        storage.files.return_value = {".nojekyll": "d" * 40}
        captured = []
        def stage(view, *args, **kwargs):
            captured.append(view)
            return {"git_commit": commit}
        storage.stage.side_effect = stage
        transport.request.side_effect = [
            [{"commit": commit, "status": "built", "url": "https://api.github.com/builds/1"}],
            [{"sha": commit, "id": 2}], {"workflow_runs": [{"head_sha": commit, "conclusion": "success", "id": 3}]}]
        identity.identify.return_value = {"production_activation": "BLOCKED"}
        output = self.fx.root / "cloud.json"
        argv = ["acceptance", "--operator-authorized", "--repository", REPOSITORY, "--repository-id", "123",
                "--node-id", "R_test", "--origin", BASE + "/", "--output", str(output)]
        fake_keys = SimpleNamespace(signers=self.keys.signers, root=self.keys.root, close=Mock())
        with patch.object(sys, "argv", argv), \
                patch.dict("os.environ", {"RO_V3_DISPOSABLE_APP_TOKEN": "test-only",
                                          "RO_V3_DISPOSABLE_APP_TOKEN_EXPIRY": str(NOW + 300)}), \
                patch.object(runner.time, "time", return_value=NOW), \
                patch.object(runner, "Keys", return_value=fake_keys), \
                patch.object(runner, "Fixture", return_value=self.fx), patch.object(self.fx, "close"), \
                patch.object(runner, "fresh_authority", return_value=(self.fx.evidence, self.fx.result, self.fx.approval)), \
                patch.object(runner, "ProviderTransport", return_value=transport), \
                patch.object(runner.GitHubStorage, "disposable_acceptance", return_value=storage), \
                patch.object(runner, "BranchPagesIdentity", return_value=identity), \
                patch("urllib.request.build_opener") as build:
            def open_request(request, *, timeout):
                view = captured[0]
                expected = BASE + "/v3/publications/" + self.fx.attempt + ".json"
                if request.full_url == expected:
                    raw = view.envelope
                else:
                    prefix = BASE + "/v3/views/" + view.sha256 + "/"
                    self.assertTrue(request.full_url.startswith(prefix))
                    raw = (view.path / "payload" / request.full_url.removeprefix(prefix)).read_bytes()
                context = Mock()
                context.__enter__ = Mock(return_value=Mock(read=Mock(return_value=raw)))
                context.__exit__ = Mock(return_value=False)
                return context
            build.return_value.open.side_effect = open_request
            runner.main()
        import json
        receipt = json.loads(output.read_bytes())
        self.assertEqual(receipt["synthetic_public_bytes"], "PASS")
        self.assertIs(receipt["publishable"], False)
        self.assertEqual(receipt["production_activation"], "BLOCKED")
        self.assertEqual(receipt["late_build_ordering"], "UNVERIFIED")
        self.assertEqual(receipt["provider_deadline_fencing"], "UNVERIFIED")
        self.assertEqual(len(captured), 1)
        for arch in ARCHES:
            self.assertEqual(captured[0].descriptor["baseurls"][arch],
                             BASE + "/v3/views/" + captured[0].sha256 + "/rpm/" + arch)


if __name__ == "__main__":
    unittest.main()
