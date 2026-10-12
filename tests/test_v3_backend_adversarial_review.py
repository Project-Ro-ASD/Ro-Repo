"""PR72 negatives: real signatures/Git, injected clocks and race boundaries.

Synthetic package fixtures are not application or production acceptance.
"""
import pathlib
import multiprocessing
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_backend_support import Keys, Fixture, NOW
from v3_backend_trust import verify_envelope, strict_json
from v3_backend_evidence import verify_protected
from v3_immutable_view import IsolatedStore, verify_remote
from v3_pages_backend import IsolatedGitStore, GitReader
from v3_promotion_planner import PlanningError
from v3_publication_backend import STATES
from test_v3_promotion_planner import snapshot, assist


class AdversarialBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Keys()

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    def setUp(self):
        self.fx = Fixture(self.keys)
        self.addCleanup(self.fx.close)

    def view(self):
        self.fx.advance("AUTHORIZED")
        self.fx.view = IsolatedStore(self.fx.root).stage(
            self.fx.result, self.fx.approval, self.keys.signers["publication"],
            origin="https://test.invalid", audit_key_sha256=self.keys.signers["audit"].key_sha256, now=NOW)
        return self.fx.view

    def git_view(self):
        view = self.view()
        store = IsolatedGitStore(self.fx.root)
        staged = store.stage(view, expected=None)
        deployment = self.keys.attestation("deployment", {
            "result_stable_sha256": view.sha256, "publication_sha256": view.envelope_sha256,
            "git_commit": staged["git_commit"], "deployment_id": "test-only"})
        return store, staged, deployment

    def test_stale_pre_verification_cannot_publish(self):
        self.fx.advance("AUTHORIZED")
        self.fx.stage()
        before = self.fx.ledger.inspect()
        self.fx.now = NOW + 61  # Approval remains valid for another 239 seconds.
        with self.assertRaises(PlanningError):
            self.fx.backend.publish(self.fx.attempt, self.fx.approval)
        self.fx.now = NOW
        self.assertEqual(before, self.fx.ledger.inspect())

    def test_json_and_wrong_seal_cannot_construct_capabilities(self):
        from v3_backend_trust import Workload, Attestation, require_attestation
        from v3_backend_evidence import Evidence, Authorization
        forged = {"role": "tests", "result": "PASS", "approved": True}
        for constructor, args in ((Workload, ({"exp": NOW + 300}, "a" * 64)),
                                  (Attestation, ("tests", forged, "a" * 64)),
                                  (Evidence, (forged, NOW + 300)),
                                  (Authorization, (forged, NOW + 300))):
            with self.subTest(capability=constructor.__name__), self.assertRaises(PlanningError):
                constructor(*args, object())
        with self.assertRaises(PlanningError):
            require_attestation(forged, "tests")

    def test_numeric_overflow_cannot_enter_strict_json(self):
        for raw in (b'{"x":1e999}', b'{"x":-1e999}'):
            with self.subTest(raw=raw), self.assertRaises(PlanningError):
                strict_json(raw)

    def test_reopen_requires_exact_authorized_request_and_preflight(self):
        view = self.view()
        signer = self.keys.signers["publication"]
        original = strict_json(view.envelope)["payload"]
        import copy
        for field in ("attempt", "preflight", "result"):
            descriptor = copy.deepcopy(original)
            if field == "attempt":
                descriptor["request"]["attempt_id"] = "another-attempt"
            elif field == "preflight":
                descriptor["preflight_sha256"] = "0" * 64
            else:
                descriptor["result_stable_sha256"] = "0" * 64
            # A real publication-role signature does not replace human binding.
            (view.path / "publication.json").write_bytes(signer.envelope("publication", descriptor))
            with self.subTest(field=field), self.assertRaises(PlanningError):
                IsolatedStore(self.fx.root).reopen(self.fx.result, self.fx.approval, signer, now=NOW)

    def test_reopen_cannot_import_a_publishable_descriptor(self):
        view = self.view()
        signer = self.keys.signers["publication"]
        descriptor = strict_json(view.envelope)["payload"]
        descriptor["publishable"] = True
        (view.path / "publication.json").write_bytes(signer.envelope("publication", descriptor))
        with self.assertRaises(PlanningError):
            IsolatedStore(self.fx.root).reopen(self.fx.result, self.fx.approval, signer, now=NOW)

    def test_primary_xml_base_override_is_rejected_even_when_href_matches(self):
        from v3_pinned_upstream import primary_inventory
        package = {"path": "probe.rpm", "nevra": "probe-0:1-1.x86_64", "sha256": "a" * 64}
        for attribute, root_attribute in ((" xml:base=\"https://outside.invalid/\"", ""),
                                          ("", " xml:base=\"file:///outside/\"")):
            xml = ('<metadata xmlns="http://linux.duke.edu/metadata/common"' + root_attribute + '><package><name>probe</name>'
                   '<arch>x86_64</arch><version epoch="0" ver="1" rel="1"/><checksum type="sha256">' + "a" * 64 +
                   '</checksum><location href="probe.rpm"' + attribute + '/></package></metadata>')
            (self.fx.root / "primary.xml").write_text(xml)
            with self.subTest(xml_base=attribute or root_attribute), self.assertRaises(PlanningError):
                primary_inventory(self.fx.root, "primary.xml", [package])

    def test_repomd_xml_base_and_url_members_are_rejected(self):
        from v3_pinned_upstream import repomd_members, member
        from v3_backend_trust import digest
        (self.fx.root / "repodata").mkdir()
        raw = b'<repomd xmlns="http://linux.duke.edu/metadata/repo" xml:base="https://outside.invalid/"/>'
        (self.fx.root / "repodata/repomd.xml").write_bytes(raw)
        with self.assertRaises(PlanningError):
            repomd_members(self.fx.root, digest(raw))
        for name in ("file:external", "encoded%20metadata", "metadata?query", "metadata#fragment", "bad\nname"):
            (self.fx.root / name).write_bytes(b"exists inside cache")
            with self.subTest(name=name), self.assertRaises(PlanningError):
                member(self.fx.root, name)

    def test_expired_authorization_cannot_advance_staging(self):
        view = self.view()
        self.fx.backend.signed(self.fx.attempt, view)
        before = self.fx.ledger.inspect()
        self.fx.now = NOW + 300
        with self.assertRaises(PlanningError):
            self.fx.backend.staged(self.fx.attempt, view)
        self.fx.now = NOW
        self.assertEqual(before, self.fx.ledger.inspect())

    def test_expiry_during_audit_signing_rolls_back_consumption(self):
        self.fx.advance()
        before = self.fx.ledger.inspect()
        sign = self.fx.ledger.signer.sign
        def slow_sign(data):
            raw = sign(data)
            self.fx.now = NOW + 300
            return raw
        with mock.patch.object(self.fx.ledger.signer, "sign", side_effect=slow_sign):
            with self.assertRaises(PlanningError):
                self.fx.backend.authorized(self.fx.attempt, self.fx.approval)
        self.fx.now = NOW
        self.assertEqual(before, self.fx.ledger.inspect())

    def test_noop_staging_retry_still_performs_ref_cas(self):
        store, staged, _ = self.git_view()
        concurrent = IsolatedGitStore(self.fx.root)
        build_tree = store._tree
        winner = []
        def racing_tree(files):
            tree = build_tree(files)
            winner.append(concurrent._cas({"v3/concurrent-record.json": b"independent writer"}, staged["git_commit"]))
            return tree
        with mock.patch.object(store, "_tree", side_effect=racing_tree):
            with self.assertRaises(PlanningError):
                store.stage(self.fx.view, expected=staged["git_commit"])
        self.assertEqual(store.head(), winner[0])

    def test_advertisement_signer_failure_cannot_move_ref(self):
        store, staged, deployment = self.git_view()
        remote = verify_remote(self.fx.view, GitReader(store, self.fx.view), deployment, now=NOW)
        signer = self.keys.signers["publication"]
        with mock.patch.object(signer, "sign", side_effect=self.keys.signers["approval"].sign):
            with self.assertRaises(PlanningError):
                store.advertise(self.fx.view, self.fx.approval, remote, signer,
                                expected=staged["git_commit"], previous_digest=None, now=NOW)
        self.assertEqual(store.head(), staged["git_commit"])

    def test_deployment_commit_must_match_git_reader(self):
        store, _, _ = self.git_view()
        wrong = self.keys.attestation("deployment", {
            "result_stable_sha256": self.fx.view.sha256, "publication_sha256": self.fx.view.envelope_sha256,
            "git_commit": "a" * 40, "deployment_id": "another-deployment"})
        with self.assertRaises(PlanningError):
            verify_remote(self.fx.view, GitReader(store, self.fx.view), wrong, now=NOW)

    def test_ref_change_during_remote_read_is_rejected(self):
        store, staged, deployment = self.git_view()
        reader = GitReader(store, self.fx.view)
        original = reader.read
        def racing_read(path):
            raw = original(path)
            store._cas({"v3/concurrent-record.json": b"new deployment"}, staged["git_commit"])
            return raw
        with mock.patch.object(reader, "read", side_effect=racing_read):
            with self.assertRaises(PlanningError):
                verify_remote(self.fx.view, reader, deployment, now=NOW)

    def test_audit_key_cannot_also_authorize_human_approval(self):
        self.fx.advance()
        args = dict(self.fx.approval_args)
        signer = self.keys.signers["audit"]
        payload = strict_json(args["approval_raw"])["payload"]
        args.update(approval_key=signer.public, approval_key_sha256=signer.key_sha256,
                    approval_raw=signer.envelope("human-approval", payload))
        approval = verify_envelope(args["approval_raw"], role="human-approval", public_key=signer.public,
                    key_sha256=signer.key_sha256, expected={k: v for k, v in payload.items() if k not in {"issued_at", "expires_at"}}, now=NOW)
        witness = strict_json(args["witness_raw"])["payload"]
        witness["approval_sha256"] = approval.sha256
        args["witness_raw"] = self.keys.signers["witness"].envelope("protected-environment-witness", witness)
        authority = verify_protected(self.fx.proposal, self.fx.attempt, self.fx.evidence, self.fx.workload, **args)
        before = self.fx.ledger.inspect()
        with self.assertRaises(PlanningError):
            self.fx.backend.authorized(self.fx.attempt, authority)
        self.assertEqual(before, self.fx.ledger.inspect())

    def test_two_independent_git_writers_have_one_cas_winner(self):
        store, staged, _ = self.git_view()
        context = multiprocessing.get_context("fork")
        barrier, queue = context.Barrier(2), context.Queue()
        def writer(number):
            other = IsolatedGitStore(self.fx.root)
            build = other._tree
            def ready(files):
                tree = build(files)
                barrier.wait(timeout=20)
                return tree
            other._tree = ready
            try:
                other._cas({"v3/writer-" + str(number): b"independent"}, staged["git_commit"])
                queue.put("won")
            except PlanningError:
                queue.put("conflict")
        processes = [context.Process(target=writer, args=(n,)) for n in (1, 2)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(30)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sorted(queue.get(timeout=5) for _ in processes), ["conflict", "won"])

    def test_provider_interruption_keeps_intent_separate_from_git_and_post(self):
        store, staged, deployment = self.git_view()
        view = self.fx.view
        self.fx.backend.signed(self.fx.attempt, view)
        self.fx.backend.staged(self.fx.attempt, view)
        # Crash after Git staging, before DB remote proof: exact staging retry.
        self.assertEqual(self.fx.ledger.inspect(self.fx.attempt)["attempt"]["state"], "STAGED")
        self.assertIsNone(self.fx.ledger.inspect()["head"]["digest"])
        self.assertEqual(store.stage(view, expected=staged["git_commit"]), staged)
        remote = verify_remote(view, GitReader(store, view), deployment, now=NOW)
        self.fx.backend.remotely_verified(self.fx.attempt, remote)
        self.assertIsNone(self.fx.ledger.inspect()["head"]["digest"])
        self.fx.backend.publish(self.fx.attempt, self.fx.approval)
        # Crash after DB intent, before Git advertisement: never POST_VERIFIED.
        self.assertEqual(store.head(), staged["git_commit"])
        self.assertIsNone(self.fx.ledger.inspect()["head"]["last_verified"])
        signer = self.keys.signers["publication"]
        with self.assertRaises(PlanningError):
            verify_remote(view, GitReader(store, view), deployment, now=NOW, post_ledger=self.fx.ledger,
                          advertisement_key=signer.public, advertisement_key_sha256=signer.key_sha256)
        advertise = store.advertise
        def crash_after_advertise(*args, **kwargs):
            advertise(*args, **kwargs)
            raise RuntimeError("external Git committed; caller lost response")
        with mock.patch.object(store, "advertise", side_effect=crash_after_advertise):
            with self.assertRaises(RuntimeError):
                store.advertise(view, self.fx.approval, remote, signer, expected=staged["git_commit"], previous_digest=None, now=NOW)
        self.assertEqual(self.fx.ledger.inspect(self.fx.attempt)["attempt"]["state"], "PUBLISHED")
        self.assertIsNone(self.fx.ledger.inspect()["head"]["last_verified"])
        # Blind stale-ref retry is rejected; reconcile actual signed bytes.
        with self.assertRaises(PlanningError):
            advertise(view, self.fx.approval, remote, signer, expected=staged["git_commit"], previous_digest=None, now=NOW)
        post_deployment = self.keys.attestation("deployment", {
            "result_stable_sha256": view.sha256, "publication_sha256": view.envelope_sha256,
            "git_commit": store.head(), "deployment_id": "reconciled-test-only"})
        post = verify_remote(view, GitReader(store, view), post_deployment, now=NOW, post_ledger=self.fx.ledger,
                             advertisement_key=signer.public, advertisement_key_sha256=signer.key_sha256)
        before = self.fx.ledger.inspect()
        # Crash after reading post bytes, before recording post proof.
        self.assertIsNone(before["head"]["last_verified"])
        self.fx.backend.post_verified(self.fx.attempt, post)
        self.assertEqual(self.fx.ledger.inspect(self.fx.attempt)["attempt"]["state"], "POST_VERIFIED")

    def test_recovery_interruptions_at_every_ledger_transition(self):
        self.fx.complete()
        newer = Fixture(self.keys, attempt="newer", version="0.2.6",
                        previous=snapshot("repo-f44-20261011-099", assist()), previous_digest=self.fx.result.sha256)
        self.addCleanup(newer.close)
        newer.backend, newer.ledger = self.fx.backend, self.fx.ledger
        newer.complete()
        recovery = Fixture(self.keys, attempt="recovery", result_source=self.fx.source,
                           # Reuse the historical package plan; recovery's
                           # current base is independently bound by the ledger.
                           previous=snapshot("repo-f44-20261011-099", assist()),
                           previous_digest=newer.result.sha256, operation="recover")
        self.addCleanup(recovery.close)
        recovery.backend, recovery.ledger = self.fx.backend, self.fx.ledger
        view = IsolatedStore(recovery.root).stage(recovery.result, recovery.approval, self.keys.signers["publication"],
                    origin="https://test.invalid", audit_key_sha256=self.keys.signers["audit"].key_sha256, now=NOW)
        deployment = self.keys.attestation("deployment", {
            "result_stable_sha256": view.sha256, "publication_sha256": view.envelope_sha256,
            "git_commit": "a" * 40, "deployment_id": "recovery-test"})
        from v3_immutable_view import DirectoryReader
        remote = verify_remote(view, DirectoryReader(view), deployment, now=NOW)
        recovery.view, recovery.deployment = view, deployment
        calls = [lambda: recovery.backend.create(recovery.proposal, recovery.plan, recovery.registry, recovery.attempt, operation="recover"),
                 lambda: recovery.backend.verified(recovery.attempt, recovery.evidence),
                 lambda: recovery.backend.composed(recovery.attempt, recovery.result),
                 lambda: recovery.backend.tested(recovery.attempt, recovery.evidence),
                 lambda: recovery.backend.awaiting_approval(recovery.attempt),
                 lambda: recovery.backend.authorized(recovery.attempt, recovery.approval),
                 lambda: recovery.backend.signed(recovery.attempt, view),
                 lambda: recovery.backend.staged(recovery.attempt, view),
                 lambda: recovery.backend.remotely_verified(recovery.attempt, remote),
                 lambda: recovery.backend.publish(recovery.attempt, recovery.approval),
                 lambda: recovery.backend.post_verified(recovery.attempt, recovery.verify_post())]
        execute = recovery.ledger.execute
        for state, call in zip(STATES, calls):
            before = recovery.ledger.inspect()
            def crash(point):
                if point == "after-audit":
                    raise RuntimeError("interrupted recovery " + state)
            def interrupted(*args, **kwargs):
                kwargs["inject"] = crash
                return execute(*args, **kwargs)
            with mock.patch.object(recovery.ledger, "execute", side_effect=interrupted):
                with self.assertRaises(RuntimeError):
                    call()
            self.assertEqual(before, recovery.ledger.inspect())
            call()
            self.assertEqual(recovery.ledger.inspect(recovery.attempt)["attempt"]["state"], state)
        self.assertEqual(recovery.result.sha256, self.fx.result.sha256)
        self.fx.result.check()


if __name__ == "__main__":
    unittest.main()
