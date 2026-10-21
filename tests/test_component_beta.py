"""Offline transport, correlation, writer-race and compatibility regressions."""
import copy
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'scripts')]
import component_beta as cb
from component_beta_storage_guard import check_storage

SHA = 'a' * 40
PARENT = 'repo-f44-20261009-001'
SNAPSHOT = 'repo-f44-20261022-001'
IDENTITY = dict(component='ro-theme', repository='Project-Ro-ASD/Ro-Theme', tag='v1.1.10',
                commit='b' * 40, release_id='12')
MANIFEST = dict(component='ro-theme', source_repository=IDENTITY['repository'],
                release_tag=IDENTITY['tag'], source_commit=IDENTITY['commit'], release_id=12)


def run(workflow=cb.STAGES[0], run_id=10, **changes):
    result = dict(id=run_id, path=f'.github/workflows/{workflow}.yml', event='workflow_dispatch',
                  head_branch='main', head_sha=SHA, display_title=f'{workflow} [request]',
                  run_attempt=1, repository={'full_name': cb.REPOSITORY},
                  head_repository={'full_name': cb.REPOSITORY}, status='completed', conclusion='success')
    result.update(changes)
    return result


def asset(run_id=10, name='accepted-component-10', **changes):
    result = dict(id=100, name=name, expired=False, digest='sha256:' + 'f' * 64,
                  workflow_run={'id': run_id, 'head_sha': SHA})
    result.update(changes)
    return result


class Clock:
    def __init__(self): self.now = 0
    def __call__(self): return self.now
    def sleep(self, seconds): self.now += seconds


class FakeAPI:
    """Stateful fake: POST records dispatch; only correlated GETs complete it."""
    def __init__(self):
        self.dispatched = []
        self.cancelled = []
        self.current = None
        self.conclusion = 'success'
        self.waiting = False
        self.duplicate = False
        self.discovery_missing = False
        self.head = 'c' * 40
        self.commit_parent = 'c' * 40
        self.verify = 'success'
        self.bad_artifact = False

    def call(self, path, body=None):
        if path.endswith('/dispatches'):
            self.current = path.split('/')[-2].removesuffix('.yml')
            self.dispatched.append((self.current, body))
            if self.current == cb.STAGES[2]: self.head = 'e'*40
            return None
        if path.endswith('/cancel'):
            self.cancelled.append(path)
            return None
        if path.endswith('/heads/main'): return {'object': {'sha': SHA}}
        if path.endswith('/heads/pages-storage'): return {'object': {'sha': self.head}}
        if '/git/commits/' in path:
            return {'parents': [{'sha': self.commit_parent}], 'message': f'publish: {SNAPSHOT} from candidate run 11'}
        if '/actions/runs/' in path:
            rid = int(path.rsplit('/', 1)[1])
            return run(cb.STAGES[rid-10], rid, conclusion=self.conclusion,
                       status='waiting' if self.waiting else 'completed')
        raise AssertionError(path)

    def all(self, path, key):
        rid = 9 + len(self.dispatched)
        if key == 'workflow_runs':
            if self.discovery_missing: return []
            return [run(self.current, rid)] * (2 if self.duplicate else 1)
        if key == 'jobs': return [{'name': 'verify-remote-beta', 'conclusion': self.verify}]
        if key == 'artifacts':
            names = ['accepted-component-10', 'signed-component-10'] if rid == 10 else [
                f'candidate-snapshot-{SNAPSHOT}-11'] if rid == 11 else [f'signed-beta-publication-{SNAPSHOT}-13']
            return [asset(rid, name, id=i+100, expired=self.bad_artifact) for i, name in enumerate(names)]
        raise AssertionError(path)


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = Clock()
        self.api = FakeAPI()
        self.state = dict(IDENTITY, source_sha=SHA, request_id='request', started_at='2026-10-22T00:00:00Z',
                          runs={}, completed_stages=[], storage_sha='c'*40, parent_snapshot=PARENT,
                          parent_manifest_sha256='d'*64, snapshot_id=SNAPSHOT)
        self.o = cb.Orchestrator(self.api, self.state, pathlib.Path(self.temp.name)/'state.json',
                                 self.clock, self.clock.sleep)
        self.evidence = {'workflow_run': 11, 'source_signing_runs': [10], 'components': [dict(
            signing_run=10, source_repository=IDENTITY['repository'], source_commit=IDENTITY['commit'],
            release_tag=IDENTITY['tag'], release_id=12)], 'inherited_snapshot': {
                'snapshot_id': PARENT, 'repository_snapshot_sha256': 'd'*64}}
        self.manifest = {'snapshot_id': SNAPSHOT, 'parent_snapshot': PARENT}

    def documents(self, api, artifact, suffixes):
        if 'accepted' in artifact['name']:
            return {'component-artifact-manifest-v1.json': copy.deepcopy(MANIFEST)}
        return {'repository-snapshot-v1.json': self.manifest, 'snapshot-build-evidence-v1.json': self.evidence}

    def execute(self):
        with mock.patch.object(cb, 'artifact_documents', side_effect=self.documents), \
             mock.patch.object(cb.rr, 'validate_schema'):
            return self.o.execute()

    def test_all_four_exact_stages_and_remote_verification(self):
        self.execute()
        self.assertEqual([x[0] for x in self.api.dispatched], list(cb.STAGES))
        self.assertEqual(self.state['result'], 'SUCCESS')
        self.assertEqual(self.state['remote_verification'], 'success')
        self.assertEqual(self.api.dispatched[2][1]['inputs']['expected_storage_commit'], 'c'*40)
        self.assertEqual(self.api.dispatched[3][1]['inputs']['expected_storage_commit'], 'e'*40)
        self.assertTrue(all(x[1]['inputs']['request_id'] == 'request' for x in self.api.dispatched))

    def test_signing_failure_cancel_or_reject_never_dispatch_candidate(self):
        for conclusion in ('failure', 'cancelled', 'timed_out', 'action_required', 'skipped', 'neutral'):
            with self.subTest(conclusion=conclusion):
                self.api.dispatched.clear()
                self.state['runs'].clear()
                self.api.conclusion = conclusion
                with self.assertRaises(ValueError): self.execute()
                self.assertEqual(len(self.api.dispatched), 1)

    def test_environment_wait_expires_and_cancellation_targets_exact_run(self):
        self.api.waiting = True
        with self.assertRaisesRegex(ValueError, 'timeout'): self.execute()
        self.assertEqual(len(self.api.dispatched), 1)
        with mock.patch.object(cb, 'API', return_value=self.api): self.o.cancel()
        self.assertTrue(self.api.cancelled[0].endswith('/10/cancel'))

    def test_no_match_and_ambiguous_match_stop(self):
        for key in ('discovery_missing', 'duplicate'):
            with self.subTest(key=key):
                self.api.dispatched.clear()
                self.clock.now = 0
                setattr(self.api, key, True)
                with self.assertRaises(ValueError): self.execute()
                self.assertEqual(len(self.api.dispatched), 1)
                setattr(self.api, key, False)

    def test_stale_parent_snapshot_and_digest_block_pages(self):
        for field in ('snapshot_id', 'repository_snapshot_sha256'):
            original = self.evidence['inherited_snapshot'][field]
            self.evidence['inherited_snapshot'][field] = 'wrong'
            with self.assertRaisesRegex(ValueError, 'parent'): self.execute()
            self.assertEqual(len(self.api.dispatched), 2)
            self.api.dispatched.clear()
            self.evidence['inherited_snapshot'][field] = original

    def test_parent_manifest_mismatch_blocks_pages(self):
        self.manifest['parent_snapshot'] = 'repo-f44-20261010-001'
        with self.assertRaises(ValueError): self.execute()
        self.assertEqual(len(self.api.dispatched), 2)

    def test_intervening_pages_commit_rollback_or_concurrent_writer_blocks_beta(self):
        self.api.commit_parent = 'e' * 40
        with self.assertRaisesRegex(ValueError, 'Pages writer'): self.execute()
        self.assertEqual(len(self.api.dispatched), 3)

    def test_concurrent_request_detects_storage_change_before_dispatch(self):
        self.api.head = 'e'*40
        with self.assertRaisesRegex(ValueError, 'storage changed'): self.execute()
        self.assertEqual(self.api.dispatched, [])

    def test_previous_run_rerun_blocks_next_stage(self):
        self.o.stage(cb.STAGES[0], {})
        original = self.api.call
        def changed(path, body=None):
            result = original(path, body)
            if path.endswith('/actions/runs/10'):
                result['run_attempt'] = 2
            return result
        with mock.patch.object(self.api, 'call', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'attempt'):
                self.o.stage(cb.STAGES[1], {})
        self.assertEqual(len(self.api.dispatched), 1)

    def test_main_movement_blocks_dispatch(self):
        self.state['source_sha'] = 'e'*40
        with self.assertRaisesRegex(ValueError, 'main changed'): self.execute()
        self.assertEqual(self.api.dispatched, [])

    def test_missing_or_bad_signing_artifact_blocks_candidate(self):
        self.api.bad_artifact = True
        with self.assertRaises(ValueError): self.execute()
        self.assertEqual(len(self.api.dispatched), 1)

    def test_remote_job_verification_is_required_for_success(self):
        self.api.verify = 'failure'
        with self.assertRaisesRegex(ValueError, 'independent'): self.execute()
        self.assertNotEqual(self.state.get('result'), 'SUCCESS')

    def test_wrong_incoming_component_blocks_candidate(self):
        with mock.patch.object(cb, 'artifact_documents', return_value={'component-artifact-manifest-v1.json': {}}):
            with self.assertRaisesRegex(ValueError, 'identity'): self.o.execute()
        self.assertEqual(len(self.api.dispatched), 1)


class IdentityAndTransportTests(unittest.TestCase):
    def test_run_wrong_identity_and_attempt_fail_closed(self):
        changes = dict(id=99, path='.github/workflows/wrong.yml', event='push', head_branch='feature',
                       head_sha='b'*40, display_title='wrong', run_attempt=2,
                       repository={'full_name': 'attacker/repo'}, head_repository={'full_name': 'attacker/repo'})
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                cb.validate_run(run(**{key: value}), 10, cb.STAGES[0], 'request', SHA)

    def test_artifact_name_id_run_commit_expiry_digest_and_duplicates(self):
        for change in ({'id': 0}, {'expired': True}, {'digest': None},
                       {'workflow_run': {'id': 11, 'head_sha': SHA}},
                       {'workflow_run': {'id': 10, 'head_sha': 'b'*40}}, {'name': 'wrong'}):
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                cb.select_artifact([asset(**change)], 'accepted-component-10', 10, SHA)
        with self.assertRaises(ValueError): cb.select_artifact([], 'accepted-component-10', 10, SHA)
        with self.assertRaises(ValueError): cb.select_artifact([asset(), asset()], 'accepted-component-10', 10, SHA)

    def test_snapshot_collision_skipped_and_namespace_exhaustion(self):
        self.assertEqual(cb.allocate_snapshot([SNAPSHOT], '20261022'), 'repo-f44-20261022-002')
        with self.assertRaises(ValueError): cb.allocate_snapshot(['repo-f44-20261022-999'], '20261022')

    def test_api_timeout_rate_limit_and_uncertain_dispatch_are_not_retried(self):
        for error in (subprocess.TimeoutExpired('gh', 60), subprocess.CalledProcessError(1, 'gh', stderr=b'rate limit')):
            with mock.patch.object(cb.subprocess, 'run', side_effect=error) as transport:
                with self.assertRaisesRegex(ValueError, 'reconcile'):
                    cb.API(cb.time.monotonic()+60).call('repos/a/b/actions/workflows/x/dispatches', {'ref': 'main'})
                self.assertEqual(transport.call_count, 1)
                self.assertLessEqual(transport.call_args.kwargs['timeout'], 60)

    def test_zip_digest_wrong_and_missing_metadata(self):
        for names, bad_digest in ((['metadata.json'], True), (['wrong.json'], False),
                                  (['metadata.json', 'nested/metadata.json'], False), (['../metadata.json'], False)):
            blob = io.BytesIO()
            with zipfile.ZipFile(blob, 'w') as archive:
                for name in names: archive.writestr(name, '{}')
            data = blob.getvalue()
            a = asset(digest='sha256:' + ('0'*64 if bad_digest else hashlib.sha256(data).hexdigest()))
            api = mock.Mock()
            api.call.side_effect = lambda path, output: output.write(data)
            with self.subTest(names=names), self.assertRaises(ValueError):
                cb.artifact_documents(api, a, ['metadata.json'])

    def test_producer_allowlist_precedes_any_request(self):
        api = mock.Mock()
        registry = cb.rr.load_producer_registry(ROOT/'config/producers-v2.json')
        for component in ('unknown', 'https://github.com/attacker/repo', 'Project-Ro-ASD/Ro-Theme'):
            with self.assertRaisesRegex(ValueError, 'allowlisted'):
                cb.producer_identity(api, registry, component, 'v1.0')
        api.call.assert_not_called()

    def test_release_identity_mutable_draft_unknown_ambiguous_commit(self):
        registry = cb.rr.load_producer_registry(ROOT/'config/producers-v2.json')
        for release in ({'draft': True, 'immutable': True}, {'draft': False, 'immutable': False},
                        {'draft': False}, {'draft': False, 'immutable': True, 'id': 0},
                        {'draft': False, 'immutable': True, 'id': 12, 'tag_name': 'wrong'}):
            with self.subTest(release=release):
                api = mock.Mock(); api.call.return_value = release
                with self.assertRaises(ValueError): cb.producer_identity(api, registry, 'ro-theme', 'v1.1.10')
        release = {'draft': False, 'immutable': True, 'id': 12, 'tag_name': 'v1.1.10',
                   'assets': [{'name': 'component-artifact-manifest-v1.json', 'id': 100}]}
        api = mock.Mock()
        api.call.side_effect = [release, {'object': {'type': 'tag', 'sha': 'c'*40}},
                                {'object': {'type': 'commit', 'sha': 'b'*40}}, {'sha': 'a'*40}]
        with self.assertRaisesRegex(ValueError, 'ambiguous'): cb.producer_identity(api, registry, 'ro-theme', 'v1.1.10')

    def test_exact_release_manifest_commit_and_component_match(self):
        registry = cb.rr.load_producer_registry(ROOT/'config/producers-v2.json')
        release = {'draft': False, 'immutable': True, 'id': 12, 'tag_name': 'v1.1.10',
                   'assets': [{'name': 'component-artifact-manifest-v1.json', 'id': 100}]}
        def asset_download(argv, stdout, **kwargs): stdout.write(json.dumps(MANIFEST).encode())
        for field in (None, 'component', 'source_commit', 'release_id', 'release_tag', 'source_repository'):
            manifest = dict(MANIFEST)
            if field: manifest[field] = 'wrong'
            api = mock.Mock(); api.call.side_effect = [release, {'object': {'type': 'commit', 'sha': 'b'*40}}, {'sha': 'b'*40}]
            with mock.patch.object(cb.subprocess, 'run', side_effect=asset_download), \
                 mock.patch.object(cb.json, 'load', return_value=manifest), mock.patch.object(cb.rr, 'validate_schema'):
                if field:
                    with self.assertRaises(ValueError): cb.producer_identity(api, registry, 'ro-theme', 'v1.1.10')
                else: self.assertEqual(cb.producer_identity(api, registry, 'ro-theme', 'v1.1.10'), IDENTITY)


class WorkflowAndStorageTests(unittest.TestCase):
    def test_manual_inputs_environment_secrets_and_cas_preserved(self):
        original_inputs = [('repository','tag','commit','release_id'), ('signing_runs','snapshot_id','parent_snapshot'),
                           ('candidate_run','snapshot_id'), ('snapshot_id',)]
        for stage, original in zip(cb.STAGES, original_inputs):
            text = (ROOT/f'.github/workflows/{stage}.yml').read_text()
            workflow = yaml.safe_load(text)
            inputs = workflow['on']['workflow_dispatch']['inputs']
            self.assertTrue(set(original) <= inputs.keys())
            self.assertFalse(inputs['request_id']['required'])
            self.assertEqual(inputs['request_id']['default'], '')
            self.assertIn('inputs.request_id', workflow['run-name'])
            self.assertNotIn('workflow_call', workflow['on'])
        for stage in cb.STAGES[2:]:
            text = (ROOT/f'.github/workflows/{stage}.yml').read_text()
            workflow = yaml.safe_load(text)
            self.assertEqual(workflow['concurrency'], {'group': 'ro-repo-pages-storage', 'cancel-in-progress': False})
            self.assertIn('component_beta_storage_guard.py pages-site', text)
            self.assertIn('rev-parse FETCH_HEAD', text)
            self.assertIn('push origin HEAD:pages-storage', text)
        remote = yaml.safe_load((ROOT/'.github/workflows/publish-remote-beta.yml').read_text())
        self.assertEqual(remote['jobs']['sign-beta-publication']['environment']['name'], 'repo-production-signing')
        self.assertEqual(remote['jobs']['publish-beta']['environment']['name'], 'repo-beta')
        new = yaml.safe_load((ROOT/'.github/workflows/publish-component-beta.yml').read_text())
        self.assertEqual(set(new['on']['workflow_dispatch']['inputs']), {'component','tag','preflight_only'})
        self.assertEqual(new['permissions'], {'contents':'read', 'actions':'write'})
        self.assertEqual(new['concurrency']['cancel-in-progress'], False)
        self.assertLessEqual(new['jobs']['orchestrate']['timeout-minutes'], 360)
        self.assertNotIn('secrets.', (ROOT/'.github/workflows/publish-component-beta.yml').read_text())

    def test_source_and_approval_deadline_guards_execute_before_each_job(self):
        for stage in cb.STAGES:
            workflow = yaml.safe_load((ROOT/f'.github/workflows/{stage}.yml').read_text())
            for job in workflow['jobs'].values():
                guard = next(step for step in job['steps'] if step.get('name', '').startswith('Validate orchestrated'))
                env = dict(cb.os.environ, REQUEST_ID='a'*32, EXPECTED_SOURCE=SHA,
                           GITHUB_REPOSITORY=cb.REPOSITORY, GITHUB_REF='refs/heads/main',
                           GITHUB_SHA=SHA, GITHUB_RUN_ATTEMPT='1', REQUEST_DEADLINE=str(int(cb.time.time())+60))
                self.assertEqual(subprocess.run(['bash','-c',guard['run']], env=env).returncode, 0)
                for key, value in {'GITHUB_SHA':'b'*40, 'GITHUB_RUN_ATTEMPT':'2',
                                   'GITHUB_REF':'refs/heads/feature', 'REQUEST_DEADLINE':'1000000000',
                                   'REQUEST_ID':'', 'GITHUB_REPOSITORY':'other/repo'}.items():
                    with self.subTest(stage=stage, key=key):
                        self.assertNotEqual(subprocess.run(['bash','-c',guard['run']],
                                            env=dict(env, **{key:value})).returncode, 0)

    def test_writer_guard_rejects_stale_missing_and_collision_head_preserves_manual(self):
        check_storage('/does-not-exist', '', '')
        for request, expected in (('request', ''), ('request', 'bad'), ('request', 'b'*40), ('', 'b'*40)):
            with mock.patch('component_beta_storage_guard.subprocess.check_output', return_value=SHA+'\n'):
                with self.assertRaises(ValueError): check_storage('/tmp/storage', request, expected)
        for deadline in ('', '1000000000'):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                check_storage('/tmp/storage', 'request', SHA, deadline)
        with mock.patch('component_beta_storage_guard.subprocess.check_output', return_value=SHA+'\n'):
            check_storage('/tmp/storage', 'request', SHA, str(int(cb.time.time())+60))

    def test_preflight_never_dispatches_and_rerun_main_fork_guards_exist(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(cb.pathlib.Path, 'write_text'):
            path = pathlib.Path(tmp)
            # Main path is exercised with the read-only verifiers mocked, not Actions.
            env = dict(COMPONENT='ro-theme', TAG='v1.1.10', GITHUB_SHA=SHA, GITHUB_REPOSITORY=cb.REPOSITORY,
                       GITHUB_REF='refs/heads/main', GITHUB_RUN_ATTEMPT='1', PREFLIGHT_ONLY='true')
            with mock.patch.dict(cb.os.environ, env), mock.patch.object(cb.API, 'call', return_value={'object': {'sha': SHA}}), \
                 mock.patch.object(cb, 'producer_identity', return_value=IDENTITY), \
                 mock.patch.object(cb.subprocess, 'check_output', return_value=SHA), \
                 mock.patch.object(cb, 'verified_parent', return_value=(PARENT, 'd'*64)), \
                 mock.patch.object(cb.pathlib.Path, 'iterdir', return_value=iter([])), \
                 mock.patch.object(cb.Orchestrator, 'execute') as execute, mock.patch.object(sys, 'argv', ['component_beta.py']):
                cb.main()
                execute.assert_not_called()


if __name__ == '__main__': unittest.main()
