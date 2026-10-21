"""Finite, fail-closed V2 Beta dispatcher. No signing credentials or writer token.

API calls use the repository GITHUB_TOKEN through gh. Mutating requests are
never retried: an uncertain dispatch must be reconciled by its request ID.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import signal
import subprocess
import tempfile
import time
import uuid
import zipfile
from urllib.parse import quote, urlencode

import ro_repo as rr

REPOSITORY = 'Project-Ro-ASD/Ro-Repo'
SHA = r'[0-9a-f]{40}'
SNAPSHOT = r'repo-f44-[0-9]{8}-[0-9]{3}'
STAGES = ('accept-component', 'build-candidate-snapshot',
          'publish-pages-snapshot', 'publish-remote-beta')
# 4 x 45 minutes + preflight/transport within a 210-minute process budget;
# the hosting job has 240 minutes, below GitHub's six-hour hosted limit.
TOTAL_SECONDS = 210 * 60
STAGE_SECONDS = 45 * 60
DISCOVERY_SECONDS = 120


def require(condition, message):
    if not condition:
        raise ValueError(message)


class API:
    def __init__(self, deadline):
        self.deadline = deadline

    def call(self, path, body=None, output=None):
        require(time.monotonic() < self.deadline, 'overall deadline exceeded')
        cmd = ['gh', 'api', '--hostname', 'github.com', '-H',
               'X-GitHub-Api-Version: 2022-11-28', '-H',
               'Accept: application/vnd.github+json', path]
        if body is not None:
            cmd += ['--method', 'POST', '--input', '-']
        try:
            result = subprocess.run(cmd, input=json.dumps(body).encode() if body is not None else None,
                                    stdout=output or subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=max(1, min(60, self.deadline-time.monotonic())), check=True)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
            # Do not log headers/tokens; no retry, including rate limits/uncertain POST.
            raise ValueError(f'GitHub API failed or timed out: {path}; reconcile request before retry') from error
        return None if output else (json.loads(result.stdout) if result.stdout.strip() else None)

    def all(self, path, key):
        rows = []
        for page in range(1, 101):
            sep = '&' if '?' in path else '?'
            data = self.call(f'{path}{sep}per_page=100&page={page}')
            batch = data[key]
            rows.extend(batch)
            if len(batch) < 100:
                return rows
        raise ValueError('API pagination bound exceeded')


def producer_identity(api, registry, component, tag):
    matches = [(p['repository'], c) for p in registry['producers']
               for c in p['components'] if c['component'] == component]
    require(len(matches) == 1, 'component must identify exactly one allowlisted producer')
    repository, policy = matches[0]
    require(isinstance(tag, str) and 0 < len(tag) <= 200 and not any(ord(c) < 32 for c in tag), 'invalid exact tag')
    base = f'repos/{repository}'
    release = api.call(f'{base}/releases/tags/{quote(tag, safe="")}')
    require(release.get('draft') is False and release.get('immutable') is True,
            'release must be published and natively immutable')
    release_id = release.get('id')
    require(type(release_id) is int and release_id > 0 and release.get('tag_name') == tag,
            'release ID/tag mismatch')
    # commits/{tag} alone is ambiguous with same-named branches. Peel exact tag ref.
    obj = api.call(f'{base}/git/ref/tags/{quote(tag, safe="")}')['object']
    for _ in range(8):
        require(re.fullmatch(SHA, obj.get('sha', '')), 'invalid tag object SHA')
        if obj.get('type') == 'commit':
            break
        require(obj.get('type') == 'tag', 'tag does not resolve to commit')
        obj = api.call(f'{base}/git/tags/{obj["sha"]}')['object']
    require(obj.get('type') == 'commit', 'tag peel bound exceeded')
    commit = api.call(f'{base}/commits/{quote(tag, safe="")}')['sha']
    require(commit == obj['sha'], 'ambiguous tag/commit identity')
    # Read the exact manifest asset by ID through GitHub, not a user-provided URL.
    assets = [a for a in release.get('assets', []) if a.get('name') == 'component-artifact-manifest-v1.json']
    require(len(assets) == 1 and type(assets[0].get('id')) is int, 'missing/ambiguous release manifest')
    with tempfile.TemporaryFile() as stream:
        # Asset endpoint needs octet-stream; use a separate finite gh invocation.
        subprocess.run(['gh', 'api', '--hostname', 'github.com', '-H', 'Accept: application/octet-stream',
                        f'{base}/releases/assets/{assets[0]["id"]}'], stdout=stream,
                       stderr=subprocess.PIPE, timeout=60, check=True)
        stream.seek(0)
        manifest = json.load(stream)
    rr.validate_schema(manifest, 'component-artifact-manifest-v1')
    identity = dict(component=component, repository=repository, tag=tag,
                    commit=commit, release_id=str(release_id))
    check_component(manifest, identity)
    return identity


def check_component(manifest, identity):
    require(all(manifest.get(k) == v for k, v in {
        'component': identity['component'], 'source_repository': identity['repository'],
        'release_tag': identity['tag'], 'source_commit': identity['commit']}.items())
        and str(manifest.get('release_id')) == identity['release_id'], 'component manifest identity mismatch')


def allocate_snapshot(existing, today):
    prefix = f'repo-f44-{today}-'
    used = {int(x[-3:]) for x in existing if re.fullmatch(SNAPSHOT, x) and x.startswith(prefix)}
    # Above every already stored suffix, never reuse an abandoned stored snapshot.
    sequence = max(used, default=0) + 1
    require(sequence <= 999, 'daily snapshot namespace exhausted')
    return prefix + f'{sequence:03d}'


def verified_parent(storage):
    beta = storage / 'rpm/fedora/44/beta'
    publication = rr.load(beta / 'publication-v1.json')
    parent = publication.get('snapshot_id', '')
    require(re.fullmatch(SNAPSHOT, parent), 'invalid current Beta snapshot')
    snapshot = storage / 'snapshots/fedora/44' / parent
    rr.directory_tree_digest(snapshot)
    rr.directory_tree_digest(beta)
    fingerprints = dict(line.split('=', 1) for line in
                        (rr.ROOT / 'keys/production/production-fingerprints.txt').read_text().splitlines()
                        if '=' in line and not line.startswith('#'))
    with tempfile.TemporaryDirectory() as tmp:
        home = pathlib.Path(tmp) / 'gpg'
        home.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(home))
        subprocess.run(['gpg', '--batch', '--import', str(rr.ROOT / 'keys/production/ro-asd-metadata-signing-public.asc')],
                       env=env, check=True, capture_output=True, timeout=30)
        try:
            manifest = rr.verify_snapshot(snapshot, home)
            require(manifest['metadata_signing_fingerprint'] == fingerprints['METADATA_SIGNING']
                    and manifest['rpm_signing_fingerprint'] == fingerprints['RPM_SIGNING'], 'parent role mismatch')
            rr.verify_signed_remote_publication(beta, snapshot, 'beta', home)
            rr.verify_signed_rpms(list((snapshot / 'rpm').rglob('*.rpm')),
                                 rr.ROOT / 'keys/production/ro-asd-rpm-signing-public.asc')
            for arch in ('x86_64', 'aarch64', 'source'):
                require(rr.directory_tree_digest(snapshot / 'rpm' / arch) ==
                        rr.directory_tree_digest(beta / arch), 'Beta bytes differ from signed parent')
        finally:
            subprocess.run(['gpgconf', '--kill', 'gpg-agent'], env=env, capture_output=True, timeout=10)
    return parent, rr.digest(snapshot / 'repository-snapshot-v1.json')


def validate_run(run, run_id, workflow, request_id, commit, completed=False):
    expected = {'id': run_id, 'path': f'.github/workflows/{workflow}.yml',
                'event': 'workflow_dispatch', 'head_branch': 'main', 'head_sha': commit,
                'display_title': f'{workflow} [{request_id}]', 'run_attempt': 1}
    require(all(run.get(k) == v for k, v in expected.items()), 'wrong workflow/run/ref/commit/request/attempt')
    require(run.get('repository', {}).get('full_name') == REPOSITORY and
            run.get('head_repository', {}).get('full_name') == REPOSITORY, 'wrong run repository')
    if completed:
        require(run.get('status') == 'completed' and run.get('conclusion') == 'success', 'stage did not succeed')


def select_artifact(rows, name, run_id, commit):
    matches = [a for a in rows if a.get('name') == name]
    require(len(matches) == 1, 'missing or ambiguous exact artifact')
    a = matches[0]
    require(type(a.get('id')) is int and a['id'] > 0 and a.get('expired') is False,
            'invalid or expired artifact ID')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', a.get('digest', '')), 'missing artifact digest')
    require(a.get('workflow_run', {}).get('id') == run_id and
            a['workflow_run'].get('head_sha') == commit, 'artifact run/commit mismatch')
    return a


def artifact_documents(api, artifact, suffixes):
    with tempfile.TemporaryFile() as stream:
        api.call(f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip', output=stream)
        stream.seek(0)
        require('sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest() == artifact['digest'],
                'artifact ZIP digest mismatch')
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), 'duplicate archive paths')
            require(all(not n.startswith('/') and '..' not in pathlib.PurePosixPath(n).parts for n in names),
                    'unsafe archive paths')
            docs = {}
            for suffix in suffixes:
                matches = [n for n in names if n == suffix or n.endswith('/' + suffix)]
                require(len(matches) == 1, 'missing/ambiguous artifact metadata')
                info = archive.getinfo(matches[0])
                require(info.file_size <= 16 * 1024 * 1024, 'artifact metadata too large')
                docs[suffix] = json.loads(archive.read(info))
            return docs


class Orchestrator:
    def __init__(self, api, state, state_path, clock=time.monotonic, sleep=time.sleep):
        self.api, self.state, self.path = api, state, pathlib.Path(state_path)
        self.clock, self.sleep = clock, sleep
        self.active = None

    def save(self):
        self.path.write_text(json.dumps(self.state, indent=2) + '\n')

    def main_unchanged(self):
        require(self.api.call(f'repos/{REPOSITORY}/git/ref/heads/main')['object']['sha'] == self.state['source_sha'],
                'main changed; restart against reviewed current source')

    def storage_unchanged(self, expected):
        require(self.api.call(f'repos/{REPOSITORY}/git/ref/heads/pages-storage')['object']['sha'] == expected,
                'Pages storage changed; stale parent/collision/intervening publication')

    def stage(self, workflow, inputs, artifacts=()):
        self.main_unchanged()
        for previous, recorded in self.state['runs'].items():
            validate_run(self.api.call(f'repos/{REPOSITORY}/actions/runs/{recorded["id"]}'),
                         recorded['id'], previous, self.state['request_id'],
                         self.state['source_sha'], completed=True)
        self.state['blocked_stage'] = workflow
        self.state['dispatch_uncertain'] = True
        self.save()
        request_id = self.state['request_id']
        self.api.call(f'repos/{REPOSITORY}/actions/workflows/{workflow}.yml/dispatches',
                      {'ref': 'main', 'inputs': dict(inputs, request_id=request_id,
                          expected_source_commit=self.state['source_sha'],
                          request_deadline=str(int(time.time()) + STAGE_SECONDS))})
        start = self.clock()
        run = None
        while self.clock() - start < DISCOVERY_SECONDS:
            rows = self.api.all(f'repos/{REPOSITORY}/actions/workflows/{workflow}.yml/runs?' + urlencode({
                'event': 'workflow_dispatch', 'branch': 'main', 'created': '>=' + self.state['started_at']}), 'workflow_runs')
            matches = [r for r in rows if r.get('display_title') == f'{workflow} [{request_id}]']
            require(len(matches) <= 1, 'ambiguous correlated runs')
            if matches:
                run = matches[0]
                break
            self.sleep(5)
        require(run is not None, 'no correlated run before discovery timeout; reconcile request ID')
        run_id = run['id']
        require(type(run_id) is int and run_id > 0, 'invalid run ID')
        self.active = run_id
        self.state['runs'][workflow] = {'id': run_id, 'status': 'waiting', 'url':
                                       f'https://github.com/{REPOSITORY}/actions/runs/{run_id}'}
        self.state['dispatch_uncertain'] = False
        self.save()
        validate_run(run, run_id, workflow, request_id, self.state['source_sha'])
        while self.clock() - start < STAGE_SECONDS:
            run = self.api.call(f'repos/{REPOSITORY}/actions/runs/{run_id}')
            validate_run(run, run_id, workflow, request_id, self.state['source_sha'])
            if run.get('status') == 'completed':
                self.active = None
                self.state['runs'][workflow]['status'] = run.get('conclusion')
                self.save()
                validate_run(run, run_id, workflow, request_id, self.state['source_sha'], completed=True)
                break
            self.sleep(15)
        else:
            raise ValueError('stage approval/execution timeout; later stages blocked')
        result = {}
        if artifacts:
            rows = self.api.all(f'repos/{REPOSITORY}/actions/runs/{run_id}/artifacts', 'artifacts')
            for template in artifacts:
                name = template.format(run=run_id)
                result[name] = select_artifact(rows, name, run_id, self.state['source_sha'])
            self.state['runs'][workflow]['artifact_ids'] = [a['id'] for a in result.values()]
        self.active = None
        self.state['completed_stages'].append(workflow)
        self.save()
        return run_id, result

    def execute(self):
        s = self.state
        self.storage_unchanged(s['storage_sha'])
        acceptance, assets = self.stage(STAGES[0], {'repository': s['repository'], 'tag': s['tag'],
            'commit': s['commit'], 'release_id': s['release_id']},
            ['accepted-component-{run}', 'signed-component-{run}'])
        docs = artifact_documents(self.api, assets[f'accepted-component-{acceptance}'],
                                  ['component-artifact-manifest-v1.json'])
        check_component(docs['component-artifact-manifest-v1.json'], s)
        self.storage_unchanged(s['storage_sha'])
        candidate, assets = self.stage(STAGES[1], {'signing_runs': str(acceptance),
            'snapshot_id': s['snapshot_id'], 'parent_snapshot': s['parent_snapshot']},
            [f'candidate-snapshot-{s["snapshot_id"]}-{{run}}'])
        artifact = next(iter(assets.values()))
        docs = artifact_documents(self.api, artifact, ['repository-snapshot-v1.json', 'snapshot-build-evidence-v1.json'])
        manifest, evidence = docs['repository-snapshot-v1.json'], docs['snapshot-build-evidence-v1.json']
        rr.validate_schema(manifest, 'repository-snapshot-v1')
        rr.validate_schema(evidence, 'snapshot-build-evidence-v1')
        require(manifest['snapshot_id'] == s['snapshot_id'] and manifest['parent_snapshot'] == s['parent_snapshot']
                and evidence['workflow_run'] == candidate and evidence['source_signing_runs'] == [acceptance]
                and evidence.get('inherited_snapshot', {}).get('snapshot_id') == s['parent_snapshot']
                and evidence['inherited_snapshot'].get('repository_snapshot_sha256') == s['parent_manifest_sha256'],
                'candidate is not based on the exact verified parent/signing run')
        require(len(evidence['components']) == 1, 'candidate must contain exactly one incoming component')
        component = evidence['components'][0]
        require(component['signing_run'] == acceptance and component['source_repository'] == s['repository']
                and component['source_commit'] == s['commit'] and component['release_tag'] == s['tag']
                and str(component['release_id']) == s['release_id'], 'candidate component identity mismatch')
        self.storage_unchanged(s['storage_sha'])
        self.stage(STAGES[2], {'candidate_run': str(candidate), 'snapshot_id': s['snapshot_id'],
                              'expected_storage_commit': s['storage_sha']})
        # The exact writer commit must be the sole child of our original storage
        # head. An intervening writer (even a rollback/ABA) is rejected.
        head = self.api.call(f'repos/{REPOSITORY}/git/ref/heads/pages-storage')['object']['sha']
        commit = self.api.call(f'repos/{REPOSITORY}/git/commits/{head}')
        require([p['sha'] for p in commit['parents']] == [s['storage_sha']] and
                commit['message'] == f'publish: {s["snapshot_id"]} from candidate run {candidate}',
                'unexpected Pages writer commit; no Beta dispatch')
        s['published_storage_sha'] = head
        self.save()
        remote, _ = self.stage(STAGES[3], {'snapshot_id': s['snapshot_id'], 'expected_storage_commit': head},
                               [f'signed-beta-publication-{s["snapshot_id"]}-{{run}}'])
        jobs = self.api.all(f'repos/{REPOSITORY}/actions/runs/{remote}/attempts/1/jobs', 'jobs')
        verification = [j for j in jobs if j.get('name') == 'verify-remote-beta']
        require(len(verification) == 1 and verification[0].get('conclusion') == 'success',
                'independent remote Beta verification did not succeed')
        s['remote_verification'] = 'success'
        s['result'] = 'SUCCESS'
        s['blocked_stage'] = None
        self.save()

    def cancel(self):
        if self.active:
            # A separate short API budget lets cleanup run after the main deadline.
            API(time.monotonic() + 20).call(f'repos/{REPOSITORY}/actions/runs/{self.active}/cancel', {})
            self.state['cancellation_requested'] = self.active
            self.save()


def summary(state, output):
    lines = ['## Publish component to Beta', '', f'Result: **{state.get("result", "FAILED / UNKNOWN")}**', '']
    for key in ('component', 'tag', 'repository', 'release_id', 'commit', 'request_id',
                'source_sha', 'parent_snapshot', 'snapshot_id', 'remote_verification', 'blocked_stage', 'error'):
        lines.append(f'- {key}: `{str(state.get(key, "unavailable")).replace(chr(10), " ").replace("`", "")}`')
    for stage in STAGES:
        run = state.get('runs', {}).get(stage)
        lines.append(f'- {stage}: [{run["id"]}]({run["url"]}) — {run["status"]}' if run else f'- {stage}: not dispatched / unknown')
    lines += ['', 'Retry: inspect every linked run and reconcile any uncertain dispatch by request ID. '
              'Cancel pending children before retry. Never rerun an old writer; start a fresh request from current Beta. '
              'A remote-stage failure may have already changed Beta; verify remote state before retry.']
    pathlib.Path(output).open('a').write('\n'.join(lines) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--summary-only', action='store_true')
    args = parser.parse_args()
    path = pathlib.Path('component-beta-state.json')
    if args.summary_only:
        summary(json.loads(path.read_text()) if path.exists() else {}, os.environ['GITHUB_STEP_SUMMARY'])
        return
    state = {'component': os.environ['COMPONENT'], 'tag': os.environ['TAG'],
             'request_id': uuid.uuid4().hex, 'source_sha': os.environ['GITHUB_SHA'],
             'started_at': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
             'runs': {}, 'completed_stages': [], 'result': 'FAILED / UNKNOWN', 'blocked_stage': 'preflight'}
    api = API(time.monotonic() + TOTAL_SECONDS)
    orchestrator = Orchestrator(api, state, path)
    orchestrator.save()
    def interrupted(signum, frame):
        raise ValueError(f'orchestrator interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        require(os.environ['GITHUB_REPOSITORY'] == REPOSITORY and os.environ['GITHUB_REF'] == 'refs/heads/main',
                'orchestration is restricted to canonical repository main')
        require(os.environ.get('GITHUB_RUN_ATTEMPT') == '1', 'start a fresh request; reruns are forbidden')
        orchestrator.main_unchanged()
        state.update(producer_identity(api, rr.load_producer_registry('config/producers-v2.json'),
                                       state['component'], state['tag']))
        storage = pathlib.Path('storage')
        storage_sha = subprocess.check_output(['git', '-C', str(storage), 'rev-parse', 'HEAD'], text=True).strip()
        require(re.fullmatch(SHA, storage_sha), 'invalid storage commit')
        state['storage_sha'] = storage_sha
        orchestrator.storage_unchanged(storage_sha)
        parent, digest = verified_parent(storage)
        state.update(parent_snapshot=parent, parent_manifest_sha256=digest,
                     snapshot_id=allocate_snapshot((p.name for p in (storage / 'snapshots/fedora/44').iterdir()),
                                                  dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d')))
        orchestrator.save()
        if os.environ.get('PREFLIGHT_ONLY') == 'true':
            state.update(result='PREFLIGHT PASSED (no publication)', blocked_stage=None)
        else:
            orchestrator.execute()
    except Exception as error:
        state['error'] = f'{type(error).__name__}: {error}'
        try:
            orchestrator.cancel()
        except Exception:
            state['cancellation_failed'] = True
        raise
    finally:
        orchestrator.save()


if __name__ == '__main__':
    main()
