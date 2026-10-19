#!/usr/bin/env python3
"""Real signed RPM + repodata + DNF5 V2 regression, ephemeral test keys only."""
import copy
import os
import pathlib
import shutil
import sys
import tempfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'scripts')]
import ro_repo as rr
import v2_selected_stable as selected
from stage_selected_stable import stage


def check_failure(fn):
    try:
        fn()
    except (rr.ContractError, OSError):
        return
    raise AssertionError('operation should have been rejected')


def main():
    with tempfile.TemporaryDirectory(prefix='selected-stable-e2e-') as tmp:
        work = pathlib.Path(tmp)
        full = work / 'keys'
        full.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(full))
        rr.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key', 'V2 TEST ONLY <v2@invalid>', 'rsa2048', 'cert', '1d'], env)
        primary = next(r['fingerprint'] for r in rr.gpg_fingerprint_records(rr.run(['gpg', '--with-colons', '--fingerprint'], env).stdout) if r['type'] == 'pub')
        for _ in range(2):
            rr.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-add-key', primary, 'rsa2048', 'sign', '1d'], env)
        keys = [r['fingerprint'] for r in rr.gpg_fingerprint_records(rr.run(['gpg', '--with-colons', '--fingerprint'], env).stdout) if r['type'] == 'sub']
        rpm_key, meta_key = keys
        home = work / 'metadata-home'
        home.mkdir(mode=0o700)
        secret = work / 'metadata-subkey.asc'
        secret.write_text(rr.run(['gpg', '--batch', '--armor', '--export-filter', f'drop-subkey=fpr <> {meta_key}', '--export-secret-subkeys', primary], env).stdout)
        rr.run(['gpg', '--batch', '--import', str(secret)], dict(os.environ, GNUPGHOME=str(home)))
        rpm_public = work / 'rpm.asc'
        rpm_public.write_text(rr.export_role_public_key(full, rpm_key))
        meta_public = work / 'metadata.asc'
        meta_public.write_text(rr.export_role_public_key(full, meta_key))
        passphrase = work / 'passphrase'
        passphrase.write_text('')
        passphrase.chmod(0o600)
        top = work / 'rpmbuild'
        for folder in ['BUILD', 'BUILDROOT', 'RPMS', 'SRPMS', 'SOURCES', 'SPECS']:
            (top / folder).mkdir(parents=True)
        packages = {}

        def build(name, version, subpackages=(), noarch=False):
            spec = f'''Name: {name}
Version: {version}
Release: 1.fc44
Summary: V2 selected stable fixture
License: MIT
'''
            if noarch:
                spec += 'BuildArch: noarch\n'
            if subpackages:
                spec += f'Requires: {name}-libs = %{{version}}-%{{release}}\n'
            spec += '%description\nTemporary test fixture.\n'
            for sub in subpackages:
                spec += f'%package {sub}\nSummary: Fixture {sub}\n%description {sub}\nFixture.\n'
            spec += '%prep\n%build\n%install\n'
            for sub in ('',) + tuple(subpackages):
                pkg = name + ('-' + sub if sub else '')
                spec += f'mkdir -p %{{buildroot}}/usr/share/{pkg}\necho {version} > %{{buildroot}}/usr/share/{pkg}/version\n'
            for sub in ('',) + tuple(subpackages):
                pkg = name + ('-' + sub if sub else '')
                spec += f'%files {sub}\n/usr/share/{pkg}\n'
            sp = top / 'SPECS' / f'{name}.spec'
            sp.write_text(spec)
            rr.run(['rpmbuild', '-ba', '--define', f'_topdir {top}', str(sp)])
            result = []
            for path in sorted(top.rglob('*.rpm')):
                if f'-{version}-' not in path.name or not path.name.startswith(name + '-'):
                    continue
                header = rr.rpm_header(path)
                signed = work / 'signed' / path.name
                signed.parent.mkdir(exist_ok=True)
                producer_digest = rr.digest(path)
                rr._sign_rpm_exact(path, signed, full, rpm_key, passphrase)
                item = {'filename': path.name, 'nevra': header['nevra'], 'architecture': header['architecture'],
                        'producer_artifact_sha256': producer_digest, 'published_signed_artifact_sha256': rr.digest(signed),
                        'producer_manifest_digest': 'a' * 64}
                result.append((item, signed))
            packages[(name, version)] = result

        build('ro-control', '1')
        build('ro-assist', '1')
        build('ro-assist', '2')
        build('dolphin', '1', ('libs', 'devel'))
        build('ro-asd-branding', '1', noarch=True)
        site = work / 'site'
        registry = rr.load(ROOT / 'config/producers-v2.json')
        registry_path = work / 'registry.json'
        rr.save(registry_path, registry)

        def snapshot(number, artifacts):
            sid = f'repo-f44-20260101-{number:03}'
            snap = site / 'snapshots/fedora/44' / sid
            manifest = {'schema_version': 1, 'snapshot_id': sid, 'created_at': rr.timestamp(), 'fedora_release': 44,
                        'parent_snapshot': None, 'packages': [a[0] for a in artifacts], 'repositories': {},
                        'rpm_signing_fingerprint': rpm_key, 'metadata_signing_fingerprint': meta_key,
                        'creation_provenance': {'tool': 'ro-repo-v2', 'run': str(number)}}
            for arch in ['x86_64', 'aarch64', 'source']:
                (snap / 'rpm' / arch).mkdir(parents=True)
            for item, source in artifacts:
                for dest in selected.rpm_paths(snap, item):
                    shutil.copy2(source, dest)
            for arch in ['x86_64', 'aarch64', 'source']:
                repo = snap / 'rpm' / arch
                rr.run(['createrepo_c', '--unique-md-filenames', str(repo)])
                mp = repo / 'repodata/repomd.xml'
                rr._sign_file_exact(mp, home, meta_key, passphrase)
                manifest['repositories'][arch] = {'repomd_sha256': rr.digest(mp), 'repomd_signature_sha256': rr.digest(str(mp)+'.asc')}
            (snap / 'keys').mkdir()
            shutil.copy2(rpm_public, snap / 'keys/RPM-GPG-KEY-ro-asd')
            shutil.copy2(meta_public, snap / 'keys/REPODATA-GPG-KEY-ro-asd')
            mp = snap / 'repository-snapshot-v1.json'
            rr.save(mp, manifest)
            rr._sign_file_exact(mp, home, meta_key, passphrase)
            out = work / f'beta-{number}'
            rr.build_signed_remote_publication(snap, 'beta', out, number, home, meta_key, passphrase)
            rr.stage_remote_channel(out / 'beta', site, 'beta', home)
            return sid

        base_artifacts = packages['ro-control', '1'] + packages['ro-assist', '1'] + packages['dolphin', '1'] + packages['ro-asd-branding', '1']
        beta_id = snapshot(100, base_artifacts)
        real_verify = rr.verify_signed_rpms
        # The sole fixture adaptation: production trust anchor is replaced by
        # the temporary RPM public key; actual RPM verification still executes.
        with mock.patch.object(rr, 'verify_signed_rpms', side_effect=lambda paths, key: real_verify(paths, rpm_public)):
            run = 200
            def promote(group, expected_id=None, expected_run='100', publish=True):
                nonlocal run
                run += 1
                out = work / f'bundle-{run}'
                audit = selected.compose(site, out, group, expected_id or beta_id, expected_run, 'fixture manual promotion', str(run), home, meta_key, passphrase, registry_path)
                if audit['changed'] and publish:
                    stage(site, out, home)
                return audit, out

            check_failure(lambda: promote('ro-assist', expected_id='repo-f44-20260101-999'))
            check_failure(lambda: promote('ro-assist', expected_run='999'))
            first, first_bundle = promote('ro-control')
            assert first['changed'] and not first['retained_packages']
            first_snapshot = site / 'snapshots/fedora/44' / first['snapshot_id']
            rr.run([str(ROOT / 'tests/selected-stable-dnf.sh'), str(first_snapshot)])
            before = {p.relative_to(site / 'rpm/fedora/44/stable'): p.read_bytes() for p in (site / 'rpm/fedora/44/stable').rglob('*.rpm')}
            second, second_bundle = promote('ro-assist')
            second_snapshot = site / 'snapshots/fedora/44' / second['snapshot_id']
            for rel, data in before.items():
                assert (site / 'rpm/fedora/44/stable' / rel).read_bytes() == data
            unchanged = rr.directory_tree_digest(site / 'rpm/fedora/44/stable')
            noop, out = promote('ro-assist')
            assert not noop['changed'] and not out.exists()
            assert unchanged == rr.directory_tree_digest(site / 'rpm/fedora/44/stable')
            multi, _ = promote('ro-kde-dolphin')
            assert len(multi['selected_packages']) == 4
            branding, _ = promote('ro-asd-branding')
            assert len(branding['selected_packages']) == 2
            previous_snapshot = site / 'snapshots/fedora/44' / branding['snapshot_id']
            beta_id = snapshot(101, packages['ro-control', '1'] + packages['ro-assist', '2'] + packages['dolphin', '1'] + packages['ro-asd-branding', '1'])
            upgraded, bundle = promote('ro-assist', expected_run='101', publish=False)
            # Failure during channel replacement restores old view.
            old_digest = rr.directory_tree_digest(site / 'rpm/fedora/44/stable')
            new_snap = bundle / 'snapshots/fedora/44' / upgraded['snapshot_id']
            rr.run([str(ROOT / 'tests/selected-stable-dnf.sh'), str(new_snap), str(previous_snapshot)])
            real_rename = os.rename
            def failing_rename(src, dest):
                if pathlib.Path(src).name == 'stable' and pathlib.Path(src).parent.name.startswith('.stable-'):
                    raise OSError('injected replacement failure')
                return real_rename(src, dest)
            with mock.patch('os.rename', side_effect=failing_rename):
                check_failure(lambda: stage(site, bundle, home))
            assert old_digest == rr.directory_tree_digest(site / 'rpm/fedora/44/stable')
            # The private failed checkout is discarded before retry (as CI does).
            shutil.rmtree(site / 'snapshots/fedora/44' / upgraded['snapshot_id'])
            shutil.rmtree(site / 'promotions/fedora/44' / upgraded['snapshot_id'])
            stage(site, bundle, home)
            for item in upgraded['retained_packages']:
                for p in selected.rpm_paths(site / 'snapshots/fedora/44' / upgraded['snapshot_id'], item):
                    assert rr.digest(p) == item['published_signed_artifact_sha256']
            assert not any('ro-assist-1-' in p.name for p in (site / 'rpm/fedora/44/stable').rglob('*.rpm'))
            target_run = branding['workflow_run']
            rr.rollback_remote_channel(site, 'stable', target_run, '999', 'fixture rollback', home)
            assert rr.load(site / 'rpm/fedora/44/stable/publication-v1.json')['publication_run'] == target_run
            rr.run([str(ROOT / 'tests/selected-stable-dnf.sh'), str(previous_snapshot)])
            beta_snap = site / 'snapshots/fedora/44' / beta_id
            victim = next(beta_snap.rglob('ro-assist-2-*.rpm'))
            original = victim.read_bytes()
            victim.write_bytes(original + b'corrupt')
            check_failure(lambda: promote('ro-assist', expected_run='101'))
            victim.write_bytes(original)
            # An unsigned RPM with a matching, freshly signed test manifest
            # must still fail the independent trusted RPM signature check.
            mp = beta_snap / 'repository-snapshot-v1.json'
            manifest_bytes = mp.read_bytes()
            signature_bytes = pathlib.Path(str(mp) + '.asc').read_bytes()
            rr.run(['rpm', '--delsign', str(victim)])
            altered = rr.load(mp)
            next(p for p in altered['packages'] if p['filename'] == victim.name)['published_signed_artifact_sha256'] = rr.digest(victim)
            rr.save(mp, altered)
            pathlib.Path(str(mp) + '.asc').unlink()
            rr._sign_file_exact(mp, home, meta_key, passphrase)
            check_failure(lambda: promote('ro-assist', expected_run='101'))
            victim.write_bytes(original)
            mp.write_bytes(manifest_bytes)
            pathlib.Path(str(mp) + '.asc').write_bytes(signature_bytes)
            victim.unlink()
            check_failure(lambda: promote('ro-assist', expected_run='101'))
            victim.write_bytes(original)
            sig = beta_snap / 'repository-snapshot-v1.json.asc'
            sig.write_text('invalid signature')
            check_failure(lambda: promote('ro-assist', expected_run='101'))
        print('PASS: empty Stable, independent addition, full Dolphin group, noarch, byte preservation, no-op, upgrade, real DNF5, failure preservation, rollback, invalid identity/signature/missing RPM')


if __name__ == '__main__':
    main()
