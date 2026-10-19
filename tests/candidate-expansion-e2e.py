#!/usr/bin/env python3
"""Real signed RPM + repodata + DNF5 candidate regression, ephemeral test keys only."""
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

        def build(name, version, subpackages=(), noarch=False, target=None):
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
            rr.run(['rpmbuild', '-ba', '--define', f'_topdir {top}', *(['--target',target] if target else []), str(sp)])
            result = []
            for path in sorted(top.rglob('*.rpm')):
                if f'-{version}-' not in path.name or not path.name.startswith(name + '-'):
                    continue
                header = rr.rpm_header(path)
                signed = work / 'signed' / path.name
                signed.parent.mkdir(exist_ok=True)
                producer_digest = rr.digest(path)
                rr._sign_rpm_exact(path, signed, full, rpm_key + '!', passphrase)
                item = {'filename': path.name, 'nevra': header['nevra'], 'architecture': header['architecture'],
                        'producer_artifact_sha256': producer_digest, 'published_signed_artifact_sha256': rr.digest(signed),
                        'producer_manifest_digest': 'a' * 64}
                result.append((item, signed))
            packages[(name, version)] = result

        # These are disposable RPM fixtures, never producer acceptance evidence.
        # Model the actual 23-entry Beta including Dolphin's three binaries.
        build('dolphin', '26.08.1', ('libs', 'devel'))
        for name, version in [('ro-asd-branding','0.1.0'), ('ro-asd-defaults','0.1.0'),
                              ('ro-asd-desktop-standard','0.1.0'), ('ro-asd-kernel-policy','0.1.0'),
                              ('ro-asd-keyring','0.1.0'), ('ro-asd-release','0.1.2'), ('ro-asd-repos','0.1.1')]:
            build(name, version, noarch=True)
        build('ro-assist', '0.2.5')
        build('ro-assist', '0.2.5', target='aarch64')
        build('ro-installer', '2.4.4')
        build('ro-installer', '2.4.5')
        build('ro-theme', '1.1.5', noarch=True)
        build('ro-widgets', '99.0', noarch=True)  # explicitly synthetic future version
        # Build a fully verified parent with the existing production composer.
        def components_for(builds):
            result = []
            for index, key in enumerate(builds, 1):
                name, version = key
                policy = rr.resolve_package_policy(rr.load_producer_registry(ROOT / 'config/producers-v2.json'), name)
                entries = []
                for item, path in packages[key]:
                    header = rr.rpm_header(path)
                    header.update(filename=item['filename'], producer_artifact_sha256=item['producer_artifact_sha256'])
                    entries.append({'item':header, 'path':path, 'nevra':item['nevra'],
                                    'signed_digest':item['published_signed_artifact_sha256'], 'manifest_digest':'a'*64})
                result.append({'signing_run':index, 'source_repository':policy['repository'], 'source_commit':'b'*40,
                               'release_tag':'fixture-'+version, 'release_id':index, 'producer_workflow_run':index,
                               'acceptance_manifest_digest':'a'*64, 'packages':entries})
            return result
        baseline_keys = list(packages)[:-3]
        source_runs = work / 'runs.json'
        def compose(builds, number, base=None):
            components = components_for(builds)
            runs = {'schema_version':1, 'runs':[{'run_id':c['signing_run']} for c in components]}
            rr.save(source_runs, runs)
            # Only the transport handoff is substituted. RPM headers, signatures,
            # parent signatures, byte hashes, repodata and DNF5 execute for real.
            with mock.patch.object(rr, 'verify_signed_component_bundle', return_value=(runs,components)):
                rr.build_production_snapshot(work/'components', source_runs, work/'output',
                    f'repo-f44-20260101-{number:03}', home, meta_key, rpm_key, number, passphrase,
                    parent=base.name if base else None, test_only_metadata_public_key=meta_public,
                    test_only_rpm_public_key=rpm_public, base_snapshot=base)
            return work/'output/snapshots/fedora/44'/f'repo-f44-20260101-{number:03}'
        base = compose(baseline_keys, 100)
        before = rr.load(base/'repository-snapshot-v1.json')
        parent_tree = rr.directory_tree_digest(base)
        # Remove ALL old signing-run transport artifacts: only snapshot RPMs survive.
        shutil.rmtree(top)
        for key in baseline_keys:
            for _, path in packages[key]:
                path.unlink()
        new = [('ro-installer','2.4.5'), ('ro-theme','1.1.5'), ('ro-widgets','99.0')]
        partial = compose(new[:2], 99, base)
        assert len(rr.load(partial/'repository-snapshot-v1.json')['packages']) == 25
        candidate = compose(new, 101, base)
        after, evidence = rr.verify_production_candidate(candidate, home, 101)
        retained = evidence['inherited_snapshot']['retained_packages']
        assert len(before['packages']) == 23
        assert len(after['packages']) == 27
        assert len(retained) == 21
        assert len(after['packages']) == len(before['packages'])+4
        for item in retained:
            for old_path, new_path in zip(selected.rpm_paths(base,item),selected.rpm_paths(candidate,item)):
                assert old_path.read_bytes() == new_path.read_bytes()
        assert rr.directory_tree_digest(base) == parent_tree
        for name in ('ro-theme','ro-widgets'):
            item = next(p for p in after['packages'] if p['filename'].startswith(name+'-') and p['architecture']=='noarch')
            assert len(list(selected.rpm_paths(candidate,item))) == 2
        rr.run(['bash', str(ROOT/'tests/selected-stable-dnf.sh'), str(candidate), str(base)])
        print('PASS Fedora 44 DNF5: clean install, Installer 2.4.4 -> 2.4.5, Theme install, synthetic Widgets install', flush=True)
        check_failure(lambda: compose(new, 102, candidate))
        # A valid older signed Installer is rejected before composition.
        packages['ro-installer','2.4.4'] = [(item,next(selected.rpm_paths(base,item))) for item in before['packages'] if item['filename'].startswith('ro-installer-')]
        check_failure(lambda: compose([('ro-installer','2.4.4')], 103, candidate))
        target = next(selected.rpm_paths(base,retained[0]))
        target.write_bytes(target.read_bytes()+b'tamper')
        check_failure(lambda: compose(new, 104, base))
        print('PASS immutable parent, unrelated SHA256 preservation, noarch copies, SRPM closure, signatures, same-version/downgrade/tamper rejection', flush=True)

if __name__ == '__main__':
    main()
