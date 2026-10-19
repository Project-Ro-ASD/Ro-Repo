#!/usr/bin/env python3
"""Manual V2 composition. No RPM signing and no V3 runtime imports."""
import argparse
import copy
import datetime as dt
import os
import pathlib
import shutil
import tempfile

import ro_repo as rr


def rpm_paths(snapshot, item):
    arch = item['architecture']
    folders = ['source'] if arch in {'src', 'nosrc'} else (
        ['x86_64', 'aarch64'] if arch == 'noarch' else [arch])
    for folder in folders:
        yield snapshot / 'rpm' / folder / item['filename']


def verified_channel(site, channel, home):
    publication_dir = site / 'rpm/fedora/44' / channel
    publication = rr.load(publication_dir / 'publication-v1.json')
    rr.validate_schema(publication, 'publication-v1')
    snapshot = site / 'snapshots/fedora/44' / publication['snapshot_id']
    # Reject symlinks anywhere in the signed input before reading RPM headers.
    rr.directory_tree_digest(snapshot)
    manifest = rr.verify_snapshot(snapshot, home)
    rr.verify_signed_rpms([next(rpm_paths(snapshot, item)) for item in manifest['packages']],
                          rr.ROOT / 'keys/production/ro-asd-rpm-signing-public.asc')
    rr.verify_signed_remote_publication(publication_dir, snapshot, channel, home)
    for arch in ('x86_64', 'aarch64', 'source'):
        if rr.directory_tree_digest(snapshot / 'rpm' / arch) != rr.directory_tree_digest(publication_dir / arch):
            raise rr.ContractError('channel RPM tree differs from immutable snapshot')
    return publication, snapshot, manifest


def inventory(snapshot, manifest):
    result = []
    seen = set()
    expected_files = {path.relative_to(snapshot).as_posix()
                      for item in manifest['packages'] for path in rpm_paths(snapshot, item)}
    if {path.relative_to(snapshot).as_posix() for path in (snapshot / 'rpm').rglob('*.rpm')} != expected_files:
        raise rr.ContractError('RPM inventory differs from signed manifest')
    for item in manifest['packages']:
        paths = list(rpm_paths(snapshot, item))
        for path in paths:
            if path.is_symlink() or rr.digest(path) != item['published_signed_artifact_sha256']:
                raise rr.ContractError('missing or changed signed RPM')
        header = rr.rpm_header(paths[0])
        if header['nevra'] != item['nevra'] or header['architecture'] != item['architecture']:
            raise rr.ContractError('RPM header differs from snapshot manifest')
        expected_filename = f"{header['name']}-{header['version']}-{header['release']}.{header['architecture']}.rpm"
        if item['filename'] != expected_filename:
            raise rr.ContractError('RPM filename differs from header')
        key = (header['name'], header['architecture'])
        if key in seen:
            raise rr.ContractError('multiple versions of package/architecture')
        seen.add(key)
        result.append((item, header, snapshot))
    return result


def select_group(entries, registry, group, complete=True):
    policies = [p for p in rr.component_policies(registry) if p['promotion_group'] == group]
    if not policies:
        raise rr.ContractError('unknown promotion group')
    names = {n for p in policies for n in p['package_names']}
    binary = [e for e in entries if e[1]['architecture'] not in {'src', 'nosrc'} and e[1]['name'] in names]
    sources = {e[1]['source_rpm'] for e in binary}
    selected = binary + [e for e in entries if e[1]['architecture'] in {'src', 'nosrc'} and e[0]['filename'] in sources]
    if complete:
        for policy in policies:
            component = [e for e in binary if e[1]['name'] in policy['package_names']]
            if {e[1]['name'] for e in component} != set(policy['package_names']):
                raise rr.ContractError('incomplete promotion group binary names')
            arches = {e[1]['architecture'] for e in component}
            if not arches <= set(policy['architectures']):
                raise rr.ContractError('unexpected group architecture')
            if policy['require_complete_architecture_set'] and arches != set(policy['architectures']):
                raise rr.ContractError('incomplete group architectures')
            for name in policy['package_names']:
                if {e[1]['architecture'] for e in component if e[1]['name'] == name} != arches:
                    raise rr.ContractError('incomplete subpackage architecture set')
            if policy['srpm_required']:
                available = {e[0]['filename'] for e in selected if e[1]['architecture'] in {'src', 'nosrc'}}
                if not {e[1]['source_rpm'] for e in component} <= available:
                    raise rr.ContractError('required SRPM missing')
            if len({(e[1]['epoch'], e[1]['version'], e[1]['release']) for e in component}) != 1:
                raise rr.ContractError('group versions differ')
    # A source RPM must not silently pull another group's binary packages.
    if any(e[1]['source_rpm'] in sources and e[1]['name'] not in names
           for e in entries if e[1]['architecture'] not in {'src', 'nosrc'}):
        raise rr.ContractError('source RPM shared with another group')
    return selected


def compose(site, output, group, beta_snapshot_id, beta_publication_run, reason,
            workflow_run, home, metadata_key, passphrase_file, registry_path=None):
    site, output = pathlib.Path(site), pathlib.Path(output)
    if not reason.strip() or rr._normalize_numeric_identity(workflow_run) is None:
        raise rr.ContractError('non-empty manual reason and numeric run required')
    beta_pub, beta_path, beta = verified_channel(site, 'beta', home)
    if (beta_pub['snapshot_id'], beta_pub['publication_run']) != (beta_snapshot_id, beta_publication_run):
        raise rr.ContractError('expected Beta snapshot/run mismatch')
    registry = rr.load_producer_registry(registry_path or rr.ROOT / 'config/producers-v2.json')
    selected = select_group(inventory(beta_path, beta), registry, group)
    stable_path = site / 'rpm/fedora/44/stable'
    stable_pub = stable = None
    retained, old_group = [], []
    if stable_path.exists():
        stable_pub, old_path, stable = verified_channel(site, 'stable', home)
        for key in ('rpm_signing_fingerprint', 'metadata_signing_fingerprint'):
            if stable[key] != beta[key]:
                raise rr.ContractError('source signing roles differ')
        old_entries = inventory(old_path, stable)
        old_group = select_group(old_entries, registry, group, complete=False)
        retained = [e for e in old_entries if e not in old_group]
    identity = lambda entries: sorted((e[0]['nevra'], e[0]['published_signed_artifact_sha256']) for e in entries)
    if identity(selected) == identity(old_group):
        return {'changed': False, 'snapshot_id': stable['snapshot_id']}
    metadata_fpr = rr.require_secret_signing_subkey(home, metadata_key, require_isolated=True)
    if metadata_fpr != beta['metadata_signing_fingerprint']:
        raise rr.ContractError('metadata signing role mismatch')
    passphrase = rr._validate_passphrase_file(passphrase_file)
    # Use the existing V2 namespace, checking every slot rather than truncating run IDs.
    date = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d')
    snapshot_id = next((f'repo-f44-{date}-{i:03}' for i in range(1, 1000)
                        if not (site / 'snapshots/fedora/44' / f'repo-f44-{date}-{i:03}').exists()), None)
    if snapshot_id is None:
        raise rr.ContractError('daily snapshot namespace exhausted')
    if output.exists():
        raise rr.ContractError('composition output must be new')
    entries = retained + selected
    if len({(e[1]['name'], e[1]['architecture']) for e in entries}) != len(entries):
        raise rr.ContractError('composed package collision')
    # Reject reusing a NEVRA with different signed content.
    historical = {p['nevra']: p['published_signed_artifact_sha256']
                  for mp in (site / 'snapshots/fedora/44').glob('*/repository-snapshot-v1.json')
                  for p in rr.load(mp)['packages']}
    if any(e[0]['nevra'] in historical and historical[e[0]['nevra']] != e[0]['published_signed_artifact_sha256'] for e in selected):
        raise rr.ContractError('historical NEVRA content changed')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.selected-stable-', dir=output.parent) as tmp:
        root = pathlib.Path(tmp) / 'bundle'
        snapshot = root / 'snapshots/fedora/44' / snapshot_id
        for arch in ('x86_64', 'aarch64', 'source'):
            (snapshot / 'rpm' / arch).mkdir(parents=True)
        checks = []
        for item, header, source in entries:
            for path in rpm_paths(source, item):
                dest = snapshot / path.relative_to(source)
                if dest.exists():
                    raise rr.ContractError('RPM filename collision')
                shutil.copy2(path, dest)
                if rr.digest(dest) != item['published_signed_artifact_sha256']:
                    raise rr.ContractError('RPM copy changed')
            checks.append((next(rpm_paths(snapshot, item)), item['architecture']))
        ok, conflicts = rr.repository_file_conflict_check(checks)
        if not ok:
            raise rr.ContractError(f'composed repository file conflicts: {conflicts}')
        manifest = copy.deepcopy(beta)
        manifest.update(snapshot_id=snapshot_id, created_at=rr.timestamp(),
                        parent_snapshot=stable['snapshot_id'] if stable else None,
                        packages=sorted([e[0] for e in entries], key=lambda x: (x['filename'], x['architecture'])),
                        creation_provenance={'tool': 'ro-repo-v2', 'run': str(workflow_run)})
        shutil.copytree(beta_path / 'keys', snapshot / 'keys')
        for arch in ('x86_64', 'aarch64', 'source'):
            repo = snapshot / 'rpm' / arch
            rr.run(['createrepo_c', '--unique-md-filenames', str(repo)])
            repomd = repo / 'repodata/repomd.xml'
            rr._sign_file_exact(repomd, home, metadata_fpr, passphrase)
            manifest['repositories'][arch] = {'repomd_sha256': rr.digest(repomd), 'repomd_signature_sha256': rr.digest(str(repomd) + '.asc')}
        mp = snapshot / 'repository-snapshot-v1.json'
        rr.validate_schema(manifest, 'repository-snapshot-v1')
        rr.save(mp, manifest)
        rr._sign_file_exact(mp, home, metadata_fpr, passphrase)
        rr.verify_snapshot(snapshot, home)
        # Reuse the V2 catalog and publication signer. Build as beta in private
        # staging, then bind the new catalog to stable with a fresh signature.
        rr.build_signed_remote_publication(snapshot, 'beta', root / 'publication', workflow_run,
                                           home, metadata_fpr, passphrase)
        publication = root / 'publication/beta'
        pub = rr.load(publication / 'publication-v1.json')
        pub['channel'] = 'stable'
        rr.save(publication / 'publication-v1.json', pub)
        (publication / 'publication-v1.json.asc').unlink()
        rr._sign_file_exact(publication / 'publication-v1.json', home, metadata_fpr, passphrase)
        publication.rename(root / 'publication/stable')
        rr.verify_signed_remote_publication(root / 'publication/stable', snapshot, 'stable', home)
        audit = {'changed': True, 'snapshot_id': snapshot_id, 'promotion_group': group,
                 'beta_snapshot_id': beta_snapshot_id, 'beta_publication_run': beta_publication_run,
                 'previous_stable': stable_pub, 'reason': reason.strip(), 'workflow_run': str(workflow_run),
                 'selected_packages': [e[0] for e in selected],
                 'retained_packages': [e[0] for e in retained]}
        rr.save(root / 'selected-promotion.json', audit)
        rr._sign_file_exact(root / 'selected-promotion.json', home, metadata_fpr, passphrase)
        os.rename(root, output)
    return audit


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('site', 'output', 'group', 'beta-snapshot-id', 'beta-publication-run', 'reason', 'workflow-run', 'home', 'metadata-key', 'passphrase-file'):
        p.add_argument('--' + name, required=True)
    a = p.parse_args()
    print(compose(**vars(a)))


if __name__ == '__main__':
    main()
