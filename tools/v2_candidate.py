"""Incremental V2 candidate planning from a verified immutable snapshot."""
import pathlib

import ro_repo as rr
from v2_selected_stable import inventory, rpm_paths, select_group


def plan(base, components, parent, home, rpm_key, metadata_key, rpm_public):
    """Preserve all unrelated signed bytes; replace only complete newer groups."""
    import rpm

    base = pathlib.Path(base)
    rr.directory_tree_digest(base)
    manifest = rr.verify_snapshot(base, home)
    if manifest['snapshot_id'] != parent:
        raise rr.ContractError('base snapshot identity differs from parent')
    if (manifest['rpm_signing_fingerprint'] != rpm_key.upper()
            or manifest['metadata_signing_fingerprint'] != metadata_key.upper()):
        raise rr.ContractError('base snapshot signing roles differ')
    old = inventory(base, manifest)
    rr.verify_signed_rpms([next(rpm_paths(base, e[0])) for e in old], rpm_public)
    registry = rr.load_producer_registry(rr.ROOT / 'config/producers-v2.json')
    retained = list(old)
    replaced = []
    groups = set()
    for component in components:
        incoming = component['packages']
        names = {p['item']['name'] for p in incoming if p['item']['architecture'] not in {'src', 'nosrc'}}
        policies = [p for p in rr.component_policies(registry)
                    if p['repository'] == component['source_repository']
                    and names & set(p['package_names'])]
        if len(policies) != 1 or names != set(policies[0]['package_names']):
            raise rr.ContractError('candidate must contain one complete component per signing run')
        group = policies[0]['promotion_group']
        if group in groups:
            raise rr.ContractError('duplicate candidate promotion group')
        groups.add(group)
        entries = []
        for p in incoming:
            item = p['item']
            entries.append((dict(item, nevra=p['nevra']), item, base))
        # Reuse V2 complete architecture, subpackage, EVR and SRPM policy.
        if len(select_group(entries, registry, group)) != len(entries):
            raise rr.ContractError('candidate contains unrelated source RPMs')
        previous = select_group(old, registry, group, complete=False)
        if previous:
            before = {(e[1]['name'], e[1]['architecture']): e[1] for e in previous}
            after = {(e[1]['name'], e[1]['architecture']): e[1] for e in entries}
            if before.keys() != after.keys():
                raise rr.ContractError('replacement changes package/architecture set')
            for key, header in before.items():
                newer = after[key]
                evr = lambda h: (str(h['epoch']), h['version'], h['release'])
                if rpm.labelCompare(evr(newer), evr(header)) <= 0:
                    raise rr.ContractError('candidate downgrade or same-version replacement rejected')
            replaced.extend(e[0] for e in previous)
            retained = [e for e in retained if e not in previous]
    all_headers = [dict(e[1], filename=e[0]['filename']) for e in retained] + [p['item'] for c in components for p in c['packages']]
    binaries = [h for h in all_headers if h['architecture'] not in {'src', 'nosrc'}]
    sources = {h['filename'] for h in all_headers if h['architecture'] in {'src', 'nosrc'}}
    if any(h['source_rpm'] not in sources for h in binaries):
        raise rr.ContractError('candidate source RPM closure incomplete')
    identities = [(h['name'], h['architecture']) for h in all_headers]
    if len(identities) != len(set(identities)):
        raise rr.ContractError('candidate package/architecture collision')
    return retained, {
        'snapshot_id': parent,
        'repository_snapshot_sha256': rr.digest(base / 'repository-snapshot-v1.json'),
        'retained_packages': [e[0] for e in retained],
        'replaced_packages': replaced,
    }
