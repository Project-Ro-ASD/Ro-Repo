#!/usr/bin/env python3
"""Reverify the signed bundle before changing the private Pages checkout."""
import pathlib
import shutil
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tools'))
import ro_repo as rr
from v2_selected_stable import verified_channel, rpm_paths

def stage(site, bundle, home):
    audit = rr.load(bundle / 'selected-promotion.json')
    snapshot_id = audit['snapshot_id']
    snapshot = bundle / 'snapshots/fedora/44' / snapshot_id
    manifest = rr.verify_snapshot(snapshot, home)
    env = dict(rr.os.environ, GNUPGHOME=str(home))
    rr.verify_gpg_signature(bundle / 'selected-promotion.json', bundle / 'selected-promotion.json.asc',
                            manifest['metadata_signing_fingerprint'], env)
    beta, _, _ = verified_channel(site, 'beta', home)
    if (beta['snapshot_id'], beta['publication_run']) != (audit['beta_snapshot_id'], audit['beta_publication_run']):
        raise rr.ContractError('Beta changed after composition')
    current = site / 'rpm/fedora/44/stable'
    if audit['previous_stable'] is None:
        if current.exists():
            raise rr.ContractError('Stable appeared after composition')
    else:
        previous, _, _ = verified_channel(site, 'stable', home)
        if previous != audit['previous_stable']:
            raise rr.ContractError('Stable changed after composition')
    rr.verify_signed_rpms([next(rpm_paths(snapshot, p)) for p in manifest['packages']],
                          rr.ROOT / 'keys/production/ro-asd-rpm-signing-public.asc')
    rr.verify_signed_remote_publication(bundle / 'publication/stable', snapshot, 'stable', home)
    final = site / 'snapshots/fedora/44' / snapshot_id
    if final.exists():
        raise rr.ContractError('immutable snapshot collision')
    shutil.copytree(snapshot, final)
    audit_dir = site / 'promotions/fedora/44' / snapshot_id / audit['workflow_run']
    audit_dir.mkdir(parents=True)
    for name in ('selected-promotion.json', 'selected-promotion.json.asc'):
        shutil.copy2(bundle / name, audit_dir / name)
    rr.stage_remote_channel(bundle / 'publication/stable', site, 'stable', home)


if __name__ == "__main__":
    stage(*map(pathlib.Path, sys.argv[1:]))
