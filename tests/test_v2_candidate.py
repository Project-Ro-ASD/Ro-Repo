import copy
import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
import yaml
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / 'tools'))
import ro_repo as rr
import v2_candidate as candidate


class SnapshotParameterTests(unittest.TestCase):
    snapshot_id = 'repo-f44-20261020-001'
    parent_id = 'repo-f44-20261009-001'

    def build(self, output, **kwargs):
        return rr.build_production_snapshot(
            '/unused/components', '/unused/runs.json', output, self.snapshot_id,
            '/unused/keys', 'B'*40, 'A'*40, 123, '/unused/passphrase', **kwargs)

    def assert_rejected_before_signing(self, message, **kwargs):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(rr, '_validate_passphrase_file') as passphrase, \
             mock.patch.object(rr, 'require_secret_signing_subkey') as keys, \
             mock.patch.object(rr, 'verify_signed_component_bundle') as bundle:
            output = pathlib.Path(tmp)/'candidate'
            with self.assertRaisesRegex(rr.ContractError, message):
                self.build(output, **kwargs)
            passphrase.assert_not_called()
            keys.assert_not_called()
            bundle.assert_not_called()
            self.assertFalse(output.exists())

    def test_parent_without_base_rejected(self):
        self.assert_rejected_before_signing('requires both', parent=self.parent_id)

    def test_base_without_parent_rejected(self):
        for base in (pathlib.Path('/snapshots')/self.parent_id, ''):
            with self.subTest(base=base):
                self.assert_rejected_before_signing('requires both', base_snapshot=base)

    def test_parent_cannot_be_candidate_itself(self):
        self.assert_rejected_before_signing(
            'distinct exact parent', parent=self.snapshot_id,
            base_snapshot=pathlib.Path('/snapshots')/self.snapshot_id)

    def test_wrong_or_empty_base_identity_rejected(self):
        for base in ('/snapshots/repo-f44-20261009-002', ''):
            with self.subTest(base=base):
                self.assert_rejected_before_signing(
                    'directory identity differs', parent=self.parent_id, base_snapshot=base)

    def test_empty_parent_does_not_become_initial_snapshot(self):
        self.assert_rejected_before_signing('invalid parent', parent='')

    def test_initial_and_matching_incremental_inputs_reach_normal_verification(self):
        for kwargs in ({}, dict(parent=self.parent_id,
                                base_snapshot=pathlib.Path('/snapshots')/self.parent_id)):
            with self.subTest(kwargs=kwargs), mock.patch.object(
                    rr, '_validate_passphrase_file', side_effect=rr.ContractError('normal verification reached')) as verify:
                with self.assertRaisesRegex(rr.ContractError, 'normal verification reached'):
                    self.build('/unused/output', **kwargs)
                verify.assert_called_once_with('/unused/passphrase')


class IncrementalCandidateTests(unittest.TestCase):
    def setUp(self):
        self.base = pathlib.Path('/fixture/repo-f44-20261009-001')
        self.packages = rr.load(rr.ROOT / 'docs/evidence/v2-beta-expansion/baseline-inventory.json')['packages']
        self.entries = []
        for item in self.packages:
            name, epoch, version, release, arch = rr._parse_snapshot_nevra(item['nevra'])
            source_name = 'dolphin' if name.startswith('dolphin') else name
            header = dict(name=name, epoch=int(epoch), version=version, release=release,
                          architecture=arch, source_rpm=None if arch == 'src' else f'{source_name}-{version}-{release}.src.rpm')
            self.entries.append((item, header, self.base))
        self.manifest = dict(snapshot_id=self.base.name, rpm_signing_fingerprint='A'*40,
                             metadata_signing_fingerprint='B'*40)
        self.components = []
        for name, version, repository, arch in [('ro-installer','2.4.5','ro-Installer','x86_64'),
                                               ('ro-theme','1.1.5','Ro-Theme','noarch'),
                                               ('ro-widgets','99.0','ro-widgets','noarch')]:
            entries = []
            for architecture in (arch,'src'):
                item = dict(name=name, epoch=0, version=version, release='1.fc44', architecture=architecture,
                            filename=f'{name}-{version}-1.fc44.{architecture}.rpm',
                            source_rpm=None if architecture=='src' else f'{name}-{version}-1.fc44.src.rpm')
                entries.append({'item':item, 'nevra':f'{name}-0:{version}-1.fc44.{architecture}'})
            self.components.append({'source_repository':'Project-Ro-ASD/'+repository,'packages':entries})

    def plan(self, components=None):
        # Version ordering itself is exercised with librpm in the Fedora E2E.
        with mock.patch.dict(sys.modules, rpm=types.SimpleNamespace(labelCompare=lambda a,b:(a>b)-(a<b))), \
             mock.patch.object(rr, 'directory_tree_digest'), \
             mock.patch.object(rr, 'verify_snapshot', return_value=self.manifest), \
             mock.patch.object(candidate, 'inventory', return_value=self.entries), \
             mock.patch.object(rr, 'verify_signed_rpms'), \
             mock.patch.object(rr, 'digest', return_value='c'*64):
            return candidate.plan(self.base, self.components if components is None else components,
                                  self.base.name, '/home', 'A'*40,'B'*40,'/public')

    def test_preserve_all_21_unrelated_entries_and_target_27(self):
        retained, evidence = self.plan()
        self.assertEqual(len(retained),21)
        self.assertEqual(len(evidence['replaced_packages']),2)
        self.assertEqual(len(retained)+sum(len(c['packages']) for c in self.components),27)
        self.assertEqual([e[0] for e in retained], [p for p in self.packages if not p['filename'].startswith('ro-installer-')])

    def test_widgets_deferred_target_25(self):
        retained, _ = self.plan(self.components[:2])
        self.assertEqual(len(retained)+4,25)

    def test_duplicate_component_rejected(self):
        with self.assertRaisesRegex(rr.ContractError,'duplicate'):
            self.plan(self.components+[self.components[0]])

    def test_missing_source_rejected(self):
        self.components[1]['packages'].pop()
        with self.assertRaisesRegex(rr.ContractError,'SRPM'):
            self.plan()

    def test_wrong_noarch_architecture_rejected(self):
        self.components[2]['packages'][0]['item']['architecture']='x86_64'
        with self.assertRaisesRegex(rr.ContractError,'architecture'):
            self.plan()

    def test_installer_architecture_loss_rejected(self):
        self.components[0]['packages'][0]['item']['architecture']='aarch64'
        with self.assertRaises(rr.ContractError):
            self.plan()

    def test_signing_role_mismatch_rejected(self):
        self.manifest['rpm_signing_fingerprint']='C'*40
        with self.assertRaisesRegex(rr.ContractError,'signing roles'):
            self.plan()

    def test_parent_identity_mismatch_rejected(self):
        self.manifest['snapshot_id']='repo-f44-20261009-002'
        with self.assertRaisesRegex(rr.ContractError,'identity'):
            self.plan()

    def test_downgrade_and_same_version_rejected(self):
        for version in ['2.4.3','2.4.4']:
            components=copy.deepcopy(self.components)
            for package in components[0]['packages']:
                for key,value in package['item'].items():
                    if isinstance(value,str):
                        package['item'][key]=value.replace('2.4.5',version)
            with self.assertRaisesRegex(rr.ContractError,'downgrade'):
                self.plan(components)

    def test_widgets_policy_requires_desktop_evidence(self):
        policy=rr.resolve_component_policy(rr.load_producer_registry(rr.ROOT/'config/producers-v2.json'),
                                           'Project-Ro-ASD/ro-widgets','ro-widgets')
        self.assertEqual(policy['architectures'],['noarch'])
        self.assertEqual(policy['risk_class'],'critical-desktop')
        self.assertTrue({'plasma-integration','login-session'} <= set(policy['required_tests']))
        self.assertTrue(policy['srpm_required'])

    def test_normal_acceptance_rejects_mutable_or_wrong_release_before_download(self):
        workflow = yaml.safe_load((rr.ROOT/'.github/workflows/accept-component.yml').read_text())
        script = next(s['run'] for s in workflow['jobs']['accept']['steps']
                      if 'verify_identity.py' in s.get('run',''))
        source = script.split("cat << 'EOF' > verify_identity.py\n",1)[1].split('\nEOF',1)[0]
        source = source.split('release_asset_names =',1)[0]
        env = dict(PRODUCER='Project-Ro-ASD/ro-widgets', TAG='v0.1.1',
                   COMMIT='a'*40, RELEASE_ID='417136413')
        for mutable, release_id, message in [(False,417136413,'not natively immutable'),
                                              (True,417136414,'Release ID mismatch')]:
            responses = [json.dumps({'sha':'a'*40}).encode(), json.dumps(
                dict(id=release_id,tag_name='v0.1.1',draft=False,immutable=mutable)).encode()]
            with mock.patch.dict(os.environ,env), mock.patch.object(sys,'excepthook'), \
                 mock.patch('subprocess.check_output',side_effect=responses), \
                 mock.patch('subprocess.check_call') as download, \
                 mock.patch.object(rr,'write_acceptance_report'):
                with self.assertRaisesRegex(rr.ContractError,message):
                    exec(compile(source,'accept-component.yml','exec'),{})
                download.assert_not_called()

if __name__=='__main__':
    unittest.main()
