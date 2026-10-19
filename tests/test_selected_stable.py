import copy
import pathlib
import sys
import unittest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import ro_repo as rr
import v2_selected_stable as selected


def entry(name, arch='x86_64', source='dolphin-1-1.fc44.src.rpm'):
    return ({'filename': f'{name}-1-1.fc44.{arch}.rpm'},
            {'name': name, 'architecture': arch, 'source_rpm': source,
             'epoch': 0, 'version': '1', 'release': '1.fc44'}, pathlib.Path('/test'))


class SelectedGroupTests(unittest.TestCase):
    def setUp(self):
        self.registry = rr.load_producer_registry(ROOT / 'config/producers-v2.json')
        self.entries = [entry(n) for n in ['dolphin', 'dolphin-libs', 'dolphin-devel']]
        self.entries += [entry('dolphin', 'src', None), entry('ro-assist', source='ro-assist-1-1.fc44.src.rpm')]

    def test_atomic_dolphin_and_srpm(self):
        result = selected.select_group(self.entries, self.registry, 'ro-kde-dolphin')
        self.assertEqual(len(result), 4)
        self.assertNotIn(self.entries[-1], result)

    def test_incomplete_binary_or_srpm_rejected(self):
        for index in range(4):
            with self.subTest(index=index), self.assertRaises(rr.ContractError):
                selected.select_group(self.entries[:index] + self.entries[index+1:], self.registry, 'ro-kde-dolphin')

    def test_partial_architecture_and_mixed_versions_rejected(self):
        values = copy.deepcopy(self.entries)
        values[1][1]['architecture'] = 'aarch64'
        with self.assertRaises(rr.ContractError):
            selected.select_group(values, self.registry, 'ro-kde-dolphin')
        values = copy.deepcopy(self.entries)
        values[1][1]['version'] = '2'
        with self.assertRaises(rr.ContractError):
            selected.select_group(values, self.registry, 'ro-kde-dolphin')

    def test_shared_source_and_unknown_group_rejected(self):
        values = self.entries + [entry('unregistered')]
        with self.assertRaises(rr.ContractError):
            selected.select_group(values, self.registry, 'ro-kde-dolphin')
        with self.assertRaises(rr.ContractError):
            selected.select_group(self.entries, self.registry, 'unknown')

    def test_noarch_paths(self):
        item = {'architecture': 'noarch', 'filename': 'a.rpm'}
        self.assertEqual([p.parent.name for p in selected.rpm_paths(pathlib.Path('/snapshot'), item)], ['x86_64', 'aarch64'])

    def test_all_v2_pages_writers_share_lock_and_commit_guard(self):
        for name in ['publish-pages-snapshot', 'publish-remote-beta', 'promote-remote-stable',
                     'rollback-remote-beta', 'rollback-remote-stable', 'promote-selected-stable']:
            text = (ROOT / f'.github/workflows/{name}.yml').read_text()
            workflow = yaml.safe_load(text)
            self.assertEqual(workflow['concurrency'], {'group': 'ro-repo-pages-storage', 'cancel-in-progress': False})
            self.assertIn('rev-parse FETCH_HEAD', text)
            self.assertNotIn('--force', text)

    def test_dispatch_contract_and_native_validation_before_publish(self):
        text = (ROOT / '.github/workflows/promote-selected-stable.yml').read_text()
        workflow = yaml.safe_load(text)
        self.assertEqual(list(workflow['on']), ['workflow_dispatch'])
        self.assertEqual(set(workflow['on']['workflow_dispatch']['inputs']), {'promotion_group', 'beta_snapshot_id', 'beta_publication_run', 'reason'})
        jobs = workflow['jobs']
        self.assertEqual(jobs['publish']['environment'], 'repo-stable')
        self.assertIn('validate', jobs['publish']['needs'])
        self.assertEqual(jobs['validate']['strategy']['matrix']['runner'], ['ubuntu-24.04', 'ubuntu-24.04-arm'])
        self.assertNotIn('v3_', (ROOT / 'tools/v2_selected_stable.py').read_text())


if __name__ == '__main__':
    unittest.main()
