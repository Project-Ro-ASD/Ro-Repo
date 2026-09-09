import unittest
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]

class PolicyTests(unittest.TestCase):
    def test_no_gpgcheck_zero(self):
        pattern = re.compile(r'gpgcheck\s*=\s*0')
        violations = []
        for path in ROOT.rglob('*'):
            if not path.is_file(): continue
            if path.parent.name in ('.git', '__pycache__', 'accepted', 'incoming', 'out', 'fixtures', 'tests'): continue
            if path.suffix in ('.pyc', '.rpm'): continue
            if path.name == 'test_policy.py': continue
            
            try:
                content = path.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                continue
                
            for line_idx, line in enumerate(content.splitlines()):
                if pattern.search(line):
                    # Exception for the README.md documentation
                    if path.name == 'README.md' and "`gpgcheck=0` kullanan V1" in line:
                        continue
                    # Also skip if it is inside test.yml's old grep (we'll remove this soon)
                    if path.name == 'test.yml' and 'grep' in line:
                        continue
                    violations.append(f"{path.relative_to(ROOT)}:{line_idx+1}: {line.strip()}")
                    
        self.assertEqual(violations, [], "Found forbidden gpgcheck=0 configurations")

    def test_no_implicit_latest_downloads(self):
        violations = []
        for path in ROOT.rglob('*'):
            if not path.is_file(): continue
            if path.parent.name in ('.git', '__pycache__', 'out', 'fixtures', 'tests'): continue
            if path.name == 'test_policy.py': continue
            
            try:
                content = path.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                continue
                
            for line_idx, line in enumerate(content.splitlines()):
                if 'gh release download' in line:
                    if 'grep' in line: continue # skip the old bad grep in test.yml
                    if re.search(r'gh release download\s+latest', line) or re.search(r'gh release download\s+(--repo|-R)', line) or re.search(r'gh release download\s*$', line):
                        violations.append(f"{path.relative_to(ROOT)}:{line_idx+1}: {line.strip()}")
                        
        self.assertEqual(violations, [], "Found forbidden implicit latest gh release download")

if __name__ == '__main__':
    unittest.main()
