from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).parents[1]

SPEC = importlib.util.spec_from_file_location(
    "verify_attested_attempt",
    ROOT / "scripts" / "verify_attested_attempt.py",
)
assert SPEC and SPEC.loader
verify_attempt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_attempt)


class AcceptanceRuntimeTests(unittest.TestCase):
    def valid_attempt(self):
        return {
            "id": 37451969709,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "event": "push",
            "head_sha": "e47d387e9a81d17aa76c4ea78382dda3c87cf20e",
            "head_branch": "v2.4.4",
            "path": ".github/workflows/release.yml",
            "repository": {"full_name": "Project-Ro-ASD/ro-Installer"},
            "head_repository": {"full_name": "Project-Ro-ASD/ro-Installer"},
        }

    def validate(self, data):
        return verify_attempt.validate_attempt(
            data,
            producer="Project-Ro-ASD/ro-Installer",
            tag="v2.4.4",
            commit="e47d387e9a81d17aa76c4ea78382dda3c87cf20e",
            workflow_path="Project-Ro-ASD/ro-Installer/.github/workflows/release.yml",
            run_id=37451969709,
            attempt=1,
        )

    def test_exact_attempt_contract_accepts(self):
        self.validate(self.valid_attempt())

    def test_exact_attempt_contract_rejects_identity_fields(self):
        mutations = {
            "id": 9,
            "run_attempt": 2,
            "path": ".github/workflows/other.yml",
            "repository": {"full_name": "Project-Ro-ASD/other"},
            "head_repository": {"full_name": "Project-Ro-ASD/other"},
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                data = self.valid_attempt()
                data[field] = value
                with self.assertRaisesRegex(Exception, "mismatch"):
                    self.validate(data)

    def test_exact_attempt_contract_rejects_execution_fields(self):
        mutations = {
            "status": "in_progress",
            "conclusion": "failure",
            "event": "workflow_dispatch",
            "head_sha": "a" * 40,
            "head_branch": "main",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                data = self.valid_attempt()
                data[field] = value
                with self.assertRaisesRegex(Exception, "mismatch"):
                    self.validate(data)

    def test_bootstrap_report_is_schema_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = pathlib.Path(tmp) / "report.json"
            subprocess.check_call([
                "bash",
                str(ROOT / "scripts" / "init_acceptance_report.sh"),
                "Project-Ro-ASD/ro-Installer",
                "v2.4.4",
                "e47d387e9a81d17aa76c4ea78382dda3c87cf20e",
                "404599015",
                str(report),
            ])
            data = json.loads(report.read_text(encoding="utf-8"))
            import sys
            sys.path.insert(0, str(ROOT / "tools"))
            import ro_repo
            ro_repo.validate_schema(data, "acceptance-report-v1")
            self.assertEqual(data["error_code"], "ACCEPTANCE_ORCHESTRATION_FAILED")


if __name__ == "__main__":
    unittest.main()
