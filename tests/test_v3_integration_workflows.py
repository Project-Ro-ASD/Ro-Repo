import pathlib
import unittest
import yaml
import json
import jsonschema
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


class WorkflowBoundaryTests(unittest.TestCase):
    def test_compatibility_evidence_accepts_relative_output_with_temporary_snapshot(self):
        script = (ROOT / "tests/e2e-local.sh").read_text()
        block = script.split('if [ -n "$evidence_out" ]; then\n', 1)[1]
        code = block.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as temp:
            work = pathlib.Path(temp)
            snapshot = work / "temporary-snapshots/repo-f44-20261011-001"
            snapshot.mkdir(parents=True)
            (snapshot / "repository-snapshot-v1.json").write_text('{"fixture": true}')
            subprocess.run([sys.executable, "-c", code, str(snapshot), "compatibility-evidence.json"],
                           cwd=work, check=True, capture_output=True)
            report = json.loads((work / "compatibility-evidence.json").read_text())
            self.assertEqual(report["reference"], "snapshot:repo-f44-20261011-001/repository-snapshot-v1.json")

    def test_all_schemas_and_workflows_parse(self):
        for path in (ROOT / "schemas").glob("*.schema.json"):
            with self.subTest(schema=path.name):
                jsonschema.Draft202012Validator.check_schema(json.loads(path.read_text()))
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            with self.subTest(workflow=path.name):
                value = yaml.safe_load(path.read_text())
                self.assertIsInstance(value["jobs"], dict)
    def test_all_production_stages_are_unconditionally_disabled(self):
        path = ROOT / ".github/workflows/v3-stable-promotion-disabled.yml"
        value = yaml.safe_load(path.read_text())
        self.assertEqual(value["permissions"], {"contents": "read"})
        self.assertEqual(set(value["on"]), {"workflow_dispatch"})
        self.assertEqual(len(value["jobs"]), 11)
        for name, job in value["jobs"].items():
            with self.subTest(job=name):
                self.assertEqual(job["if"], "${{ false }}")
                self.assertNotIn("permissions", job)
                self.assertEqual(job["steps"], [{"run": "exit 1"}])
        self.assertNotIn("secrets.", path.read_text())

    def test_fixture_ci_has_no_production_authority(self):
        value = yaml.safe_load((ROOT / ".github/workflows/v3-integration-tests.yml").read_text())
        self.assertEqual(value["permissions"], {"contents": "read"})
        self.assertNotIn("workflow_dispatch", value["on"])
        for job in value["jobs"].values():
            self.assertNotIn("environment", job)
            self.assertNotIn("permissions", job)
            for step in job["steps"]:
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertIs(step["with"]["persist-credentials"], False)


if __name__ == "__main__":
    unittest.main()
