import pathlib
import unittest
import yaml

ROOT = pathlib.Path(__file__).parents[1]


class BackendWorkflowTests(unittest.TestCase):
    def test_all_eleven_production_jobs_unconditionally_disabled(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/v3-stable-promotion-disabled.yml").read_text())
        self.assertEqual(len(workflow["jobs"]), 11)
        for job in workflow["jobs"].values():
            self.assertEqual(job["if"], "${{ false }}")
        self.assertNotIn("inputs", workflow.get("on", {}).get("workflow_dispatch", {}) or {})

    def test_backend_workflow_has_no_publication_authority(self):
        raw = (ROOT / ".github/workflows/v3-backend-rehearsal.yml").read_text()
        workflow = yaml.safe_load(raw)
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        for job in workflow["jobs"].values():
            self.assertNotIn("environment", job)
            self.assertNotIn("permissions", job)
        for forbidden in ("secrets.", "id-token:", "deploy-pages", "git push", "pages-storage", "workflow_dispatch:"):
            self.assertNotIn(forbidden, raw)


if __name__ == "__main__":
    unittest.main()
