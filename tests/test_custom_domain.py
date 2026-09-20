import pathlib
import unittest
import yaml


class CustomDomainWorkflowTests(unittest.TestCase):
    def test_custom_domain_workflow_contract(self):
        root = pathlib.Path(__file__).parents[1]
        path = root / ".github/workflows/verify-pages-domain.yml"
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)

        self.assertIn("workflow_dispatch", data["on"])
        self.assertEqual(data["permissions"]["contents"], "read")
        self.assertIn("verify-domain", data["jobs"])

        self.assertIn("repo.ro-asd.org", text)
        self.assertIn("project-ro-asd.github.io.", text)
        self.assertIn("pages-storage", text)
        self.assertIn("CNAME", text)
        self.assertIn("curl", text)
        self.assertIn("gpg --batch --verify", text)

        self.assertNotIn("secrets.", text)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("pages: write", text)

    def test_custom_domain_workflow_does_not_publish_channels(self):
        root = pathlib.Path(__file__).parents[1]
        text = (
            root / ".github/workflows/verify-pages-domain.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("publish-local", text)
        self.assertNotIn("promote-snapshot", text)
        self.assertNotIn("rollback-publication", text)


if __name__ == "__main__":
    unittest.main()
