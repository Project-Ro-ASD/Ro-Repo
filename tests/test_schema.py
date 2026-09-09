import unittest
import pathlib
import json
import jsonschema
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
from tools import ro_repo

class SchemaTests(unittest.TestCase):
    def test_invalid_manifest_rejected(self):
        data = {"schema_version": 1} # missing component, source_repository, etc.
        with self.assertRaisesRegex(ro_repo.ContractError, "schema validation failed"):
            ro_repo.validate_schema(data, "component-artifact-manifest-v1")
            
    def test_invalid_type_rejected(self):
        data = {"schema_version": "1"} # should be integer
        with self.assertRaisesRegex(ro_repo.ContractError, "schema validation failed"):
            ro_repo.validate_schema(data, "component-artifact-manifest-v1")

    def test_additional_properties_rejected(self):
        data = {
            "schema_version": 1,
            "component": "test",
            "source_repository": "test/test",
            "source_commit": "a"*40,
            "release_tag": "v1",
            "release_id": "1",
            "workflow_run": "1",
            "fedora_release": 44,
            "artifacts": [],
            "provenance": {"provider": "test", "subject_digest": "test"},
            "attestation": {"provider": "test", "verification": "test"},
            "sbom": None,
            "extra_property_not_in_schema": "forbidden"
        }
        with self.assertRaisesRegex(ro_repo.ContractError, "schema validation failed"):
            ro_repo.validate_schema(data, "component-artifact-manifest-v1")

    def test_invalid_date_time_rejected(self):
        data = {
            "schema_version": 1,
            "snapshot_id": "repo-f44-20260908-001",
            "from": "beta",
            "to": "stable",
            "risk_class": "normal-app",
            "promotion_group": "ro-control",
            "beta_started_at": "not-a-date-time",
            "evidence": [],
            "approved_by": "test",
            "approved_at": "2026-09-08", # Missing time/timezone
            "emergency": False
        }
        with self.assertRaisesRegex(ro_repo.ContractError, "schema validation failed"):
            ro_repo.validate_schema(data, "promotion-manifest-v1")

if __name__ == '__main__':
    unittest.main()
