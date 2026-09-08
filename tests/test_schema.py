import unittest
import pathlib
import json
import jsonschema

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

if __name__ == '__main__':
    unittest.main()
