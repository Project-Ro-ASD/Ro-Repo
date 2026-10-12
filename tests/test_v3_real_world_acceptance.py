"""Regression contracts for bounded real-input acquisition and RPM status."""
import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from v3_pinned_upstream import trusted_rpm_status
from v3_promotion_planner import PlanningError
from v3_full_set_dnf import _config_result

spec = importlib.util.spec_from_file_location("real_acquisition", ROOT / "tests/v3-real-upstream-acquire.py")
acquisition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acquisition)


class RealAcceptanceTests(unittest.TestCase):
    def test_valid_signature_is_not_rejected_by_package_name(self):
        self.assertTrue(trusted_rpm_status("/tmp/gstreamer1-plugins-bad-free-libs.rpm: digests signatures OK\n"))
        self.assertTrue(trusted_rpm_status("/tmp/unsigned-name.rpm: digests signatures OK\n"))

    def test_bad_missing_and_ambiguous_signatures_remain_rejected(self):
        for output in ("/tmp/pkg.rpm: digests OK", "/tmp/pkg.rpm: digests signatures NOT OK",
                       "/tmp/pkg.rpm: digests signatures BAD", "/tmp/pkg.rpm: digests signatures NOKEY",
                       "/tmp/pkg.rpm: digests signatures OK\n/tmp/other.rpm: digests OK", "digests signatures OK"):
            with self.subTest(output=output):
                self.assertFalse(trusted_rpm_status(output))

    def test_acquisition_rejects_traversal_and_url_members(self):
        for path in (None, "", "../file", "/file", "a//b", "a/./b", "file:///outside", "%2e%2e/file", "a?x", "a#x", "a\\b", "a\nfile"):
            with self.subTest(path=path), self.assertRaises(PlanningError):
                acquisition.safe_relative(path)

    def test_acquisition_keeps_canonical_package_members(self):
        self.assertEqual(acquisition.safe_relative("Packages/g/gstreamer1-plugins-bad-free-libs-1.fc44.x86_64.rpm"),
                         "Packages/g/gstreamer1-plugins-bad-free-libs-1.fc44.x86_64.rpm")

    def test_acquisition_refuses_http_before_writing(self):
        from unittest import mock
        with mock.patch.object(acquisition.urllib.request, "build_opener") as opener:
            with self.assertRaises(PlanningError):
                acquisition.get("http://mirror.invalid/pkg.rpm", pathlib.Path("/tmp/unused-real-acquisition"))
            opener.assert_not_called()

    def test_unchanged_packaged_config_preserves_without_rpmnew(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            result = _config_result(pathlib.Path(root) / "config", "a" * 64, "a" * 64)
            self.assertTrue(result["rpmnew_not_required_unchanged_packaged_file"])

    def test_changed_packaged_config_still_requires_exact_rpmnew(self):
        import tempfile, hashlib
        with tempfile.TemporaryDirectory() as root:
            config = pathlib.Path(root) / "config"
            with self.assertRaises(PlanningError):
                _config_result(config, "a" * 64, "b" * 64)
            rpmnew = pathlib.Path(str(config) + ".rpmnew")
            rpmnew.write_bytes(b"wrong")
            with self.assertRaises(PlanningError):
                _config_result(config, "a" * 64, "b" * 64)
            expected = hashlib.sha256(b"wrong").hexdigest()
            self.assertEqual(_config_result(config, "a" * 64, expected)["rpmnew_sha256"], expected)

    def test_config_probe_rejects_rpmnew_symlinks(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            config = pathlib.Path(root) / "config"
            pathlib.Path(str(config) + ".rpmnew").symlink_to("/etc/passwd")
            with self.assertRaises(PlanningError):
                _config_result(config, "a" * 64, "a" * 64)


if __name__ == "__main__":
    unittest.main()
