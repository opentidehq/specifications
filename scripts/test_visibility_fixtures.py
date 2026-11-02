"""visibility::1.0 conformance fixtures (specs/visibility.md)."""

from __future__ import annotations

import unittest

import visibility_fixtures as vf


class VisibilityFixtures(unittest.TestCase):
    def test_fixtures_conform(self) -> None:
        self.assertEqual(vf.check_visibility_fixtures(), [])

    def test_default_name_is_the_dataset(self) -> None:
        self.assertEqual(vf.dataset({"table": "SigninLogs"}), "SigninLogs")
        self.assertEqual(vf.dataset({"index": "main", "sourcetype": "st"}), "main:st")

    def test_same_name_under_two_systems(self) -> None:
        doc = {
            "logsources": [
                {"system": "sentinel", "table": "DeviceEvents"},
                {"system": "defender_for_endpoint", "table": "DeviceEvents"},
            ]
        }
        self.assertEqual(vf.errors(doc), [])

    def test_columns_need_the_system_type_set(self) -> None:
        source = {"system": "splunk", "index": "main", "columns": [{"name": "x", "type": "long"}]}
        self.assertEqual(vf.errors({"logsources": [source]}), ["column_type_unknown"])

    def test_single_dataset_keeps_its_name(self) -> None:
        doc = {"logsources": [{"name": "Sign-ins", "system": "sentinel", "tables": ["SigninLogs"]}]}
        migrated, renamed = vf.migrate(doc)
        self.assertEqual(migrated["logsources"], [{"system": "sentinel", "table": "SigninLogs", "name": "Sign-ins"}])
        self.assertEqual(renamed, {})


if __name__ == "__main__":
    unittest.main()
