"""visibility::1.0 conformance fixtures (specs/visibility.md)."""

from __future__ import annotations

import unittest

import visibility_fixtures as vf


def source(**fields: object) -> dict:
    return {"name": "Contoso_Audit_CL", "description": "Audit", "system": "sentinel", **fields}


class VisibilityFixtures(unittest.TestCase):
    def test_fixtures_conform(self) -> None:
        self.assertEqual(vf.check_visibility_fixtures(), [])

    def test_same_name_under_two_systems(self) -> None:
        doc = {"logsources": [source(), source(system="defender_for_endpoint")]}
        self.assertEqual(vf.errors(doc), [])

    def test_columns_on_a_wildcard_name(self) -> None:
        doc = {"logsources": [source(name="*_CL", columns={"TimeGenerated": {"type": "datetime"}})]}
        self.assertEqual(vf.errors(doc), [])

    def test_columns_need_the_system_type_set(self) -> None:
        doc = {"logsources": [source(system="splunk", columns={"x": {"type": "long"}})]}
        self.assertEqual(vf.errors(doc), ["column_type_unknown"])

    def test_former_singular_keys_are_unknown(self) -> None:
        for key in ("table", "index", "sourcetype", "macro", "data_view"):
            with self.subTest(key=key):
                self.assertEqual(vf.errors({"logsources": [source(**{key: "x"})]}), ["unknown_key"])


if __name__ == "__main__":
    unittest.main()
