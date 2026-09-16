#!/usr/bin/env python3
"""Unit and fixture tests for threat::1.0 field types and encoding rules."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from object_fixtures import (
    EXPECTED_INVALID_CODES,
    CheckError,
    load_vocabularies,
    load_yaml,
    validate_document,
    validate_fixture_file,
    validate_threat,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
VOCAB_DIR = ROOT / "vocabularies"


def _codes(errors: list[CheckError]) -> set[str]:
    return {item.code for item in errors}


class ThreatFixtureTests(unittest.TestCase):
    vocabs = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.vocabs = load_vocabularies(VOCAB_DIR)
        cls.valid = load_yaml(FIXTURES / "valid" / "threat-1.0.yaml")

    def test_vocab_index_loads_required_fields(self) -> None:
        for field_name in (
            "impact",
            "leverage",
            "severity",
            "viability",
            "criticality",
            "surface",
            "att&ck",
            "actors",
            "tlp",
        ):
            self.assertIn(field_name, self.vocabs)

    def test_scoped_actor_tokens_exist(self) -> None:
        actors = self.vocabs["actors"]
        self.assertTrue(actors.has_scoped("att&ck::G0007"))
        self.assertTrue(actors.has_scoped("misp::5b4ee3ea-eee3-4c8e-8323-85ae32658754"))
        self.assertFalse(actors.has_scoped("G0007"))
        self.assertFalse(actors.has_scoped("misp::G0007"))
        self.assertFalse(actors.has_unscoped("att&ck::G0007"))

    def test_valid_threat_fixture_passes(self) -> None:
        errors = validate_threat(self.valid, self.vocabs)
        self.assertEqual(errors, [], msg=[item.format() for item in errors])

    def test_valid_threat_uses_lists_and_actor_objects(self) -> None:
        body = self.valid["threat"]
        self.assertIsInstance(body["impact"], list)
        self.assertGreaterEqual(len(body["impact"]), 2)
        self.assertIsInstance(body["leverage"], list)
        self.assertGreaterEqual(len(body["leverage"]), 2)
        self.assertIsInstance(body["actors"], list)
        self.assertGreaterEqual(len(body["actors"]), 2)
        self.assertTrue(all(isinstance(item, dict) for item in body["actors"]))
        self.assertTrue(all("name" in item for item in body["actors"]))
        self.assertNotIn(";", "".join(body["impact"]))
        self.assertNotIn(";", "".join(body["leverage"]))

    def test_valid_threat_uses_real_vocab_tokens(self) -> None:
        body = self.valid["threat"]
        self.assertIn("Data Breach", body["impact"])
        self.assertIn("Identity Theft", body["impact"])
        self.assertIn("Elevation of privilege", body["leverage"])
        self.assertIn("Repudiation", body["leverage"])
        self.assertIn(body["severity"], self.vocabs["severity"].identities())
        self.assertIn(body["viability"], self.vocabs["viability"].identities())
        self.assertNotEqual(body["leverage"], ["High"])
        self.assertNotEqual(body["severity"], "High")
        self.assertNotEqual(body["viability"], "High")

    def test_impact_scalar_string_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["impact"] = "Data Breach"
        self.assertIn("field_not_list", _codes(validate_threat(doc, self.vocabs)))

    def test_leverage_scalar_without_semicolon_is_still_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["leverage"] = "Elevation of privilege"
        self.assertIn("field_not_list", _codes(validate_threat(doc, self.vocabs)))

    def test_semicolon_packed_string_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["leverage"] = "Elevation of privilege; Repudiation"
        self.assertIn("packed_vocab_string", _codes(validate_threat(doc, self.vocabs)))

    def test_semicolon_packed_list_item_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["impact"] = ["Data Breach; Identity Theft"]
        self.assertIn("packed_vocab_string", _codes(validate_threat(doc, self.vocabs)))

    def test_empty_impact_list_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["impact"] = []
        self.assertIn("empty_vocab_list", _codes(validate_threat(doc, self.vocabs)))

    def test_empty_leverage_list_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["leverage"] = []
        self.assertIn("empty_vocab_list", _codes(validate_threat(doc, self.vocabs)))

    def test_impact_semicolon_packed_scalar_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["impact"] = "Data Breach; Identity Theft"
        self.assertIn("packed_vocab_string", _codes(validate_threat(doc, self.vocabs)))

    def test_unknown_impact_token_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["impact"] = ["High"]
        self.assertIn("unknown_vocab_value", _codes(validate_threat(doc, self.vocabs)))

    def test_unknown_leverage_high_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["leverage"] = ["High"]
        self.assertIn("unknown_vocab_value", _codes(validate_threat(doc, self.vocabs)))

    def test_unknown_severity_high_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["severity"] = "High"
        self.assertIn("unknown_vocab_value", _codes(validate_threat(doc, self.vocabs)))

    def test_unknown_viability_high_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["viability"] = "High"
        self.assertIn("unknown_vocab_value", _codes(validate_threat(doc, self.vocabs)))

    def test_packed_string_is_not_the_split_token_list(self) -> None:
        """Packed catalogue strings MUST fail; first-token collapse is a different document."""
        packed = "Elevation of privilege; Repudiation; Tampering"
        split_tokens = [token.strip() for token in packed.split(";") if token.strip()]
        first_only = [split_tokens[0]]
        packed_doc = copy.deepcopy(self.valid)
        packed_doc["threat"]["leverage"] = packed
        self.assertIn("packed_vocab_string", _codes(validate_threat(packed_doc, self.vocabs)))

        collapsed_doc = copy.deepcopy(self.valid)
        collapsed_doc["threat"]["leverage"] = first_only
        self.assertEqual(validate_threat(collapsed_doc, self.vocabs), [])
        self.assertNotEqual(first_only, split_tokens)

        migrated_doc = copy.deepcopy(self.valid)
        migrated_doc["threat"]["leverage"] = split_tokens
        self.assertEqual(validate_threat(migrated_doc, self.vocabs), [])
        self.assertNotEqual(packed_doc["threat"]["leverage"], migrated_doc["threat"]["leverage"])

    def test_null_impact_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["impact"] = None
        self.assertIn("field_not_list", _codes(validate_threat(doc, self.vocabs)))

    def test_actors_mapping_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["actors"] = {"name": "att&ck::G0007"}
        self.assertIn("actors_not_objects", _codes(validate_threat(doc, self.vocabs)))

    def test_invalid_tlp_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["metadata"]["tlp"] = "not-a-tlp"
        self.assertIn("unknown_vocab_value", _codes(validate_threat(doc, self.vocabs)))

    def test_actors_string_list_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["actors"] = ["att&ck::G0007"]
        self.assertIn("actors_not_objects", _codes(validate_threat(doc, self.vocabs)))

    def test_actor_missing_name_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["actors"] = [{"sighting": "2024-11-02"}]
        self.assertIn("actor_missing_name", _codes(validate_threat(doc, self.vocabs)))

    def test_actor_unscoped_name_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["actors"] = [{"name": "G0007"}]
        self.assertIn("actor_unscoped", _codes(validate_threat(doc, self.vocabs)))

    def test_actor_wrong_stage_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["actors"] = [{"name": "misp::G0007"}]
        self.assertIn("actor_unknown", _codes(validate_threat(doc, self.vocabs)))

    def test_actor_unknown_id_is_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["actors"] = [{"name": "att&ck::G9999"}]
        self.assertIn("actor_unknown", _codes(validate_threat(doc, self.vocabs)))

    def test_empty_actors_list_is_allowed(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["actors"] = []
        self.assertEqual(validate_threat(doc, self.vocabs), [])

    def test_omitted_actors_is_allowed(self) -> None:
        doc = copy.deepcopy(self.valid)
        del doc["threat"]["actors"]
        self.assertEqual(validate_threat(doc, self.vocabs), [])

    def test_actor_optional_fields_types(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["actors"] = [
            {"name": "att&ck::G0007", "references": "https://example.invalid"}
        ]
        self.assertIn("invalid_actor_references", _codes(validate_threat(doc, self.vocabs)))
        doc["threat"]["actors"] = [{"name": "att&ck::G0007", "sighting": 2024}]
        self.assertIn("invalid_actor_sighting", _codes(validate_threat(doc, self.vocabs)))

    def test_missing_threat_body(self) -> None:
        doc = copy.deepcopy(self.valid)
        del doc["threat"]
        self.assertIn("missing_threat_body", _codes(validate_threat(doc, self.vocabs)))

    def test_unknown_attck_id(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["att&ck"] = ["not-a-technique"]
        self.assertIn("unknown_vocab_value", _codes(validate_threat(doc, self.vocabs)))

    def test_empty_surface_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["threat"]["surface"] = []
        self.assertIn("empty_vocab_list", _codes(validate_threat(doc, self.vocabs)))

    def test_bad_uuid_rejected(self) -> None:
        doc = copy.deepcopy(self.valid)
        doc["metadata"]["uuid"] = "not-a-valid-uuid"
        self.assertIn("invalid_uuid", _codes(validate_threat(doc, self.vocabs)))

    def test_non_mapping_document(self) -> None:
        errors = validate_document(["not", "an", "object"], self.vocabs)
        self.assertIn("invalid_yaml", _codes(errors))


class InvalidFixtureRegistryTests(unittest.TestCase):
    vocabs = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.vocabs = load_vocabularies(VOCAB_DIR)

    def test_every_invalid_yaml_has_an_expected_code(self) -> None:
        names = {path.name for path in (FIXTURES / "invalid").glob("*.yaml")}
        self.assertEqual(names, set(EXPECTED_INVALID_CODES))

    def test_invalid_fixtures_fail_with_expected_code(self) -> None:
        for name, expected in EXPECTED_INVALID_CODES.items():
            with self.subTest(name=name):
                issues = validate_fixture_file(FIXTURES / "invalid" / name, self.vocabs)
                self.assertTrue(issues, msg=f"{name} passed")
                self.assertIn(expected, _codes(issues), msg=[item.format() for item in issues])

    def test_valid_and_cross_object_fixtures_pass_structural_checks(self) -> None:
        for directory in (FIXTURES / "valid", FIXTURES / "cross-object"):
            for path in directory.glob("*.yaml"):
                with self.subTest(path=str(path.relative_to(ROOT))):
                    issues = validate_fixture_file(path, self.vocabs)
                    self.assertEqual(issues, [], msg=[item.format() for item in issues])

    def test_invalid_threat_yaml_covers_list_and_actor_encodings(self) -> None:
        required = {
            "threat-impact-as-string.yaml",
            "threat-impact-semicolon.yaml",
            "threat-leverage-semicolon.yaml",
            "threat-leverage-semicolon-list-item.yaml",
            "threat-impact-empty.yaml",
            "threat-leverage-empty.yaml",
            "threat-leverage-high.yaml",
            "threat-actors-string-list.yaml",
            "threat-actors-not-list.yaml",
            "threat-actor-missing-name.yaml",
            "threat-actor-unscoped.yaml",
            "threat-actor-wrong-stage.yaml",
        }
        present = {path.name for path in (FIXTURES / "invalid").glob("threat-*.yaml")}
        self.assertTrue(required.issubset(present), msg=sorted(required - present))


class ValidateScriptTests(unittest.TestCase):
    def test_repo_validate_script_passes(self) -> None:
        import validate as validate_script

        self.assertEqual(validate_script.main(), 0)


if __name__ == "__main__":
    unittest.main()
