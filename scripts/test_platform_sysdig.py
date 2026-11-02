#!/usr/bin/env python3
"""Consistency tests for specs/platforms/sysdig-1.0.md, its fixtures, and the specs that list Sysdig.

The generated Falco file and API body under fixtures/platforms/sysdig/ are the
goldens implementations compare against. These tests check that they follow the
spec's derivations from their source rule fixtures (priority, tags, desc, and
expansion of the block's own lists), so a golden cannot drift from the text.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from typing import Any

import yaml

from object_fixtures import (
    EXPECTED_INVALID_CODES,
    load_vocabularies,
    validate_fixture_file,
    validate_sysdig_block,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specs" / "platforms" / "sysdig-1.0.md"
INDEX = ROOT / "specs" / "platforms" / "index.md"
FIXTURES = ROOT / "fixtures"
GOLDEN = FIXTURES / "platforms" / "sysdig"
SECTIONS = ["Summary", "Requirements", "Definition", "Relationships", "Defaults & overrides", "Examples", "History"]

PRIORITY = {
    "Critical": ("CRITICAL", "critical"),
    "High": ("ERROR", "error"),
    "Medium": ("WARNING", "warning"),
    "Low": ("NOTICE", "notice"),
    "Informational": ("INFORMATIONAL", "info"),
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _codes(errors: list[Any]) -> set[str]:
    return {error.code for error in errors}


def _block(**keys: Any) -> dict[str, Any]:
    return {"enabled": True, "schema": "platform::sysdig::1.0", "status": "STAGING", **keys}


def _constraint_codes(text: str) -> list[str]:
    section = text[text.index("### Constraints") : text.index("### Falco language")]
    return re.findall(r"^\| `(sysdig_[a-z_]+)` \|", section, flags=re.MULTILINE)


class SpecShapeTests(unittest.TestCase):
    def test_frontmatter_and_sections(self) -> None:
        text = _read(SPEC)
        self.assertIn("schema_id: platform::sysdig::1.0", text)
        self.assertIn("status: normative", text)
        headings = re.findall(r"^## (.+)$", text, flags=re.MULTILINE)
        self.assertEqual(headings, SECTIONS)

    def test_constraint_table_is_complete(self) -> None:
        self.assertEqual(
            _constraint_codes(_read(SPEC)),
            [
                "sysdig_rule_shape",
                "sysdig_tuning_keys",
                "sysdig_priority",
                "sysdig_source",
                "sysdig_exception_shape",
                "sysdig_definition_name",
                "sysdig_definition_duplicate",
                "sysdig_definition_cycle",
            ],
        )

    def test_priority_table_matches(self) -> None:
        section = _read(SPEC).split("### Priority", 1)[1].split("###", 1)[0]
        for severity, (falco, api) in PRIORITY.items():
            self.assertIn(f"| `{severity}` | `{falco}` | `{api}` |", section)


class ListingTests(unittest.TestCase):
    def test_platform_index(self) -> None:
        text = _read(INDEX)
        self.assertIn("opentide ships nine detection platform integrations.", text)
        self.assertIn("| `sysdig` | `platform::sysdig::1.0` | [sysdig-1.0.md](sysdig-1.0.md) |", text)
        self.assertIn("| `sysdig` | Sysdig Secure | yes* | **no**‡ | Falco condition |", text)
        self.assertIn("Excluded: `crowdstrike`, `harfanglab`, `sysdig`.", text)

    def test_spec_index_and_llms(self) -> None:
        self.assertIn("[specs/platforms/sysdig-1.0.md](specs/platforms/sysdig-1.0.md)", _read(ROOT / "SPECS.md"))
        self.assertIn("specs/platforms/sysdig-1.0.md (schema_id: platform::sysdig::1.0)", _read(ROOT / "llms.txt"))
        self.assertIn("[0014](0014-sysdig-falco-platform.md)", _read(ROOT / "rfcs" / "README.md"))

    def test_rule_specs_list_the_block(self) -> None:
        for name in ("rule-1.0.md", "rule-1.1.md"):
            text = _read(ROOT / "specs" / "objects" / name)
            self.assertIn("| `sysdig` | SysdigConfig | `platform::sysdig::1.0` |", text)

    def test_validation_excludes_sysdig(self) -> None:
        self.assertIn("| `sysdig` | no.", _read(ROOT / "specs" / "validation.md"))

    def test_deployment_state_accepts_sysdig_decimal_ids(self) -> None:
        schema = json.loads(_read(ROOT / "schemas" / "deployment.state.1.0.schema.json"))
        self.assertEqual(schema["properties"]["platforms"]["properties"]["sysdig"], {"$ref": "#/$defs/decimalTenants"})
        self.assertIn("| `sysdig` | Canonical decimal integer as a string.", _read(ROOT / "specs" / "deployment-state.md"))


class CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vocabs = load_vocabularies(ROOT / "vocabularies")

    def test_valid_fixtures_pass(self) -> None:
        for path in (
            FIXTURES / "platforms" / "sysdig.yaml",
            FIXTURES / "valid" / "rule-sysdig-1.0.yaml",
            FIXTURES / "valid" / "rule-sysdig-tuning-1.0.yaml",
        ):
            with self.subTest(path=path.name):
                self.assertEqual(validate_fixture_file(path, self.vocabs), [])

    def test_invalid_fixture_codes(self) -> None:
        path = FIXTURES / "invalid" / "rule-sysdig-tuning-output.yaml"
        self.assertEqual(EXPECTED_INVALID_CODES[path.name], "sysdig_tuning_keys")
        self.assertEqual(
            _codes(validate_fixture_file(path, self.vocabs)), {"sysdig_tuning_keys", "sysdig_exception_shape"}
        )

    def test_rule_shape(self) -> None:
        self.assertEqual(_codes(validate_sysdig_block(_block())), {"sysdig_rule_shape"})
        self.assertEqual(_codes(validate_sysdig_block(_block(condition="  "))), {"sysdig_rule_shape"})
        self.assertEqual(_codes(validate_sysdig_block(_block(append_to_rule="X"))), {"sysdig_rule_shape"})
        self.assertEqual(_codes(validate_sysdig_block(_block(append_to_rule="X", condition="and not a"))), set())
        tuning = _block(append_to_rule="X", exceptions=[{"name": "e", "fields": "proc.name", "values": ["sh"]}])
        self.assertEqual(_codes(validate_sysdig_block(tuning)), set())

    def test_tuning_keys(self) -> None:
        for key, value in (("output", "o"), ("priority", "ERROR"), ("policies", ["p"]), ("source", "syscall"), ("name", "n")):
            with self.subTest(key=key):
                block = _block(append_to_rule="X", condition="and not a", **{key: value})
                self.assertEqual(_codes(validate_sysdig_block(block)), {"sysdig_tuning_keys"})

    def test_priority(self) -> None:
        for value in ("warning", "INFO", "Informational", "DEBUG"):
            self.assertEqual(_codes(validate_sysdig_block(_block(condition="a", priority=value))), set())
        for value in ("HIGH", "", 4):
            self.assertEqual(_codes(validate_sysdig_block(_block(condition="a", priority=value))), {"sysdig_priority"})

    def test_source(self) -> None:
        for value in ("syscall", "k8s_audit", "aws_cloudtrail", "my_plugin2"):
            self.assertEqual(_codes(validate_sysdig_block(_block(condition="a", source=value))), set())
        for value in ("Syscall", "k8s-audit", "", "1src"):
            self.assertEqual(_codes(validate_sysdig_block(_block(condition="a", source=value))), {"sysdig_source"})

    def test_exception_shapes(self) -> None:
        ok = [
            {"name": "a", "fields": ["proc.name", "proc.pname"], "values": [["sh", "bash"]]},
            {"name": "b", "fields": ["proc.name", "proc.pname"], "comps": ["=", "in"], "values": [["sh", ["bash", "zsh"]]]},
            {"name": "c", "fields": "proc.name", "values": ["sh", "bash"]},
            {"name": "d", "fields": "proc.name", "comps": "pmatch", "values": ["/tmp"]},
            {"name": "e", "fields": ["fd.name"]},
        ]
        self.assertEqual(_codes(validate_sysdig_block(_block(condition="a", exceptions=ok))), set())
        bad = [
            {"name": "", "fields": "proc.name"},
            {"name": "x", "fields": ["proc.name"], "comps": ["=", "="]},
            {"name": "x", "fields": ["proc.name", "proc.name"]},
            {"name": "x", "fields": ["proc.name"], "comps": ["~"]},
            {"name": "x", "fields": ["proc.name", "proc.pname"], "values": [["sh"]]},
            {"name": "x", "fields": ["proc.name"], "comps": ["in"], "values": [["sh"]]},
            {"name": "x", "fields": "proc.name", "comps": "="},
            {"name": "x", "fields": "proc.name", "values": [["sh"]]},
            {"name": "x", "fields": []},
        ]
        for exc in bad:
            with self.subTest(exc=exc):
                self.assertEqual(
                    _codes(validate_sysdig_block(_block(condition="a", exceptions=[exc]))), {"sysdig_exception_shape"}
                )
        duplicate = [{"name": "a", "fields": "proc.name"}, {"name": "a", "fields": "proc.pname"}]
        self.assertEqual(
            _codes(validate_sysdig_block(_block(condition="a", exceptions=duplicate))), {"sysdig_exception_shape"}
        )

    def test_definitions(self) -> None:
        for name in ("in", "and", "1abc", "has-dash", "contains"):
            with self.subTest(name=name):
                block = _block(condition="a", macros=[{"name": name, "condition": "b"}])
                self.assertEqual(_codes(validate_sysdig_block(block)), {"sysdig_definition_name"})
        block = _block(
            condition="a",
            macros=[{"name": "shared", "condition": "b"}],
            lists=[{"name": "shared", "items": ["c"]}],
        )
        self.assertEqual(_codes(validate_sysdig_block(block)), {"sysdig_definition_duplicate"})


class GoldenTests(unittest.TestCase):
    def _pair(self, stem: str) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
        rule = yaml.safe_load(_read(FIXTURES / "valid" / f"{stem}.yaml"))
        text = _read(GOLDEN / f"{stem}.falco.yaml")
        return rule, text, yaml.safe_load(text)

    def test_header_names_the_rule(self) -> None:
        for stem in ("rule-sysdig-1.0", "rule-sysdig-tuning-1.0"):
            rule, text, _ = self._pair(stem)
            self.assertTrue(text.startswith(f"# Generated by opentide from rule {rule['metadata']['uuid']}. Do not edit"))
            self.assertTrue(text.endswith("\n") and "\r" not in text)

    def test_new_rule_derivations(self) -> None:
        rule, _, items = self._pair("rule-sysdig-1.0")
        block = rule["configurations"]["sysdig"]
        (item,) = items
        self.assertEqual(item["rule"], rule["name"])
        self.assertEqual(item["desc"], " ".join(rule["description"].split()))
        self.assertEqual(item["priority"], PRIORITY[rule["response"]["alert_severity"]][0])
        self.assertEqual(item["source"], block["source"])
        self.assertIs(item["enabled"], True)
        self.assertEqual(item["output"], " ".join(block["output"].split()))
        # Block tags, technique, tactic, maturity for a PREVIEW strategy (STAGING).
        self.assertEqual(item["tags"], [*block["tags"], "T1059.004", "mitre_execution", "maturity_incubating"])
        self.assertEqual(item["exceptions"], block["exceptions"])
        self.assertNotIn("lists", item)
        self.assertNotIn("macros", item)

    def test_lists_are_expanded(self) -> None:
        rule, text, items = self._pair("rule-sysdig-1.0")
        block = rule["configurations"]["sysdig"]
        for definition in block["lists"]:
            self.assertNotRegex(items[0]["condition"], rf"\b{definition['name']}\b")
            self.assertIn(", ".join(definition["items"]), items[0]["condition"])
        self.assertNotIn("- list:", text)
        self.assertNotIn("- macro:", text)
        expected = " ".join(block["condition"].split())
        for definition in block["lists"]:
            expected = expected.replace(definition["name"], ", ".join(definition["items"]))
        self.assertEqual(items[0]["condition"], expected)

    def test_tuning(self) -> None:
        rule, _, items = self._pair("rule-sysdig-tuning-1.0")
        block = rule["configurations"]["sysdig"]
        (item,) = items
        self.assertEqual(item["rule"], block["append_to_rule"])
        self.assertEqual(item["condition"], "and not proc.pname in (gitlab-runner, buildkite-agent)")
        self.assertEqual(item["exceptions"], block["exceptions"])
        self.assertEqual(item["override"], {"condition": "append", "exceptions": "append"})
        for key in ("desc", "priority", "output", "tags", "source", "enabled"):
            self.assertNotIn(key, item)

    def test_api_body_matches_file(self) -> None:
        _, _, items = self._pair("rule-sysdig-1.0")
        body = json.loads(_read(GOLDEN / "rule-sysdig-1.0.api.json"))
        item = items[0]
        self.assertEqual(body["name"], item["rule"])
        self.assertEqual(body["description"], item["desc"])
        self.assertEqual(body["tags"], item["tags"])
        details = body["details"]
        self.assertEqual(details["ruleType"], "FALCO")
        self.assertIs(details["append"], False)
        self.assertEqual(details["condition"], {"components": [], "condition": item["condition"]})
        self.assertEqual(details["output"], item["output"])
        self.assertEqual(details["priority"], item["priority"].lower())
        self.assertEqual(details["source"], item["source"])
        self.assertEqual(details["exceptions"], item["exceptions"])


if __name__ == "__main__":
    unittest.main()
