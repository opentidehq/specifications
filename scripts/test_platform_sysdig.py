#!/usr/bin/env python3
"""Consistency tests for specs/platforms/sysdig-1.0.md, its fixtures, and the specs that list Sysdig.

The API bodies under fixtures/platforms/sysdig/ are the goldens implementations
compare against. These tests check that they follow the spec's derivations from
their source rule fixtures (priority, tags, desc, and expansion of the block's
own lists), so a golden cannot drift from the text.
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
                "sysdig_definition_order",
                "sysdig_list_in_value",
            ],
        )

    def test_list_order_follows_falco(self) -> None:
        """Real Falco 0.45.2: a macro naming a later macro is refused; a list naming a later list resolves."""
        text = _read(SPEC)
        row = next(line for line in text.splitlines() if line.startswith("| `sysdig_definition_order` |"))
        self.assertIn("for macros", row)
        self.assertIn("Lists have no ordering constraint", row)
        self.assertIn("a list may name a later list", text)
        advisories = text.split("### Advisories", 1)[1].split("###", 1)[0]
        self.assertIn("| `sysdig_list_self_reference` |", advisories)
        self.assertIn("| `sysdig_list_self_reference` | warning |", _read(ROOT / "specs" / "validation.md"))

    def test_priority_table_matches(self) -> None:
        section = _read(SPEC).split("### Priority", 1)[1].split("###", 1)[0]
        for severity, (falco, api) in PRIORITY.items():
            self.assertIn(f"| `{severity}` | `{falco}` | `{api}` |", section)


class ListingTests(unittest.TestCase):
    def test_platform_index(self) -> None:
        text = _read(INDEX)
        self.assertIn("opentide ships ten detection platform integrations.", text)
        self.assertIn("| `sysdig` | `platform::sysdig::1.0` | [sysdig-1.0.md](sysdig-1.0.md) |", text)
        self.assertIn("| `sysdig` | Sysdig Secure | yes* | **no**‡ | Falco condition |", text)
        self.assertIn("Excluded from `--live`: `crowdstrike`, `harfanglab`, `sysdig`, `bitdefender`.", text)

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
        """Falco's validate_exception_info and build_rule_exception_infos (falcosecurity/falco)."""
        ok = [
            {"name": "a", "fields": ["proc.name", "proc.pname"], "values": [["sh", "bash"]]},
            {"name": "b", "fields": ["proc.name", "proc.pname"], "comps": ["=", "in"], "values": [["sh", ["bash", "zsh"]]]},
            # A single value under a list comparison: Falco wraps it, so it can name a list.
            {"name": "c", "fields": ["proc.name", "proc.pname"], "comps": ["=", "in"], "values": [["sh", "shell_binaries"]]},
            {"name": "d", "fields": "proc.name", "values": ["sh", "bash"]},
            {"name": "e", "fields": "proc.name", "comps": "pmatch", "values": ["/tmp"]},
            {"name": "f", "fields": "proc.name", "comps": "startswith oneof", "values": ["ba", "zs"]},
            {"name": "g", "fields": ["fd.name"]},
            {"name": "h", "fields": ["proc.name", "fd.name"], "comps": ["==", " glob anyof "], "values": [["sh", ["/tmp/*"]]]},
            {"name": "i", "fields": ["proc.name"], "comps": ["exists"], "values": []},
        ]
        self.assertEqual(_codes(validate_sysdig_block(_block(condition="a", exceptions=ok))), set())
        bad = [
            {"name": "", "fields": "proc.name"},
            {"name": "x", "fields": ["proc.name"], "comps": ["=", "="]},
            {"name": "x", "fields": ["proc.name"], "comps": ["~"]},
            {"name": "x", "fields": ["proc.name"], "comps": ["< oneof"]},
            {"name": "x", "fields": ["proc.name"], "comps": ["startswith someof"]},
            {"name": "x", "fields": ["proc.name", "proc.pname"], "values": [["sh"]]},
            {"name": "x", "fields": "proc.name", "comps": "="},
            {"name": "x", "fields": "proc.name", "comps": ["in"]},
            {"name": "x", "fields": "proc.name", "values": [["sh"]]},
            {"name": "x", "fields": []},
        ]
        for exc in bad:
            with self.subTest(exc=exc):
                self.assertEqual(
                    _codes(validate_sysdig_block(_block(condition="a", exceptions=[exc]))), {"sysdig_exception_shape"}
                )

    def test_repeated_exception_names_are_not_a_constraint(self) -> None:
        """Falco only warns (LOAD_EXCEPTION_NAME_NOT_UNIQUE); the engine reports the warning."""
        repeated = [{"name": "a", "fields": "proc.name"}, {"name": "a", "fields": "proc.pname"}]
        self.assertEqual(_codes(validate_sysdig_block(_block(condition="a", exceptions=repeated))), set())

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
    """The API bodies deploy sends, derived from their rule fixtures as the spec says."""

    def _pair(self, stem: str) -> tuple[dict[str, Any], dict[str, Any]]:
        rule = yaml.safe_load(_read(FIXTURES / "valid" / f"{stem}.yaml"))
        return rule, json.loads(_read(GOLDEN / f"{stem}.api.json"))

    def test_goldens_are_api_bodies_only(self) -> None:
        self.assertEqual(
            sorted(path.name for path in GOLDEN.iterdir()),
            ["rule-sysdig-1.0.api.json", "rule-sysdig-tuning-1.0.api.json"],
        )

    def test_new_rule_derivations(self) -> None:
        rule, body = self._pair("rule-sysdig-1.0")
        block = rule["configurations"]["sysdig"]
        details = body["details"]
        self.assertEqual(body["name"], rule["name"])
        self.assertEqual(body["description"], " ".join(rule["description"].split()))
        self.assertEqual(details["ruleType"], "FALCO")
        self.assertIs(details["append"], False)
        self.assertEqual(details["priority"], PRIORITY[rule["response"]["alert_severity"]][1])
        self.assertEqual(details["source"], block["source"])
        self.assertEqual(details["output"], " ".join(block["output"].split()))
        # Block tags, technique, tactic, maturity for a PREVIEW strategy (STAGING).
        self.assertEqual(body["tags"], [*block["tags"], "T1059.004", "mitre_execution", "maturity_incubating"])
        self.assertEqual(details["exceptions"], block["exceptions"])
        self.assertNotIn("minimumEngineVersion", details)

    def test_lists_are_expanded(self) -> None:
        rule, body = self._pair("rule-sysdig-1.0")
        block = rule["configurations"]["sysdig"]
        condition = body["details"]["condition"]
        self.assertEqual(condition["components"], [])
        expected = " ".join(block["condition"].split())
        for definition in block["lists"]:
            self.assertNotRegex(condition["condition"], rf"\b{definition['name']}\b")
            # Falco's resolve_list: the name becomes " " + items + " " (no blank around it here).
            expected = expected.replace(definition["name"], " " + ", ".join(definition["items"]) + " ")
        self.assertEqual(condition["condition"], expected)

    def test_tuning(self) -> None:
        rule, body = self._pair("rule-sysdig-tuning-1.0")
        block = rule["configurations"]["sysdig"]
        self.assertEqual(body["name"], block["append_to_rule"])
        self.assertEqual(body["description"], "")
        self.assertEqual(body["tags"], [])
        details = body["details"]
        self.assertEqual(sorted(details), ["append", "condition", "exceptions", "ruleType"])
        self.assertIs(details["append"], True)
        self.assertEqual(
            details["condition"],
            {"components": [], "condition": "and not proc.pname in ( gitlab-runner, buildkite-agent )"},
        )
        self.assertEqual(details["exceptions"], block["exceptions"])


if __name__ == "__main__":
    unittest.main()
