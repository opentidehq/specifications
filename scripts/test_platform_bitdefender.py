#!/usr/bin/env python3
"""Consistency tests for specs/platforms/bitdefender-1.0.md, its fixtures, and the specs that list Bitdefender.

The JSON-RPC bodies under fixtures/platforms/bitdefender/ are the goldens implementations compare
against. These tests derive each body from its source rule fixture and the fixture tenant by the
spec's rules (name, description, severity, tags, settings by kind, full automatic actions, targets),
so a golden cannot drift from the text.
"""

from __future__ import annotations

import json
import re
import tomllib
import unittest
from pathlib import Path
from typing import Any

import yaml

from object_fixtures import (
    EXPECTED_INVALID_CODES,
    load_vocabularies,
    validate_bitdefender_block,
    validate_fixture_file,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specs" / "platforms" / "bitdefender-1.0.md"
INDEX = ROOT / "specs" / "platforms" / "index.md"
FIXTURES = ROOT / "fixtures"
GOLDEN = FIXTURES / "platforms" / "bitdefender"
SECTIONS = ["Summary", "Requirements", "Definition", "Relationships", "Defaults & overrides", "Examples", "History"]
SAMPLE_RULE_ID = "6372b7a3897aaa77ee021642"

SEVERITY = {"Critical": 3, "High": 3, "Medium": 2, "Low": 1, "Informational": 1}
BLOCK_SEVERITY = {"Low": 1, "Medium": 2, "High": 3}
ACTION_TYPES = {
    "isolate": 1,
    "collect_investigation_package": 2,
    "sandbox": 3,
    "kill_process": 4,
    "antimalware_scan": 5,
    "quarantine": 6,
    "risk_scan": 7,
}
CONSTRAINTS = [
    "bitdefender_rule_kind",
    "bitdefender_target",
    "bitdefender_criterion_shape",
    "bitdefender_criterion_field",
    "bitdefender_criterion_relation",
    "bitdefender_criterion_value",
    "bitdefender_criteria_combination",
    "bitdefender_action_scope",
    "bitdefender_targets_shape",
    "bitdefender_severity",
    "bitdefender_yara_ascii",
    "bitdefender_yara_size",
    "bitdefender_name_duplicate",
]
ADVISORIES = ["bitdefender_registry_full_hive", "bitdefender_contains_no_wildcard", "bitdefender_severity_collapsed"]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _codes(errors: list[Any]) -> set[str]:
    return {error.code for error in errors}


# --- the spec's derivations ------------------------------------------------------------------------


def normalise(text: str) -> str:
    """specs/platforms/bitdefender-1.0.md#name-and-description."""
    for before, after in (("<", "‹"), (">", "›"), ("'", "’"), ('"', "”")):
        text = text.replace(before, after)
    return text.lstrip()


def gz_name(rule: dict[str, Any]) -> str:
    block = rule["configurations"]["bitdefender"]
    return normalise(block.get("name") or rule["name"])[:128]


def gz_description(rule: dict[str, Any]) -> str:
    text = normalise(" ".join(str(rule.get("description", "")).split()))
    return text if len(text) <= 1024 else text[:1023] + "…"


def gz_severity(rule: dict[str, Any]) -> int:
    block = rule["configurations"]["bitdefender"]
    if block.get("severity"):
        return BLOCK_SEVERITY[block["severity"]]
    return SEVERITY.get((rule.get("response") or {}).get("alert_severity"), 2)


def gz_tags(rule: dict[str, Any], tenant_tags: list[str]) -> list[str]:
    block = rule["configurations"]["bitdefender"]
    candidates = [
        *(block.get("tags") or []),
        *(rule.get("techniques") or []),
        "opentide",
        f"opentide:{rule['metadata']['uuid']}",
        *tenant_tags,
    ]
    tags: list[str] = []
    for tag in candidates:
        tag = normalise(str(tag))[:128]
        if len(tag) >= 2 and tag not in tags:
            tags.append(tag)
    return tags


def gz_actions(kind: str, actions: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for key, code in ACTION_TYPES.items():
        if kind == "yara" and code == 4:
            continue
        entry: dict[str, Any] = {"type": code, "enabled": key in actions}
        if key in actions and code in (4, 6):
            value = actions[key] if isinstance(actions[key], dict) else {}
            entry["settings"] = {
                "includeParent": bool(value.get("include_parent", False)),
                "includeChildren": bool(value.get("include_children", False)),
            }
        if key in actions and code == 5:
            entry["settings"] = {"type": 1 if actions[key] == "quick" else 2}
        entries.append(entry)
    return entries


def gz_settings(rule: dict[str, Any], strategy: str, update: bool = False) -> tuple[int, dict[str, Any]]:
    block = rule["configurations"]["bitdefender"]
    disabled = strategy == "DISABLEMENT"
    if "detection" in block:
        detection = block["detection"]
        settings: dict[str, Any] = {
            "status": 0 if disabled else 1,
            "severity": gz_severity(rule),
            "target": detection["target"],
            "criteriaList": [
                {"field": c["field"], "relation": relation, "value": c[relation]}
                for c in detection["criteria"]
                for relation in ("is", "contains", "any")
                if relation in c
            ],
        }
        if detection.get("alert"):
            settings["filters"] = [{"field": "detection", "value": detection["alert"]}]
        elif update:
            settings["filters"] = []
        settings["automaticActions"] = gz_actions("detection", block.get("actions") or {})
        return 0, settings
    yara_block = block["yara"]
    signature = yara_block["signature"].replace("\r\n", "\n")
    signature = signature if signature.endswith("\n") else signature + "\n"
    settings = {
        "status": 0 if disabled or not yara_block.get("on_access", True) else 1,
        "severity": gz_severity(rule),
        "yaraQuery": signature,
        "automaticActions": gz_actions("yara", block.get("actions") or {}),
    }
    return 1, settings


def gz_targets(rule: dict[str, Any], setup: dict[str, Any]) -> dict[str, Any] | None:
    targets = rule["configurations"]["bitdefender"].get("targets") or setup.get("targets")
    if not targets:
        return None
    if "endpoint_tags" in targets:
        aliases = setup.get("endpoint_tags", {})
        return {
            "endpointTags": [
                {"tagId": aliases[a]["tag_id"], "companyId": aliases[a]["company_id"]} for a in targets["endpoint_tags"]
            ]
        }
    return {"companiesIds": [setup["companies"][a] for a in targets["companies"]]}


def build(rule: dict[str, Any], setup: dict[str, Any], method: str, strategy: str = "RELEASE") -> dict[str, Any]:
    subtype, settings = gz_settings(rule, strategy, update=method == "updateCustomRule")
    params: dict[str, Any] = {}
    if method == "updateCustomRule":
        params["ruleId"] = SAMPLE_RULE_ID
    params["type"] = 1
    if method == "createCustomRule":
        params["subtype"] = subtype
    params.update(
        {
            "name": gz_name(rule),
            "description": gz_description(rule),
            "tags": gz_tags(rule, setup.get("tags", [])),
            "settings": settings,
        }
    )
    targets = gz_targets(rule, setup)
    if targets:
        params["targets"] = targets
    elif method == "updateCustomRule":
        params["targets"] = {}
    if method == "createCustomRule":
        params["returnRuleId"] = True
    return {"jsonrpc": "2.0", "method": method, "params": params}


GOLDENS = {
    "rule-bitdefender-detection-1.0.create.api.json": ("rule-bitdefender-detection-1.0.yaml", "createCustomRule", "RELEASE"),
    "rule-bitdefender-detection-1.0.update.api.json": ("rule-bitdefender-detection-1.0.yaml", "updateCustomRule", "RELEASE"),
    "rule-bitdefender-detection-1.0.disable.api.json": ("rule-bitdefender-detection-1.0.yaml", "updateCustomRule", "DISABLEMENT"),
    "rule-bitdefender-yara-1.0.create.api.json": ("rule-bitdefender-yara-1.0.yaml", "createCustomRule", "RELEASE"),
}


def _tenant_setup() -> dict[str, Any]:
    return tomllib.loads(_read(GOLDEN / "tenant.toml"))["tenants"][0]["setup"]


def _rule(name: str) -> dict[str, Any]:
    return yaml.safe_load(_read(FIXTURES / "valid" / name))


# --- tests -----------------------------------------------------------------------------------------


class SpecShapeTests(unittest.TestCase):
    def test_frontmatter_and_sections(self) -> None:
        text = _read(SPEC)
        self.assertIn("schema_id: platform::bitdefender::1.0", text)
        self.assertIn("status: normative", text)
        self.assertEqual(re.findall(r"^## (.+)$", text, flags=re.MULTILINE), SECTIONS)

    def test_constraint_and_advisory_tables(self) -> None:
        text = _read(SPEC)
        section = text[text.index("### Constraints") : text.index("Every implementation reports each code")]
        self.assertEqual(re.findall(r"^\| `(bitdefender_[a-z_]+)` \|", section, flags=re.MULTILINE), CONSTRAINTS)
        advisories = text[text.index("### Advisories") : text.index("### Name and description")]
        self.assertEqual(re.findall(r"^\| `(bitdefender_[a-z_]+)` \|", advisories, flags=re.MULTILINE), ADVISORIES)
        validation = _read(ROOT / "specs" / "validation.md")
        for code in ADVISORIES:
            self.assertIn(f"| `{code}` | warning |", validation)

    def test_severity_table(self) -> None:
        section = _read(SPEC).split("### Severity", 1)[1].split("###", 1)[0]
        for label, value in SEVERITY.items():
            self.assertIn(f"| `{label}` | {value} |", section)

    def test_field_paths_are_fixed(self) -> None:
        text = _read(SPEC)
        self.assertIn('version: "1.4"', text)
        self.assertIn("| `bitdefender_action_scope` | `actions.<key>` |", text)

    def test_no_exclusion_and_whole_payload(self) -> None:
        text = _read(SPEC)
        self.assertIn("Deploy MUST NOT create, update, or delete an exclusion rule (`type: 2`).", text)
        self.assertIn("Every `updateCustomRule` MUST send the whole payload", text)
        self.assertIn("`^[0-9a-f]{24}$`", text)


class GoldenTests(unittest.TestCase):
    def test_goldens_follow_the_spec(self) -> None:
        setup = _tenant_setup()
        for golden, (source, method, strategy) in GOLDENS.items():
            with self.subTest(golden=golden):
                expected = build(_rule(source), setup, method, strategy)
                self.assertEqual(json.loads(_read(GOLDEN / golden)), expected)

    def test_golden_set_is_complete(self) -> None:
        self.assertEqual(sorted(p.name for p in GOLDEN.glob("*.api.json")), sorted(GOLDENS))

    def test_derivations(self) -> None:
        rule = _rule("rule-bitdefender-detection-1.0.yaml")
        self.assertNotIn('"', gz_description(rule))
        self.assertIn("‹macro›", gz_description(rule))
        yara_rule = _rule("rule-bitdefender-yara-1.0.yaml")
        self.assertEqual(gz_severity(yara_rule), 3)
        self.assertEqual([a["type"] for a in gz_actions("yara", {})], [1, 2, 3, 5, 6, 7])


class ListingTests(unittest.TestCase):
    def test_platform_index(self) -> None:
        text = _read(INDEX)
        self.assertIn("opentide ships twelve detection platform integrations.", text)
        self.assertIn("| `bitdefender` | `platform::bitdefender::1.0` | [bitdefender-1.0.md](bitdefender-1.0.md) |", text)
        self.assertIn("| `bitdefender` | Bitdefender GravityZone | yes* | **no**¶ | GravityZone criteria or YARA |", text)
        self.assertIn("Excluded from `--live`: `crowdstrike`, `harfanglab`, `sysdig`, `bitdefender`.", text)

    def test_spec_index_and_llms(self) -> None:
        self.assertIn("[specs/platforms/bitdefender-1.0.md](specs/platforms/bitdefender-1.0.md)", _read(ROOT / "SPECS.md"))
        self.assertIn("specs/platforms/bitdefender-1.0.md (schema_id: platform::bitdefender::1.0)", _read(ROOT / "llms.txt"))
        self.assertIn("[0016](0016-bitdefender-gravityzone-platform.md)", _read(ROOT / "rfcs" / "README.md"))

    def test_rule_specs_list_the_block(self) -> None:
        for name in ("rule-1.0.md", "rule-1.1.md"):
            self.assertIn(
                "| `bitdefender` | BitdefenderConfig | `platform::bitdefender::1.0` |",
                _read(ROOT / "specs" / "objects" / name),
            )

    def test_deployment_state_accepts_24_hex_ids(self) -> None:
        schema = json.loads(_read(ROOT / "schemas" / "deployment.state.1.0.schema.json"))
        self.assertEqual(schema["properties"]["platforms"]["properties"]["bitdefender"], {"$ref": "#/$defs/objectIdTenants"})
        pattern = schema["$defs"]["objectIdTenants"]["additionalProperties"]["pattern"]
        self.assertEqual(pattern, "^[0-9a-f]{24}$")
        self.assertIn("| `bitdefender` | 24 lower-case hex digits as a string", _read(ROOT / "specs" / "deployment-state.md"))


class CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vocabs = load_vocabularies(ROOT / "vocabularies")

    def test_valid_fixtures_pass(self) -> None:
        for path in (
            FIXTURES / "platforms" / "bitdefender.yaml",
            FIXTURES / "valid" / "rule-bitdefender-detection-1.0.yaml",
            FIXTURES / "valid" / "rule-bitdefender-yara-1.0.yaml",
        ):
            with self.subTest(path=path.name):
                self.assertEqual(validate_fixture_file(path, self.vocabs), [])

    def test_invalid_fixtures_report_their_code(self) -> None:
        for name in (
            "rule-bitdefender-two-kinds.yaml",
            "rule-bitdefender-criterion-field.yaml",
            "rule-bitdefender-exclusion.yaml",
            "rule-bitdefender-kill-on-yara.yaml",
        ):
            with self.subTest(name=name):
                codes = _codes(validate_fixture_file(FIXTURES / "invalid" / name, self.vocabs))
                self.assertIn(EXPECTED_INVALID_CODES[name], codes)

    def test_block_codes(self) -> None:
        def block(**keys: Any) -> dict[str, Any]:
            return {"enabled": True, "schema": "platform::bitdefender::1.0", "status": "STAGING", **keys}

        detection = {"target": "process", "criteria": [{"field": "Process.Name", "is": "x.exe"}]}
        self.assertEqual(validate_bitdefender_block(block(detection=detection)), [])
        self.assertEqual(_codes(validate_bitdefender_block(block(detection=detection, severity="Critical"))), {"bitdefender_severity"})
        self.assertEqual(
            _codes(validate_bitdefender_block(block(detection={**detection, "target": "flow"}))), {"bitdefender_target"}
        )
        both = {"target": "registry", "criteria": [{"field": "Registry.Operation", "contains": "key_*"}]}
        self.assertIn("bitdefender_criterion_relation", _codes(validate_bitdefender_block(block(detection=both))))
        shape = {"target": "process", "criteria": [{"field": "Process.Name", "is": "a", "contains": "b"}]}
        self.assertEqual(_codes(validate_bitdefender_block(block(detection=shape))), {"bitdefender_criterion_shape"})
        port = {"target": "connection", "criteria": [{"field": "Connection.DestinationPort", "any": [443, 70000]}]}
        self.assertEqual(_codes(validate_bitdefender_block(block(detection=port))), {"bitdefender_criterion_value"})
        self.assertEqual(
            _codes(validate_bitdefender_block(block(detection=detection, targets={"endpoint_tags": [], "companies": ["a"]}))),
            {"bitdefender_targets_shape"},
        )
        for targets in ({}, {"endpoint_tags": []}, {"endpoint_tags": [" "]}, {"companies": ["a", ""]}):
            with self.subTest(targets=targets):
                self.assertEqual(
                    _codes(validate_bitdefender_block(block(detection=detection, targets=targets))),
                    {"bitdefender_targets_shape"},
                )
        self.assertEqual(validate_bitdefender_block(block(detection=detection, targets={"endpoint_tags": ["tier0"]})), [])
        alert_field = {"target": "email", "criteria": [{"field": "detection", "is": "Some alert"}]}
        self.assertEqual(_codes(validate_bitdefender_block(block(detection=alert_field))), {"bitdefender_criterion_field"})
        xdr = {"target": "connection", "criteria": [{"field": "Connection.SourceUser", "is": "bob"}]}
        self.assertEqual(validate_bitdefender_block(block(detection=xdr)), [])
        is_only = {"target": "registry", "criteria": [{"field": "Registry.DataType", "any": ["dword"]}]}
        self.assertEqual(_codes(validate_bitdefender_block(block(detection=is_only))), {"bitdefender_criterion_relation"})
        boolean = {"target": "process", "criteria": [{"field": "Process.Name", "is": True}]}
        self.assertEqual(_codes(validate_bitdefender_block(block(detection=boolean))), {"bitdefender_criterion_shape"})
        sig = {"signature": "rule A {\n  condition:\n    true // é\n}\n"}
        self.assertEqual(_codes(validate_bitdefender_block(block(yara=sig))), {"bitdefender_yara_ascii"})


if __name__ == "__main__":
    unittest.main()
