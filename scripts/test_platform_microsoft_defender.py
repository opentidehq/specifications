#!/usr/bin/env python3
"""Consistency tests for specs/platforms/microsoft-defender-1.0.md (RFC 0021), its fixtures, the specs
that list Microsoft Defender, and the removal of defender_for_endpoint.

The Graph request bodies under fixtures/platforms/microsoft-defender/ are the goldens implementations
compare against. These tests derive them from the source fixtures by the spec's tables, so a golden
cannot drift from the text. graph-beta-properties.json is a snapshot of the Graph beta docs' Properties tables; every
property in it must be modelled by the block or listed in the spec's "Beta properties not modelled".
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
    DEFENDER_ACTIONS,
    DEFENDER_ENTITIES,
    DEFENDER_GROUPING,
    DEFENDER_ISOLATION_TYPES,
    EXPECTED_INVALID_CODES,
    defender_duration_hours,
    load_vocabularies,
    validate_microsoft_defender_block,
    validate_fixture_file,
)

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = ROOT / "specs" / "platforms"
SPEC = PLATFORMS / "microsoft-defender-1.0.md"
SPEC_OLD = PLATFORMS / "defender-for-endpoint-1.0.md"
RFC = ROOT / "rfcs" / "0021-defender-graph-beta-detection-rules.md"
FIXTURES = ROOT / "fixtures"
RULE = FIXTURES / "platforms" / "microsoft-defender.yaml"
RULE_COMPLETE = FIXTURES / "platforms" / "microsoft-defender-complete.yaml"
GOLDEN = FIXTURES / "platforms" / "microsoft-defender"
SNAPSHOT = GOLDEN / "graph-beta-properties.json"
SECTIONS = ["Summary", "Requirements", "Definition", "Relationships", "Defaults & overrides", "Examples", "History"]
SCHEMA = "platform::microsoft_defender::1.0"
BASE = "https://graph.microsoft.com/beta/security/rules/detectionRules"

CONSTRAINTS = [
    "microsoft_defender_schema",
    "microsoft_defender_frequency",
    "microsoft_defender_lookback",
    "microsoft_defender_severity",
    "microsoft_defender_grouping",
    "microsoft_defender_custom_details",
    "microsoft_defender_entity_kind",
    "microsoft_defender_entity_mapping",
    "microsoft_defender_action_kind",
    "microsoft_defender_action_target",
    "microsoft_defender_isolation_type",
    "microsoft_defender_column",
    "microsoft_defender_scope",
    "microsoft_defender_incident",
]
ADVISORIES = ["microsoft_defender_no_entities"]
DIAGNOSTICS = ["microsoft_defender_rule_absent"]

STATUS = {"PREVIEW": "enabled", "RELEASE": "enabled", "UNIVERSAL": "enabled", "DISABLEMENT": "disabled"}
TACTICS = [
    (("Reconnaissance",), "Reconnaissance"),
    (("Resource Development",), "ResourceDevelopment"),
    (("Initial Access",), "InitialAccess"),
    (("Execution",), "Execution"),
    (("Persistence",), "Persistence"),
    (("Privilege Escalation",), "PrivilegeEscalation"),
    (("Stealth", "Defense Impairment", "Defense Evasion"), "DefenseEvasion"),
    (("Credential Access",), "CredentialAccess"),
    (("Discovery",), "Discovery"),
    (("Lateral Movement",), "LateralMovement"),
    (("Collection",), "Collection"),
    (("Command and Control",), "CommandAndControl"),
    (("Exfiltration",), "Exfiltration"),
    (("Impact",), "Impact"),
]
BETA_ONLY = {("schedule", "lookback"), ("alertTemplate", "eventGroupingKind"), ("detectionAction", "incidentConfiguration")}

# Graph v1.0 detectionRule properties (api-reference/v1.0, 2026-11-24), for the informational note only.
V1_PROPERTIES = {
    "": {"id", "displayName", "description", "status", "queryCondition", "schedule", "detectionAction"},
    "queryCondition": {"queryText"},
    "schedule": {"frequency"},
    "detectionAction": {"alertTemplate", "automatedActions", "organizationalScope"},
    "alertTemplate": {"title", "description", "severity", "recommendedActions", "tactics", "entityMappings", "customDetails"},
    "organizationalScope": {"deviceGroups"},
}
DEPRECATED = {"isEnabled", "period", "category", "mitreTechniques", "impactedAssets", "responseActions", "scopeType", "scopeNames"}

# The Graph paths the block's own keys model (schedule, alert, scope, incident tables' Graph column).
MODELLED_PATHS = [
    "queryCondition", "schedule", "detectionAction",
    "schedule.frequency", "schedule.lookback",
    "detectionAction.alertTemplate", "detectionAction.automatedActions",
    "detectionAction.organizationalScope", "detectionAction.incidentConfiguration",
    "detectionAction.alertTemplate.title", "detectionAction.alertTemplate.description",
    "detectionAction.alertTemplate.severity", "detectionAction.alertTemplate.recommendedActions",
    "detectionAction.alertTemplate.customDetails", "detectionAction.alertTemplate.eventGroupingKind",
    "detectionAction.alertTemplate.entityMappings",
    "detectionAction.organizationalScope.deviceGroups",
    "detectionAction.incidentConfiguration.isExcludedFromIncidentCorrelation",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load(path: Path) -> Any:
    return yaml.safe_load(_read(path))


def _frontmatter(text: str) -> dict[str, str]:
    block = text.split("---", 2)[1]
    pairs = (line.split(":", 1) for line in block.strip().splitlines())
    return {key.strip(): value.strip().strip('"') for key, value in pairs}


def _section(text: str, heading: str, level: str = "###") -> str:
    start = text.index(f"\n{level} {heading}\n")
    rest = text[start + 1 :]
    match = re.search(rf"\n#{{1,{len(level)}}} ", rest)
    return rest[: match.start()] if match else rest


def _codes(errors: list[Any]) -> set[str]:
    return {error.code for error in errors}


def _attack() -> dict[str, dict[str, Any]]:
    doc = tomllib.loads(_read(ROOT / "vocabularies" / "att&ck.vocab.toml"))
    return {key["id"]: key for key in doc["keys"]}


def _snapshot() -> dict[str, Any]:
    return json.loads(_read(SNAPSHOT))


def _type_of(prop: dict[str, Any]) -> str | None:
    match = re.search(r"security\.(\w+)", prop["type"])
    return match.group(1) if match else None


# --- the spec's derivations ------------------------------------------------------------------------


def tactics(ids: list[str], attack: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """specs/platforms/microsoft-defender-1.0.md#attck."""
    grouped: dict[str, dict[str, set[str]]] = {}
    for tid in ids:
        key = attack.get(tid)
        if key is None or key["name"].startswith(("Mobile : ", "Industrial : ")):
            continue
        parent = tid.split(".")[0]
        for stage in key.get("tide.vocab.stages", []):
            tactic = next((t for stages, t in TACTICS if stage in stages), None)
            if tactic is None:
                continue
            subs = grouped.setdefault(tactic, {}).setdefault(parent, set())
            if tid != parent:
                subs.add(tid)
    out = []
    for _, tactic in TACTICS:
        if tactic not in grouped:
            continue
        techniques = []
        for parent in sorted(grouped[tactic]):
            entry: dict[str, Any] = {"technique": parent}
            if grouped[tactic][parent]:
                entry["subTechniques"] = sorted(grouped[tactic][parent])
            techniques.append(entry)
        out.append({"tactic": tactic, "techniques": techniques})
    return out


def _duration(value: str) -> str:
    """specs/platforms/microsoft-defender-1.0.md#schedule-defenderschedule."""
    if value == "NRT":
        return "PT0S"
    assert defender_duration_hours(value) is not None
    return f"P{value[:-1]}D" if value.endswith("D") else f"PT{value[:-1]}H"


def body(
    rule: dict[str, Any], strategy: str, attack: dict[str, dict[str, Any]], create: bool, tenant: str = "contoso"
) -> dict[str, Any]:
    """specs/platforms/microsoft-defender-1.0.md#request-body for `tenant`.

    The spec does not fix how an exclusion is spliced into the query, so a golden may only hold
    exclusions scoped to another tenant: those are skipped and the query is sent unchanged.
    """
    block = rule["configurations"]["microsoft_defender"]
    applied = [e for e in block.get("exclusions") or [] if e.get("tenant") in (None, tenant)]
    assert not applied, "a golden may not apply an exclusion"
    alert = block.get("alert") or {}
    out: dict[str, Any] = {}
    if create:
        out["id"] = rule["metadata"]["uuid"].lower()
    out["displayName"] = block.get("name") or rule["name"]
    out["description"] = rule["description"]
    out["status"] = STATUS[strategy]
    out["queryCondition"] = {"queryText": block["query"]}
    schedule = {"frequency": _duration(block["schedule"]["frequency"])}
    if block["schedule"].get("lookback"):
        schedule["lookback"] = _duration(block["schedule"]["lookback"])
    out["schedule"] = schedule

    severity = alert.get("severity") or (rule.get("response") or {}).get("alert_severity") or "Medium"
    template: dict[str, Any] = {
        "title": alert.get("title") or rule["name"],
        "description": alert.get("description") or rule["description"],
        "severity": "high" if severity == "Critical" else severity.lower(),
    }
    if alert.get("recommendation"):
        template["recommendedActions"] = alert["recommendation"]
    derived = tactics(alert.get("techniques") or [], attack)
    if derived:
        template["tactics"] = derived
    if block.get("entities"):
        mappings = {}
        for kind, items in block["entities"].items():
            graph_kind, fields = DEFENDER_ENTITIES[kind]
            if items:
                mappings[graph_kind] = [{fields[k]: v for k, v in item.items()} for item in items]
        if mappings:
            template["entityMappings"] = mappings
    if alert.get("custom_details"):
        template["customDetails"] = dict(alert["custom_details"])
    if alert.get("grouping"):
        template["eventGroupingKind"] = {"alert_per_event": "alertPerEvent", "single_alert": "singleAlert"}[alert["grouping"]]

    action: dict[str, Any] = {"alertTemplate": template}
    if block.get("actions"):
        action["automatedActions"] = {
            DEFENDER_ACTIONS[name][0]: [{DEFENDER_ACTIONS[name][1][k]: v for k, v in target.items()} for target in targets]
            for name, targets in block["actions"].items()
        }
    if block.get("scope"):
        action["organizationalScope"] = {"deviceGroups": list(block["scope"]["device_groups"])}
    if block.get("incident"):
        action["incidentConfiguration"] = {"isExcludedFromIncidentCorrelation": block["incident"]["exclude_from_correlation"]}
    out["detectionAction"] = action
    return out


def _walk(node: Any, path: str = "") -> list[tuple[str, str]]:
    """(parent property, key) for every object key in a body."""
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.append((path, key))
            found.extend(_walk(value, key))
    elif isinstance(node, list):
        for item in node:
            found.extend(_walk(item, path))
    return found


# --- tests ----------------------------------------------------------------------------------------


class SpecShapeTests(unittest.TestCase):
    def test_frontmatter_and_sections(self) -> None:
        text = _read(SPEC)
        meta = _frontmatter(text)
        self.assertEqual(meta["spec"], "platform-microsoft-defender")
        self.assertEqual(meta["schema_id"], SCHEMA)
        self.assertEqual(meta["status"], "normative")
        self.assertEqual(meta["version"], "1.1")
        self.assertEqual(meta["supersedes"], "null")
        for needle in ("defender_for_endpoint", "defender-for-endpoint", "legacy binding", "opentide migrate"):
            self.assertNotIn(needle, text)
        self.assertEqual(re.findall(r"^## (.+)$", text, flags=re.MULTILINE), SECTIONS)
        self.assertFalse((PLATFORMS / "defender-for-endpoint-2.0.md").exists())

    def test_old_spec_is_a_removed_record(self) -> None:
        """Owner decision (2026-11-25): defender_for_endpoint is removed; its spec is kept as a record only."""
        text = _read(SPEC_OLD)
        meta = _frontmatter(text)
        self.assertEqual(meta["status"], "deprecated")
        self.assertEqual(meta["version"], "1.4")
        self.assertIn("**Removed.** opentide 1.0 does not have this platform, and this spec defines no behaviour for it.", text)
        self.assertNotIn("### Deprecation", text)
        for code in ("defender_platform_", "defender_migrate_unmapped", "defender_schema_"):
            self.assertNotIn(code, text)
        self.assertFalse((FIXTURES / "platforms" / "defender-for-endpoint.yaml").exists())

    def test_no_handling_of_the_removed_platform(self) -> None:
        """defender_for_endpoint gets nothing: no code, no message, no migrate path, no legacy state."""
        allowed = {SPEC_OLD, ROOT / "SPECS.md", ROOT / "CHANGELOG.md"}
        for path in [*ROOT.joinpath("specs").rglob("*.md"), ROOT / "SPECS.md", ROOT / "CHANGELOG.md", ROOT / "llms.txt", RFC]:
            text = _read(path)
            for code in ("defender_platform_", "defender_migrate_unmapped", "defender_schema_", "legacy_retired", "legacy_delete_failed", "Legacy Defender"):
                self.assertNotIn(code, text, path)
            if path not in allowed and path != RFC:
                # Only a spec's History may record the removal.
                self.assertNotIn("defender_for_endpoint", text.split("\n## History\n", 1)[0], path)
        for name in ("migrated.yaml",):
            self.assertFalse((GOLDEN / name).exists())
        self.assertFalse((FIXTURES / "invalid" / "rule-defender-both-platforms.yaml").exists())
        self.assertNotIn("defender_for_endpoint", _read(ROOT / "llms.txt"))
        self.assertNotIn("defender-for-endpoint", _read(ROOT / "site" / "meta.json"))

    def test_codes(self) -> None:
        text = _read(SPEC)
        self.assertEqual(re.findall(r"^\| `([a-z_]+)` \|", _section(text, "Constraints"), flags=re.MULTILINE), CONSTRAINTS)
        self.assertEqual(re.findall(r"^\| `([a-z_]+)` \|", _section(text, "Advisories"), flags=re.MULTILINE), ADVISORIES)
        self.assertEqual(re.findall(r"^\| `([a-z_]+)` \|", _section(text, "Diagnostics"), flags=re.MULTILINE), DIAGNOSTICS)
        for code in CONSTRAINTS + ADVISORIES + DIAGNOSTICS:
            self.assertTrue(code.startswith("microsoft_defender_"), code)
        validation = _read(ROOT / "specs" / "validation.md")
        self.assertIn("| `microsoft_defender_no_entities` | warning | Microsoft Defender:", validation)

    def test_entity_table_is_the_checker_table(self) -> None:
        section = _section(_read(SPEC), "`entities` (DefenderEntities)")
        rows = re.findall(r"^\| `([a-z_]+)` \| `([A-Za-z]+)` \| (.+) \|$", section, flags=re.MULTILINE)
        parsed = {kind: (graph, dict(re.findall(r"`([a-z_0-9]+)` → `([A-Za-z0-9]+)`", fields))) for kind, graph, fields in rows}
        self.assertEqual(parsed, DEFENDER_ENTITIES)
        self.assertEqual(len(parsed), 17)

    def test_action_table_is_the_checker_table(self) -> None:
        section = _section(_read(SPEC), "`actions` (DefenderActions)")
        rows = re.findall(r"^\| `([a-z_]+)` \| `([A-Za-z]+)` \| ([^|]+) \|$", section, flags=re.MULTILINE)
        self.assertEqual([r[0] for r in rows], list(DEFENDER_ACTIONS))
        email = None
        for action, graph, fields in rows:
            expected_graph, expected_fields = DEFENDER_ACTIONS[action]
            self.assertEqual(graph, expected_graph, action)
            parsed = dict(re.findall(r"`([a-z_0-9]+)` → `([A-Za-z0-9]+)`", fields))
            if fields.startswith("same as"):
                parsed = email
            elif action == "soft_delete_emails":
                email = parsed
            self.assertEqual(parsed, expected_fields, action)

    def test_schedule_tactic_and_beta_tables(self) -> None:
        text = _read(SPEC)
        coverage = _section(text, "Beta-only properties", "####")
        self.assertEqual(re.findall(r"^\| `([a-z_.]+)` \|", coverage, flags=re.MULTILINE), ["schedule.lookback", "alert.grouping", "incident"])
        self.assertIn("opentide does not target v1.0", coverage)
        self.assertNotIn("later minor", text)
        attack = _section(text, "ATT&CK")
        for stages, tactic in TACTICS:
            self.assertRegex(attack, rf"\| {re.escape(stages[0])}[^|]* \| `{tactic}` \|")


class BetaCoverageTests(unittest.TestCase):
    """Every property of the Graph beta docs snapshot is modelled or listed as not modelled, with its reason."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshot = _snapshot()
        cls.types = cls.snapshot["types"]

    def _modelled(self) -> set[str]:
        out: set[str] = set()

        def walk(path: str) -> None:
            current = "detectionRule"
            for part in path.split("."):
                props = self.types[current]
                self.assertIn(part, props, f"{current}.{part}")
                out.add(f"{current}.{part}")
                current = _type_of(props[part]) or ""

        for path in MODELLED_PATHS:
            walk(path)
        for graph_kind, fields in DEFENDER_ENTITIES.values():
            walk(f"detectionAction.alertTemplate.entityMappings.{graph_kind}")
            mapping_type = _type_of(self.types["entityMappingConfiguration"][graph_kind])
            out.update(f"{mapping_type}.{prop}" for prop in fields.values())
        for graph_action, fields in DEFENDER_ACTIONS.values():
            walk(f"detectionAction.automatedActions.{graph_action}")
            action_type = _type_of(self.types["automatedActionSet"][graph_action])
            out.update(f"{action_type}.{prop}" for prop in fields.values())
        return out

    def _not_modelled(self) -> dict[str, str]:
        section = _section(_read(SPEC), "Beta properties not modelled", "####")
        table = section.split("Enum values not accepted", 1)[0]
        return dict(re.findall(r"^\| `(\w+\.\w+)` \| ([^|]+) \|$", table, flags=re.MULTILINE))

    def test_snapshot_is_the_beta_docs(self) -> None:
        self.assertIn("api-reference/beta", self.snapshot["source"])
        self.assertEqual(len(self.types), 36)
        self.assertEqual(self.snapshot["enums"]["alertTemplate.severity"], ["informational", "low", "medium", "high"])

    def test_every_property_is_modelled_or_listed(self) -> None:
        everything = {f"{name}.{prop}" for name, props in self.types.items() for prop in props}
        modelled, listed = self._modelled(), self._not_modelled()
        self.assertEqual(modelled & set(listed), set())
        self.assertEqual(sorted(everything - modelled - set(listed)), [])
        self.assertEqual(sorted(set(listed) - everything), [])
        self.assertEqual(sorted(modelled - everything), [])

    def test_reasons_match_the_docs(self) -> None:
        for key, reason in self._not_modelled().items():
            name, prop = key.split(".")
            flags = self.types[name][prop]
            with self.subTest(key=key):
                self.assertRegex(reason, r"^(Set by deploy|Read-only|Deprecated)")
                if flags["deprecated"]:
                    self.assertTrue(reason.startswith("Deprecated"))
                elif flags["readOnly"]:
                    self.assertTrue(reason.startswith("Read-only"))
                else:
                    self.assertTrue(reason.startswith("Set by deploy"))
        for name, props in self.types.items():
            for prop, flags in props.items():
                if flags["deprecated"] or flags["readOnly"]:
                    self.assertIn(f"{name}.{prop}", self._not_modelled(), f"{name}.{prop}")

    def test_every_enum_value_is_accepted_or_explained(self) -> None:
        enums = self.snapshot["enums"]
        section = _section(_read(SPEC), "Beta properties not modelled", "####")
        self.assertEqual(set(DEFENDER_GROUPING.values()), set(enums["eventGroupingKind"]) - {"unknownFutureValue"})
        self.assertEqual(set(DEFENDER_ISOLATION_TYPES), set(enums["isolationType"]) - {"unknownFutureValue"})
        self.assertEqual({"enabled", "disabled"} | {"autoDisabled"}, set(enums["detectionRuleStatus"]) - {"unknownFutureValue"})
        self.assertEqual(set(STATUS.values()), {"enabled", "disabled"})
        self.assertIn("| `detectionRuleStatus.autoDisabled` |", section)
        self.assertIn("| `unknownFutureValue` (every enum) |", section)
        sent = {"high" if s == "Critical" else s.lower() for s in ("Informational", "Low", "Medium", "High", "Critical")}
        self.assertEqual(sent, set(enums["alertTemplate.severity"]))


class GoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.attack = _attack()
        cls.rule = _load(RULE)

    def _golden(self, name: str) -> dict[str, Any]:
        return json.loads(_read(GOLDEN / name))

    def test_create(self) -> None:
        golden = self._golden("rule-microsoft-defender.create.api.json")
        self.assertEqual((golden["method"], golden["url"]), ("POST", BASE))
        self.assertEqual(golden["body"], body(self.rule, "RELEASE", self.attack, create=True))

    def test_update_is_create_without_id(self) -> None:
        golden = self._golden("rule-microsoft-defender.update.api.json")
        uuid = self.rule["metadata"]["uuid"]
        self.assertEqual((golden["method"], golden["url"]), ("PATCH", f"{BASE}/{uuid}"))
        self.assertEqual(golden["body"], body(self.rule, "RELEASE", self.attack, create=False))
        self.assertNotIn("id", golden["body"])

    def test_disable(self) -> None:
        golden = self._golden("rule-microsoft-defender.disable.api.json")
        self.assertEqual(golden["method"], "PATCH")
        self.assertEqual(golden["body"]["status"], "disabled")
        self.assertEqual(golden["body"], body(self.rule, "DISABLEMENT", self.attack, create=False))

    def test_tactics_of_the_example(self) -> None:
        derived = tactics(["T1059.001", "T1078.004"], self.attack)
        self.assertEqual([t["tactic"] for t in derived], ["InitialAccess", "Execution", "Persistence", "PrivilegeEscalation", "DefenseEvasion"])
        self.assertEqual(derived[1]["techniques"], [{"technique": "T1059", "subTechniques": ["T1059.001"]}])
        self.assertEqual(tactics(["T1078"], self.attack)[0]["techniques"], [{"technique": "T1078"}])

    def test_durations(self) -> None:
        self.assertEqual([_duration(v) for v in ("NRT", "1H", "24H", "1D", "7D")], ["PT0S", "PT1H", "PT24H", "P1D", "P7D"])

    def test_no_deprecated_property_and_v1_note(self) -> None:
        full = body(self.rule, "RELEASE", self.attack, create=True)
        keys = _walk(full)
        self.assertFalse({k for _, k in keys} & DEPRECATED)
        self.assertTrue(BETA_ONLY & set(keys))
        plain = json.loads(json.dumps(self.rule))
        block = plain["configurations"]["microsoft_defender"]
        del block["schedule"]["lookback"], block["alert"]["grouping"], block["incident"]
        for parent, key in _walk(body(plain, "RELEASE", self.attack, create=True)):
            if parent in V1_PROPERTIES:
                self.assertIn(key, V1_PROPERTIES[parent], (parent, key))
            self.assertNotIn((parent, key), BETA_ONLY)


class CompleteBlockTests(unittest.TestCase):
    """The complete block: every key of every field table, in the spec's Examples and in the fixture."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.rule = _load(RULE_COMPLETE)
        cls.block = cls.rule["configurations"]["microsoft_defender"]

    @staticmethod
    def _table_keys(heading: str) -> list[str]:
        section = _section(_read(SPEC), heading)
        table = section.split("\n\n|", 1)[1]
        rows = []
        for line in ("|" + table).splitlines():
            if not line.startswith("|"):
                break
            match = re.match(r"^\| `([a-z_]+)` \|", line)
            if match:
                rows.append(match.group(1))
        return rows

    def test_every_table_key_is_set(self) -> None:
        missing = []
        shared = ["enabled", "name", "schema", "status", "flags", "tenants", "contributors"]
        missing += [key for key in shared + self._table_keys("Block") if key not in self.block]
        for heading, key in (
            ("`schedule` (DefenderSchedule)", "schedule"),
            ("`alert` (DefenderAlert)", "alert"),
            ("`scope` (DefenderScope)", "scope"),
            ("`incident` (DefenderIncident)", "incident"),
        ):
            fields = self._table_keys(heading)
            self.assertTrue(fields, heading)
            missing += [f"{key}.{f}" for f in fields if f not in (self.block.get(key) or {})]
        exclusion_fields = self._table_keys("`exclusions[]` (DefenderExclusion)")
        self.assertEqual(exclusion_fields, ["query", "reason", "tenant", "let"])
        exclusions = self.block.get("exclusions") or [{}]
        missing += [f"exclusions.{f}" for f in exclusion_fields if not any(f in e for e in exclusions)]
        for kind, (_, fields) in DEFENDER_ENTITIES.items():
            mappings = (self.block.get("entities") or {}).get(kind) or [{}]
            missing += [f"entities.{kind}.{f}" for f in fields if not any(f in m for m in mappings)]
        for action, (_, fields) in DEFENDER_ACTIONS.items():
            targets = (self.block.get("actions") or {}).get(action) or [{}]
            missing += [f"actions.{action}.{f}" for f in fields if not any(f in t for t in targets)]
        self.assertEqual(missing, [])

    def test_valid(self) -> None:
        self.assertEqual(validate_microsoft_defender_block(self.block), [])
        self.assertEqual(validate_fixture_file(RULE_COMPLETE, load_vocabularies(ROOT / "vocabularies")), [])

    def test_spec_example_is_the_fixture(self) -> None:
        examples = _section(_read(SPEC), "Examples", "##")
        complete = examples.split("**Complete block.**", 1)[1]
        snippet = re.search(r"```yaml\n(.*?)```", complete, flags=re.S).group(1)
        self.assertEqual(yaml.safe_load(snippet)["configurations"], self.rule["configurations"])
        self.assertIn(snippet.split("configurations:\n", 1)[1], _read(RULE_COMPLETE))

    def test_beta_only_keys_are_commented(self) -> None:
        text = _read(RULE_COMPLETE)
        for line in ("lookback: 4H  # beta-only", "grouping: single_alert  # beta-only", "incident:  # beta-only"):
            self.assertIn(line, text)

    def test_create_golden(self) -> None:
        golden = json.loads(_read(GOLDEN / "rule-microsoft-defender-complete.create.api.json"))
        self.assertEqual((golden["method"], golden["url"]), ("POST", BASE))
        self.assertEqual(golden["body"], body(self.rule, "RELEASE", _attack(), create=True, tenant="contoso"))
        self.assertEqual(len(golden["body"]["detectionAction"]["alertTemplate"]["entityMappings"]), 17)
        self.assertEqual(len(golden["body"]["detectionAction"]["automatedActions"]), 16)


class CheckerTests(unittest.TestCase):
    def _block(self, **keys: Any) -> dict[str, Any]:
        return {"schema": SCHEMA, "query": "DeviceEvents", "schedule": {"frequency": "1H"}, **keys}

    def test_fixtures(self) -> None:
        vocabs = load_vocabularies(ROOT / "vocabularies")
        for path in (RULE, RULE_COMPLETE):
            self.assertEqual(validate_fixture_file(path, vocabs), [], path.name)
        for name in (
            "rule-microsoft-defender-lookback-nrt.yaml", "rule-microsoft-defender-entity-field.yaml",
            "rule-microsoft-defender-action-target.yaml", "rule-microsoft-defender-unknown-key.yaml",
        ):
            self.assertIn(EXPECTED_INVALID_CODES[name], _codes(validate_fixture_file(FIXTURES / "invalid" / name, vocabs)), name)

    def test_codes(self) -> None:
        cases = [
            (self._block(schema="platform::defender_for_endpoint::1.0"), "microsoft_defender_schema"),
            (self._block(schedule={"frequency": "90M"}), "microsoft_defender_frequency"),
            (self._block(schedule={"frequency": "3H", "lookback": "2H"}), "microsoft_defender_lookback"),
            (self._block(schedule={"frequency": "1H", "lookback": "04H"}), "microsoft_defender_lookback"),
            (self._block(schedule={"frequency": "NRT", "lookback": "1H"}), "microsoft_defender_lookback"),
            (self._block(alert={"severity": "Severe"}), "microsoft_defender_severity"),
            (self._block(alert={"grouping": "per_run"}), "microsoft_defender_grouping"),
            (self._block(alert={"custom_details": {" ": "Col"}}), "microsoft_defender_custom_details"),
            (self._block(entities={"devices": [{"device_id": "DeviceId"}]}), "microsoft_defender_entity_kind"),
            (self._block(entities={"hosts": [{}]}), "microsoft_defender_entity_mapping"),
            (self._block(entities={"hosts": [{"device_id": " "}]}), "microsoft_defender_column"),
            (self._block(actions={"quarantine": [{"device_id": "DeviceId"}]}), "microsoft_defender_action_kind"),
            (self._block(actions={"block_files": [{"device_groups": []}]}), "microsoft_defender_action_target"),
            (self._block(actions={"isolate_devices": [{}]}), "microsoft_defender_action_target"),
            (self._block(actions={"isolate_devices": [{"device_id": "DeviceId", "isolation_type": "Full"}]}), "microsoft_defender_isolation_type"),
            (self._block(scope={"device_groups": []}), "microsoft_defender_scope"),
            (self._block(scope={"selection": "All"}), "microsoft_defender_scope"),
            (self._block(incident={"exclude_from_correlation": "yes"}), "microsoft_defender_incident"),
            (self._block(rule_id=1), "external_id_in_rule"),
        ]
        for block, code in cases:
            with self.subTest(code=code, block=block):
                self.assertIn(code, _codes(validate_microsoft_defender_block(block)))
        for ok in (
            self._block(schedule={"frequency": "24H", "lookback": "1D"}),
            self._block(schedule={"frequency": "2H", "lookback": "30D"}),
            self._block(actions={"isolate_devices": [{"device_id": "DeviceId", "isolation_type": "selective"}]}),
            self._block(actions={"block_files": [{"sha1": "SHA1"}]}),
            {"query": "DeviceEvents", "schedule": {"frequency": "NRT"}},
        ):
            self.assertEqual(validate_microsoft_defender_block(ok), [], ok)


class IndexTests(unittest.TestCase):
    def test_rows(self) -> None:
        specs = _read(ROOT / "SPECS.md")
        self.assertIn("| Microsoft Defender platform | 1.1 | `platform::microsoft_defender::1.0` | normative | [specs/platforms/microsoft-defender-1.0.md](specs/platforms/microsoft-defender-1.0.md) |", specs)
        self.assertIn("| Defender for Endpoint platform (removed) | 1.4 | `platform::defender_for_endpoint::1.0` | deprecated | [specs/platforms/defender-for-endpoint-1.0.md](specs/platforms/defender-for-endpoint-1.0.md) |", specs)
        index = _read(PLATFORMS / "index.md")
        self.assertIn("| `microsoft_defender` | `platform::microsoft_defender::1.0` | [microsoft-defender-1.0.md](microsoft-defender-1.0.md) |", index)
        self.assertIn("| `microsoft_defender` | Microsoft Defender | yes* | yes | KQL |", index)
        self.assertIn("`sentinel`, `microsoft_defender`, `splunk`", index)
        self.assertIn("| `microsoft_defender` | yes |", _read(ROOT / "specs" / "validation.md"))
        self.assertIn("specs/platforms/microsoft-defender-1.0.md (schema_id: platform::microsoft_defender::1.0)", _read(ROOT / "llms.txt"))
        self.assertIn("[0021](0021-defender-graph-beta-detection-rules.md)", _read(ROOT / "rfcs" / "README.md"))
        pages = json.loads(_read(ROOT / "site" / "meta.json"))["pages"]
        self.assertIn("specs/platforms/microsoft-defender-1.0", pages)
        for name in ("rule-1.0.md", "rule-1.1.md"):
            self.assertIn("| `microsoft_defender` | MicrosoftDefenderConfig | `platform::microsoft_defender::1.0` |", _read(ROOT / "specs" / "objects" / name))
        changelog = _read(ROOT / "CHANGELOG.md")
        for heading in (
            "## platform-microsoft-defender 1.1", "## platform-defender-for-endpoint 1.4", "## deployment-state 1.10",
            "## deployment 1.5", "## platforms 1.11", "## validation 1.16", "## workspace 1.6", "## visibility 1.2",
            "## platform-microsoft-defender 1.0",
        ):
            self.assertIn(heading, changelog)
        self.assertNotIn("platform-defender-for-endpoint 2.0", changelog)

    def test_no_trace_of_the_unshipped_2_0(self) -> None:
        for path in [*ROOT.joinpath("specs").rglob("*.md"), ROOT / "SPECS.md", ROOT / "CHANGELOG.md", ROOT / "llms.txt"]:
            # The RFC names the rejected 2.0 draft under Alternatives; nothing normative does.
            text = _read(path)
            self.assertNotIn("defender_for_endpoint::2.0", text, path)
            self.assertNotIn("defender-for-endpoint-2.0", text, path)

    def test_no_defender_shard_key(self) -> None:
        state = _read(ROOT / "specs" / "deployment-state.md")
        self.assertNotIn("defender_for_endpoint` |", state.split("\n## History\n")[0])
        schema = json.loads(_read(ROOT / "schemas" / "deployment.state.1.0.schema.json"))
        self.assertNotIn("defender_for_endpoint", schema["properties"]["platforms"]["properties"])
        self.assertNotIn("microsoft_defender", schema["properties"]["platforms"]["properties"])
        self.assertIn("| `microsoft_defender` ([microsoft-defender-1.0](platforms/microsoft-defender-1.0.md)) | Graph detection-rule `id` is `metadata.uuid` | None |", state)
        self.assertIn("**Superseded in part:** for Microsoft Defender for Endpoint by [RFC 0021]", _read(ROOT / "rfcs" / "0010-deployment-external-ids.md"))
        self.assertNotIn("like Defender for Endpoint", _read(PLATFORMS / "exabeam-1.0.md"))

    def test_rfc_header_and_questions(self) -> None:
        text = _read(RFC)
        self.assertTrue(text.startswith("# RFC 0021: Microsoft Defender on the Graph beta custom detection contract\n"))
        for needle in ("### 5. Rules", "Legacy", "migrate", "defender_platform"):
            self.assertNotIn(needle, text)
        self.assertIn("- **Status:** accepted", text)
        self.assertIn("- **Issue:** [#104](https://github.com/opentidehq/specifications/issues/104)", text)
        questions = _section(text, "Unresolved questions", "##")
        for needle in ("NRT encoding", "404 on update and delete", "Which entity mappings Defender honours"):
            self.assertIn(needle, questions)


class RfcArtefactTests(unittest.TestCase):
    """RFC 0021 carries the platform-RFC artefacts (.agents/skills/platform-rfc), and they match the fixtures."""

    @staticmethod
    def _blocks(text: str, lang: str) -> list[str]:
        return re.findall(rf"```{lang}\n(.*?)```", text, flags=re.S)

    def test_complete_block_is_the_fixture(self) -> None:
        section = _section(_read(RFC), "2.1 Complete block", "####")
        snippet = self._blocks(section, "yaml")[0]
        self.assertEqual(yaml.safe_load(snippet)["configurations"], _load(RULE_COMPLETE)["configurations"])

    def test_minimal_block_is_the_specs_and_valid(self) -> None:
        rfc_minimal = self._blocks(_section(_read(RFC), "2.2 Minimal block", "####"), "yaml")[0]
        spec_minimal = self._blocks(_read(SPEC).split("**Minimal block.**", 1)[1], "yaml")[0]
        self.assertEqual(yaml.safe_load(rfc_minimal), yaml.safe_load(spec_minimal))
        block = yaml.safe_load(rfc_minimal)["configurations"]["microsoft_defender"]
        self.assertEqual(validate_microsoft_defender_block(block), [])

    def test_create_body_is_the_golden(self) -> None:
        text = _read(RFC)
        body = text.split("<!-- rfc0021:complete-create-body -->\n", 1)[1]
        sent = json.loads(self._blocks(body, "json")[0])
        golden = json.loads(_read(GOLDEN / "rule-microsoft-defender-complete.create.api.json"))
        self.assertEqual(sent, golden["body"])
        self.assertIn(f"PATCH {BASE}/{golden['body']['id']}", text)
        self.assertIn(f"POST {BASE}\n", text)

    def test_every_code_is_in_the_validation_table(self) -> None:
        section = _section(_read(RFC), "4. Validation")
        codes = set(re.findall(r"^\| `([a-z_]+)` \|", section, flags=re.MULTILINE))
        for code in CONSTRAINTS + ADVISORIES + DIAGNOSTICS + ["unknown_field", "external_id_in_rule", "tenant_refused"]:
            self.assertIn(code, codes)

    def test_invalid_fixture_headers_name_their_code(self) -> None:
        for name, code in EXPECTED_INVALID_CODES.items():
            if name.startswith("rule-microsoft-defender-"):
                first = _read(FIXTURES / "invalid" / name).splitlines()[0]
                self.assertRegex(first, rf"Expected (constraint )?code: {code}\.", name)

    def test_implementation_and_test_plan_are_linked(self) -> None:
        text = _read(RFC)
        for number in (1856, 1860, 1861):
            self.assertIn(f"https://github.com/opentidehq/opentide/pull/{number}", text)
        self.assertIn(
            "https://github.com/opentidehq/opentide/blob/integration/unified-core/docs/internal/microsoft-defender-tenant-test.md",
            text,
        )

class LinkTests(unittest.TestCase):
    FILES = [
        SPEC, SPEC_OLD, RFC,
        ROOT / "specs" / "deployment-state.md", ROOT / "specs" / "deployment.md", PLATFORMS / "index.md",
        ROOT / "specs" / "validation.md", ROOT / "specs" / "workspace.md", ROOT / "specs" / "visibility.md",
        ROOT / "SPECS.md", ROOT / "CHANGELOG.md",
    ]

    @staticmethod
    def _anchors(text: str) -> set[str]:
        def slug(heading: str) -> str:
            return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")
        return {slug(m.group(1)) for m in re.finditer(r"^#{1,6} (.+)$", text, flags=re.MULTILINE)}

    def test_links_resolve(self) -> None:
        problems = []
        for path in self.FILES:
            for target in re.findall(r"\]\(([^)\s]+)\)", _read(path)):
                if re.match(r"^[a-z]+:", target) or not ("defender" in target or "0021" in target or path in (SPEC, RFC)):
                    continue
                file_part, _, anchor = target.partition("#")
                dest = (path.parent / file_part).resolve() if file_part else path
                if not dest.exists():
                    problems.append(f"{path.name}: {target}")
                elif anchor and dest.suffix == ".md" and anchor not in self._anchors(_read(dest)):
                    problems.append(f"{path.name}: {target} (anchor)")
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
