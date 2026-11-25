#!/usr/bin/env python3
"""Consistency tests for specs/platforms/defender-for-endpoint-2.0.md (RFC 0021), the deprecated 1.0 spec,
their fixtures, and the specs that list Defender for Endpoint.

The Graph request bodies under fixtures/platforms/defender-for-endpoint/ are the goldens implementations
compare against, and migrated-2.0.yaml is `opentide migrate` of the 1.0 fixture. These tests derive both
from the source fixtures by the spec's tables, so a golden cannot drift from the text.
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
    EXPECTED_INVALID_CODES,
    defender_lookback_hours,
    load_vocabularies,
    validate_defender_block,
    validate_fixture_file,
)

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = ROOT / "specs" / "platforms"
SPEC = PLATFORMS / "defender-for-endpoint-2.0.md"
SPEC_V1 = PLATFORMS / "defender-for-endpoint-1.0.md"
RFC = ROOT / "rfcs" / "0021-defender-graph-beta-detection-rules.md"
FIXTURES = ROOT / "fixtures"
RULE_V2 = FIXTURES / "platforms" / "defender-for-endpoint-2.0.yaml"
RULE_V1 = FIXTURES / "platforms" / "defender-for-endpoint.yaml"
RULE_COMPLETE = FIXTURES / "platforms" / "defender-for-endpoint-2.0-complete.yaml"
GOLDEN = FIXTURES / "platforms" / "defender-for-endpoint"
SECTIONS = ["Summary", "Requirements", "Definition", "Relationships", "Defaults & overrides", "Examples", "History"]
V2 = "platform::defender_for_endpoint::2.0"
BASE = "https://graph.microsoft.com/beta/security/rules/detectionRules"

CONSTRAINTS = [
    "defender_frequency",
    "defender_lookback",
    "defender_severity",
    "defender_grouping",
    "defender_custom_details",
    "defender_entity_kind",
    "defender_entity_mapping",
    "defender_action_kind",
    "defender_action_target",
    "defender_column",
    "defender_scope",
]
ADVISORIES = ["defender_schema_deprecated", "defender_no_entities"]
DIAGNOSTICS = [
    "defender_schema_deprecated",
    "defender_schema_retired",
    "defender_migrate_unmapped",
    "defender_rule_absent",
    "defender_legacy_delete_failed",
    "defender_legacy_retired",
]

FREQUENCY = {"NRT": "PT0S", "1H": "PT1H", "3H": "PT3H", "12H": "PT12H", "24H": "P1D"}
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

# Graph v1.0 detectionRule properties the body may hold (api-reference/v1.0, 2026-11-24).
V1_PROPERTIES = {
    "": {"id", "displayName", "description", "status", "queryCondition", "schedule", "detectionAction"},
    "queryCondition": {"queryText"},
    "schedule": {"frequency"},
    "detectionAction": {"alertTemplate", "automatedActions", "organizationalScope"},
    "alertTemplate": {"title", "description", "severity", "recommendedActions", "tactics", "entityMappings", "customDetails"},
    "organizationalScope": {"deviceGroups"},
}
DEPRECATED = {"isEnabled", "period", "category", "mitreTechniques", "impactedAssets", "responseActions", "scopeType", "scopeNames"}


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


# --- the spec's derivations ------------------------------------------------------------------------


def tactics(ids: list[str], attack: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """specs/platforms/defender-for-endpoint-2.0.md#attck."""
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
    hours = defender_lookback_hours(value)
    assert hours is not None
    return f"P{value[:-1]}D" if value.endswith("D") else f"PT{value[:-1]}H"


def body(
    rule: dict[str, Any], strategy: str, attack: dict[str, dict[str, Any]], create: bool, tenant: str = "contoso"
) -> dict[str, Any]:
    """specs/platforms/defender-for-endpoint-2.0.md#request-body for `tenant`.

    The spec does not fix how an exclusion is spliced into the query, so a golden may only hold
    exclusions scoped to another tenant: those are skipped and the query is sent unchanged.
    """
    block = rule["configurations"]["defender_for_endpoint"]
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
    schedule = {"frequency": FREQUENCY[block["schedule"]["frequency"]]}
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


def _column(value: str) -> str:
    return value[:1].upper() + value[1:]


def _ident(value: str) -> str:
    return value[:1].lower() + value[1:]


DEVICE_ENTITY = {"deviceId": "device_id", **{k: "name" for k in ("deviceName", "remoteDeviceName", "targetDeviceName", "destinationDeviceName")}}
USER_ENTITY = {
    **{k: "aad_user_id" for k in ("accountObjectId", "recipientObjectId", "processAccountObjectId")},
    **{k: "sid" for k in ("accountSid", "requestAccountSid", "initiatingAccountSid")},
    **{k: "upn" for k in ("accountUpn", "initiatingProcessAccountUpn", "targetAccountUpn")},
    **{k: "name" for k in ("accountName", "requestAccountName", "initiatingAccountName")},
    **{k: "nt_domain" for k in ("accountDomain", "requestAccountDomain", "initiatingAccountDomain")},
}
MAILBOX_ENTITY = {
    k: "primary_address"
    for k in (
        "accountUpn", "fileOwnerUpn", "initiatingProcessAccountUpn", "lastModifyingAccountUpn", "targetAccountUpn",
        "senderFromAddress", "senderMailFromAddress", "recipientEmailAddress",
    )
}
DEVICE_FLAGS = {
    "collect_investigation_package": "collect_investigation_packages",
    "run_antivirus_scan": "run_antivirus_scans",
    "initiate_investigation": "initiate_investigations",
    "restrict_app_execution": "restrict_app_executions",
}


class Unmapped(Exception):
    pass


def migrate(block: dict[str, Any]) -> dict[str, Any]:
    """specs/platforms/defender-for-endpoint-2.0.md#migration-from-10. Raises Unmapped (defender_migrate_unmapped)."""
    out: dict[str, Any] = {}
    for key in ("enabled", "name"):
        if key in block:
            out[key] = block[key]
    out["schema"] = V2
    for key in ("status", "flags", "tenants", "contributors", "query"):
        if key in block:
            out[key] = block[key]
    out["schedule"] = {"frequency": block["scheduling"]}
    alert = {k: v for k, v in (block.get("alert") or {}).items() if k != "category"}
    if alert:
        out["alert"] = alert

    entities: dict[str, list[dict[str, str]]] = {}
    for key, table, kind in (("device", DEVICE_ENTITY, "hosts"), ("user", USER_ENTITY, "accounts"), ("mailbox", MAILBOX_ENTITY, "mailboxes")):
        value = (block.get("impacted_entities") or {}).get(key)
        if value is None:
            continue
        if _ident(value) not in table:
            raise Unmapped(f"impacted_entities.{key}: {value}")
        entities.setdefault(kind, []).append({table[_ident(value)]: _column(value)})
    if entities:
        out["entities"] = entities

    actions: dict[str, list[dict[str, Any]]] = {}
    devices = (block.get("actions") or {}).get("devices") or {}
    if devices.get("isolate_device"):
        actions["isolate_devices"] = [{"device_id": "DeviceId", "isolation_type": _ident(devices["isolate_device"])}]
    for flag, name in DEVICE_FLAGS.items():
        if devices.get(flag):
            actions[name] = [{"device_id": "DeviceId"}]
    files = (block.get("actions") or {}).get("files") or {}
    allow_block = files.get("allow_block")
    if allow_block:
        ident = _ident(allow_block["identifier"])
        field = {"sha1": "sha1", "initiatingProcessSHA1": "sha1", "sha256": "sha256", "initiatingProcessSHA256": "sha256"}.get(ident)
        if field is None:
            raise Unmapped(f"actions.files.allow_block.identifier: {allow_block['identifier']}")
        target: dict[str, Any] = {field: _column(allow_block["identifier"])}
        groups = allow_block.get("groups") or {}
        if groups.get("selection") == "Specific":
            if not groups.get("device_groups"):
                raise Unmapped("actions.files.allow_block.groups")
            target["device_groups"] = list(groups["device_groups"])
        actions["allow_files" if allow_block["action"] == "Allow" else "block_files"] = [target]
    quarantine = files.get("quarantine_file") or files.get("quarantine_files")
    if quarantine:
        if _ident(quarantine) not in ("sha1", "initiatingProcessSHA1"):
            raise Unmapped(f"actions.files.quarantine_file: {quarantine}")
        actions["stop_and_quarantine_files"] = [{"device_id": "DeviceId", "sha1": _column(quarantine)}]
    users = (block.get("actions") or {}).get("users") or {}
    for key, name, field in (
        ("mark_as_compromised", "mark_users_as_compromised", "account_object_id"),
        ("disable_user", "disable_users", "account_sid"),
        ("force_password_reset", "force_user_password_resets", "account_sid"),
    ):
        if users.get(key):
            actions[name] = [{field: _column(users[key])}]
    if actions:
        out["actions"] = actions

    scope = block.get("scope") or {}
    if scope.get("selection") == "Specific":
        if not scope.get("device_groups"):
            raise Unmapped("scope.device_groups")
        out["scope"] = {"device_groups": list(scope["device_groups"])}
    if block.get("exclusions"):
        out["exclusions"] = block["exclusions"]
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
        self.assertEqual(meta["schema_id"], V2)
        self.assertEqual(meta["status"], "normative")
        self.assertEqual(meta["version"], "2.0")
        self.assertEqual(meta["supersedes"], "platform::defender_for_endpoint::1.0")
        self.assertEqual(re.findall(r"^## (.+)$", text, flags=re.MULTILINE), SECTIONS)

    def test_v1_is_deprecated_and_kept(self) -> None:
        text = _read(SPEC_V1)
        meta = _frontmatter(text)
        self.assertEqual(meta["status"], "deprecated")
        self.assertEqual(meta["schema_id"], "platform::defender_for_endpoint::1.0")
        self.assertEqual(meta["version"], "1.4")
        self.assertEqual(re.findall(r"^## (.+)$", text, flags=re.MULTILINE), SECTIONS)
        deprecation = _section(text, "Deprecation")
        for needle in ("`defender_schema_deprecated`", "`defender_schema_retired`", "`opentide migrate`", "defender-for-endpoint-2.0.md#migration-from-10"):
            self.assertIn(needle, deprecation)

    def test_constraint_advisory_and_diagnostic_codes(self) -> None:
        text = _read(SPEC)
        self.assertEqual(re.findall(r"^\| `(defender_[a-z_]+)` \|", _section(text, "Constraints"), flags=re.MULTILINE), CONSTRAINTS)
        self.assertEqual(re.findall(r"^\| `(defender_[a-z_]+)` \|", _section(text, "Advisories"), flags=re.MULTILINE), ADVISORIES)
        self.assertEqual(re.findall(r"^\| `(defender_[a-z_]+)` \|", _section(text, "Diagnostics"), flags=re.MULTILINE), DIAGNOSTICS)
        validation = _read(ROOT / "specs" / "validation.md")
        for code in ADVISORIES:
            self.assertIn(f"| `{code}` | warning | Defender for Endpoint:", validation)

    def test_entity_table_is_the_checker_table(self) -> None:
        section = _section(_read(SPEC), "`entities` (DefenderEntities)")
        rows = re.findall(r"^\| `([a-z_]+)` \| `([A-Za-z]+)` \| (.+) \|$", section, flags=re.MULTILINE)
        parsed = {kind: (graph, dict(re.findall(r"`([a-z_0-9]+)` → `([A-Za-z0-9]+)`", fields))) for kind, graph, fields in rows}
        self.assertEqual(parsed, DEFENDER_ENTITIES)
        self.assertEqual(len(parsed), 17)

    def test_action_table_is_the_checker_table(self) -> None:
        section = _section(_read(SPEC), "`actions` (DefenderActions)")
        rows = re.findall(r"^\| `([a-z_]+)` \| `([A-Za-z]+)` \| ([^|]+) \| ([^|]+) \|$", section, flags=re.MULTILINE)
        self.assertEqual([r[0] for r in rows], list(DEFENDER_ACTIONS))
        email = None
        for action, graph, fields, _ in rows:
            expected_graph, expected_fields, _ = DEFENDER_ACTIONS[action]
            self.assertEqual(graph, expected_graph, action)
            parsed = dict(re.findall(r"`([a-z_0-9]+)` → `([A-Za-z0-9]+)`", fields))
            if fields.startswith("same as"):
                parsed = email
            elif action == "soft_delete_emails":
                email = parsed
            self.assertEqual(parsed, expected_fields, action)

    def test_frequency_and_beta_tables(self) -> None:
        text = _read(SPEC)
        schedule = _section(text, "`schedule` (DefenderSchedule)")
        self.assertEqual(dict(re.findall(r"^\| `([0-9A-Z]+)` \| `([0-9A-Z]+)`", schedule, flags=re.MULTILINE)), FREQUENCY)
        beta = _section(text, "Beta-only keys")
        self.assertEqual(re.findall(r"^\| `([a-z_.]+)` \|", beta, flags=re.MULTILINE), ["schedule.lookback", "alert.grouping", "incident"])
        attack = _section(text, "ATT&CK")
        for stages, tactic in TACTICS:
            self.assertRegex(attack, rf"\| {re.escape(', '.join(stages) if len(stages) == 1 else stages[0])}[^|]* \| `{tactic}` \|")


class GoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.attack = _attack()
        cls.rule = _load(RULE_V2)

    def _golden(self, name: str) -> dict[str, Any]:
        return json.loads(_read(GOLDEN / name))

    def test_create(self) -> None:
        golden = self._golden("rule-defender-2.0.create.api.json")
        self.assertEqual(golden["method"], "POST")
        self.assertEqual(golden["url"], BASE)
        self.assertEqual(golden["body"], body(self.rule, "RELEASE", self.attack, create=True))

    def test_update_is_create_without_id(self) -> None:
        golden = self._golden("rule-defender-2.0.update.api.json")
        uuid = self.rule["metadata"]["uuid"]
        self.assertEqual(golden["method"], "PATCH")
        self.assertEqual(golden["url"], f"{BASE}/{uuid}")
        self.assertEqual(golden["body"], body(self.rule, "RELEASE", self.attack, create=False))
        self.assertNotIn("id", golden["body"])

    def test_disable(self) -> None:
        golden = self._golden("rule-defender-2.0.disable.api.json")
        self.assertEqual(golden["method"], "PATCH")
        self.assertEqual(golden["body"]["status"], "disabled")
        self.assertEqual(golden["body"], body(self.rule, "DISABLEMENT", self.attack, create=False))

    def test_tactics_of_the_example(self) -> None:
        derived = tactics(["T1059.001", "T1078.004"], self.attack)
        self.assertEqual([t["tactic"] for t in derived], ["InitialAccess", "Execution", "Persistence", "PrivilegeEscalation", "DefenseEvasion"])
        self.assertEqual(derived[1]["techniques"], [{"technique": "T1059", "subTechniques": ["T1059.001"]}])
        self.assertEqual(tactics(["T1078"], self.attack)[0]["techniques"], [{"technique": "T1078"}])

    def test_no_deprecated_property_and_v1_without_beta_keys(self) -> None:
        full = body(self.rule, "RELEASE", self.attack, create=True)
        keys = _walk(full)
        self.assertFalse({k for _, k in keys} & DEPRECATED)
        self.assertTrue(BETA_ONLY & set(keys))
        plain = json.loads(json.dumps(self.rule))
        block = plain["configurations"]["defender_for_endpoint"]
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
        cls.block = cls.rule["configurations"]["defender_for_endpoint"]

    @staticmethod
    def _table_keys(heading: str) -> list[str]:
        section = _section(_read(SPEC), heading)
        table = section.split("\n\n|", 1)[1] if "\n\n|" in section else section
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
        for key in shared + self._table_keys("Block"):
            if key not in self.block:
                missing.append(key)
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
        for action, (_, fields, _) in DEFENDER_ACTIONS.items():
            targets = (self.block.get("actions") or {}).get(action) or [{}]
            missing += [f"actions.{action}.{f}" for f in fields if not any(f in t for t in targets)]
        self.assertEqual(missing, [])

    def test_valid(self) -> None:
        self.assertEqual(validate_defender_block(self.block), [])
        self.assertEqual(validate_fixture_file(RULE_COMPLETE, load_vocabularies(ROOT / "vocabularies")), [])

    def test_spec_example_is_the_fixture(self) -> None:
        examples = _section(_read(SPEC), "Examples", "##")
        complete = examples.split("**Complete block.**", 1)[1]
        snippet = re.search(r"```yaml\n(.*?)```", complete, flags=re.S).group(1)
        self.assertEqual(yaml.safe_load(snippet)["configurations"], self.rule["configurations"])
        fixture_text = _read(RULE_COMPLETE)
        self.assertIn(snippet.split("configurations:\n", 1)[1], fixture_text)

    def test_beta_only_keys_are_commented(self) -> None:
        text = _read(RULE_COMPLETE)
        for line in ("lookback: 4H  # beta-only", "grouping: single_alert  # beta-only", "incident:  # beta-only"):
            self.assertIn(line, text)

    def test_create_golden(self) -> None:
        golden = json.loads(_read(GOLDEN / "rule-defender-2.0-complete.create.api.json"))
        self.assertEqual(golden["method"], "POST")
        self.assertEqual(golden["url"], BASE)
        self.assertEqual(golden["body"], body(self.rule, "RELEASE", _attack(), create=True, tenant="contoso"))
        mappings = golden["body"]["detectionAction"]["alertTemplate"]["entityMappings"]
        self.assertEqual(len(mappings), 17)
        self.assertEqual(len(golden["body"]["detectionAction"]["automatedActions"]), 16)


class MigrationTests(unittest.TestCase):
    def test_v1_fixture_migrates_to_the_golden(self) -> None:
        source, migrated = _load(RULE_V1), _load(GOLDEN / "migrated-2.0.yaml")
        block = source["configurations"].pop("defender_for_endpoint")
        target = migrated["configurations"].pop("defender_for_endpoint")
        self.assertEqual(target, migrate(block))
        self.assertEqual(source, migrated)
        self.assertEqual(validate_defender_block(target), [])

    def test_only_the_block_changes(self) -> None:
        before = _read(RULE_V1).split("  defender_for_endpoint:\n")[0]
        self.assertTrue(_read(GOLDEN / "migrated-2.0.yaml").startswith(before))

    def test_unmapped_values(self) -> None:
        base = {"schema": "platform::defender_for_endpoint::1.0", "query": "T", "scheduling": "1H", "alert": {}}
        for extra in (
            {"impacted_entities": {"user": "ServicePrincipalId"}},
            {"impacted_entities": {"mailbox": "SenderDisplayName"}},
            {"impacted_entities": {"device": "DeviceIp"}},
            {"actions": {"files": {"quarantine_file": "SHA256"}}},
            {"actions": {"files": {"allow_block": {"action": "Block", "identifier": "FileName"}}}},
            {"scope": {"selection": "Specific"}},
        ):
            with self.subTest(extra=extra), self.assertRaises(Unmapped):
                migrate({**base, **extra})

    def test_identifier_case(self) -> None:
        block = {"query": "T", "scheduling": "NRT", "impacted_entities": {"device": "deviceId", "user": "InitiatingProcessAccountUpn"}}
        self.assertEqual(migrate(block)["entities"], {"hosts": [{"device_id": "DeviceId"}], "accounts": [{"upn": "InitiatingProcessAccountUpn"}]})


class CheckerTests(unittest.TestCase):
    def _block(self, **keys: Any) -> dict[str, Any]:
        return {"schema": V2, "query": "DeviceEvents", "schedule": {"frequency": "1H"}, **keys}

    def test_fixtures(self) -> None:
        vocabs = load_vocabularies(ROOT / "vocabularies")
        for path in (RULE_V2, RULE_V1, GOLDEN / "migrated-2.0.yaml"):
            self.assertEqual(validate_fixture_file(path, vocabs), [], path.name)
        for name in ("rule-defender-lookback-nrt.yaml", "rule-defender-entity-field.yaml", "rule-defender-action-target.yaml", "rule-defender-1.0-keys.yaml"):
            self.assertIn(EXPECTED_INVALID_CODES[name], _codes(validate_fixture_file(FIXTURES / "invalid" / name, vocabs)), name)

    def test_codes(self) -> None:
        cases = [
            (self._block(schedule={"frequency": "2H"}), "defender_frequency"),
            (self._block(schedule={"frequency": "3H", "lookback": "2H"}), "defender_lookback"),
            (self._block(schedule={"frequency": "1H", "lookback": "04H"}), "defender_lookback"),
            (self._block(alert={"severity": "Severe"}), "defender_severity"),
            (self._block(alert={"grouping": "per_run"}), "defender_grouping"),
            (self._block(alert={"custom_details": {" ": "Col"}}), "defender_custom_details"),
            (self._block(entities={"devices": [{"device_id": "DeviceId"}]}), "defender_entity_kind"),
            (self._block(entities={"hosts": [{}]}), "defender_entity_mapping"),
            (self._block(entities={"hosts": [{"device_id": "Device Id"}]}), "defender_column"),
            (self._block(actions={"quarantine": [{"device_id": "DeviceId"}]}), "defender_action_kind"),
            (self._block(actions={"block_files": [{"device_groups": ["A"]}]}), "defender_action_target"),
            (self._block(actions={"isolate_devices": [{"device_id": "DeviceId", "isolation_type": "Full"}]}), "defender_action_target"),
            (self._block(scope={"device_groups": []}), "defender_scope"),
            (self._block(scope={"selection": "All"}), "defender_scope"),
            (self._block(rule_id=1), "external_id_in_rule"),
        ]
        for block, code in cases:
            with self.subTest(code=code, block=block):
                self.assertIn(code, _codes(validate_defender_block(block)))
        self.assertEqual(validate_defender_block(self._block(schedule={"frequency": "24H", "lookback": "1D"})), [])
        self.assertEqual(validate_defender_block({"schema": "platform::defender_for_endpoint::1.0", "scheduling": "2H"}), [])


class IndexTests(unittest.TestCase):
    def test_rows(self) -> None:
        specs = _read(ROOT / "SPECS.md")
        self.assertIn("| Defender for Endpoint platform | 2.0 | `platform::defender_for_endpoint::2.0` | normative | [specs/platforms/defender-for-endpoint-2.0.md](specs/platforms/defender-for-endpoint-2.0.md) |", specs)
        self.assertIn("| Defender for Endpoint platform | 1.4 | `platform::defender_for_endpoint::1.0` | deprecated | [specs/platforms/defender-for-endpoint-1.0.md](specs/platforms/defender-for-endpoint-1.0.md) |", specs)
        index = _read(PLATFORMS / "index.md")
        self.assertIn("| `defender_for_endpoint` | `platform::defender_for_endpoint::2.0` | [defender-for-endpoint-2.0.md](defender-for-endpoint-2.0.md) |", index)
        self.assertIn("| `defender_for_endpoint` (deprecated) | `platform::defender_for_endpoint::1.0` |", index)
        self.assertIn("specs/platforms/defender-for-endpoint-2.0.md (schema_id: platform::defender_for_endpoint::2.0)", _read(ROOT / "llms.txt"))
        self.assertIn("[0021](0021-defender-graph-beta-detection-rules.md)", _read(ROOT / "rfcs" / "README.md"))
        self.assertIn("specs/platforms/defender-for-endpoint-2.0", json.loads(_read(ROOT / "site" / "meta.json"))["pages"])
        for name in ("rule-1.0.md", "rule-1.1.md"):
            self.assertIn("| `defender_for_endpoint` | DefenderConfig | `platform::defender_for_endpoint::2.0`;", _read(ROOT / "specs" / "objects" / name))
        changelog = _read(ROOT / "CHANGELOG.md")
        for heading in (
            "## platform-defender-for-endpoint 2.0", "## platform-defender-for-endpoint 1.4", "## deployment-state 1.10",
            "## deployment 1.5", "## platforms 1.11", "## validation 1.16", "## workspace 1.6",
        ):
            self.assertIn(heading, changelog)

    def test_defender_left_the_state_backed_set(self) -> None:
        state = _read(ROOT / "specs" / "deployment-state.md")
        decisions = _section(state, "Deploy decisions")
        self.assertNotIn("`defender_for_endpoint`, `sentinel_one`", decisions)
        self.assertIn("#### Legacy Defender bindings", decisions)
        schema = json.loads(_read(ROOT / "schemas" / "deployment.state.1.0.schema.json"))
        self.assertIn("defender_for_endpoint", schema["properties"]["platforms"]["properties"])
        self.assertIn("**Superseded in part:** for Microsoft Defender for Endpoint by [RFC 0021]", _read(ROOT / "rfcs" / "0010-deployment-external-ids.md"))

    def test_rfc_header_and_questions(self) -> None:
        text = _read(RFC)
        self.assertTrue(text.startswith("# RFC 0021: Defender for Endpoint on the Graph beta custom detection contract\n"))
        self.assertIn("- **Status:** accepted", text)
        questions = _section(text, "Unresolved questions", "##")
        for needle in ("NRT encoding", "404 on update and delete", "Which entity mappings Defender honours"):
            self.assertIn(needle, questions)


class LinkTests(unittest.TestCase):
    FILES = [
        SPEC, SPEC_V1, RFC,
        ROOT / "specs" / "deployment-state.md", ROOT / "specs" / "deployment.md", ROOT / "specs" / "platforms" / "index.md",
        ROOT / "specs" / "validation.md", ROOT / "specs" / "workspace.md", ROOT / "SPECS.md", ROOT / "CHANGELOG.md",
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
