#!/usr/bin/env python3
"""Consistency tests for specs/platforms/graylog-1.0.md, its fixtures, and the specs that list Graylog.

The request files under fixtures/platforms/graylog/ are the goldens implementations compare against, one
per server version. These tests derive each request from its source rule fixture and the fixture tenant by
the spec's rules (version table, title, description, priority, tags, ATT&CK, event fields, the condition
compilation), so a golden cannot drift from the text.
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
    GraylogConditionError,
    duration_seconds,
    graylog_event_field_kind,
    graylog_list,
    load_vocabularies,
    parse_graylog_condition,
    validate_fixture_file,
    validate_graylog_block,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specs" / "platforms" / "graylog-1.0.md"
ELASTIC = ROOT / "specs" / "platforms" / "elastic-1.0.md"
INDEX = ROOT / "specs" / "platforms" / "index.md"
FIXTURES = ROOT / "fixtures"
GOLDEN = FIXTURES / "platforms" / "graylog"
SECTIONS = ["Summary", "Requirements", "Definition", "Relationships", "Defaults & overrides", "Examples", "History"]
SAMPLE_ID = "65f1c0de2a3b4c5d6e7f8091"

PRIORITY = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
CONSTRAINTS = [
    "graylog_query_blank",
    "graylog_list_shape",
    "graylog_schedule",
    "graylog_event_limit",
    "graylog_aggregation",
    "graylog_event_field",
    "graylog_event_key",
    "graylog_priority",
    "graylog_field_name",
    "graylog_query_syntax",
    "graylog_leading_wildcard",
    "graylog_regex_unsupported",
]
ADVISORIES = [
    "graylog_overlapping_window",
    "graylog_lowercase_operator",
    "graylog_regex_operator",
    "graylog_regex_quote",
    "graylog_double_backslash",
    "graylog_analyzed_field",
    "graylog_all_streams",
    "graylog_title_duplicate",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _codes(errors: list[Any]) -> set[str]:
    return {error.code for error in errors}


def _version(text: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in text.split("+", 1)[0].split(".")[:3])
    return major, minor, patch


# --- the spec's derivations ------------------------------------------------------------------------


def _tactic_table() -> tuple[list[tuple[str, str]], dict[str, str]]:
    """The Elastic stage → tactic table and its legacy-stage renames, read from the spec."""
    text = _read(ELASTIC)
    section = text[text.index("### ATT&CK") :]
    tactics = re.findall(r"^\| ([A-Z][A-Za-z ]+) \| (TA\d{4}) \|$", section, flags=re.MULTILINE)
    legacy = dict(re.findall(r"^\| ([A-Z][A-Za-z ]+) \| ([A-Z][A-Za-z ]+) \|$", section.split("| Legacy stage | Stage |", 1)[1], flags=re.MULTILINE))
    return tactics, legacy


def _attack_vocab() -> dict[str, dict[str, Any]]:
    data = tomllib.loads(_read(ROOT / "vocabularies" / "att&ck.vocab.toml"))
    return {entry["id"]: entry for entry in data["keys"]}


def attack_ids(rule: dict[str, Any]) -> list[str]:
    """specs/platforms/graylog-1.0.md#attck: Enterprise techniques by id, then their tactics in table order."""
    vocab = _attack_vocab()
    techniques = sorted(
        t for t in set(rule.get("techniques") or [])
        if t in vocab and not str(vocab[t].get("name", "")).startswith(("Mobile : ", "Industrial : "))
    )
    tactics, legacy = _tactic_table()
    stages = {legacy.get(stage, stage) for t in techniques for stage in vocab[t].get("tide.vocab.stages", [])}
    return (techniques + [tactic for stage, tactic in tactics if stage in stages])[:64]


def gl_title(rule: dict[str, Any]) -> str:
    return rule["configurations"]["graylog"].get("name") or rule["name"]


def gl_description(rule: dict[str, Any], version: tuple[int, int, int]) -> str:
    text = " ".join(str(rule.get("description", "")).split())
    ids = attack_ids(rule)
    if version < (7, 2, 0) and ids:
        text += "\n\nATT&CK: " + ", ".join(ids)
    return text


def gl_priority(rule: dict[str, Any], version: tuple[int, int, int]) -> int:
    block = rule["configurations"]["graylog"]
    label = block.get("priority") or (rule.get("response") or {}).get("alert_severity")
    value = PRIORITY.get(label, 2)
    return 1 if value == 0 and version < (7, 1, 0) else value


def gl_tags(rule: dict[str, Any], setup: dict[str, Any]) -> list[str]:
    block = rule["configurations"]["graylog"]
    candidates = [
        *(graylog_list(block.get("tags")) or []),
        "opentide",
        f"opentide.{rule['metadata']['uuid']}",
        *(graylog_list(setup.get("tags")) or []),
    ]
    tags: list[str] = []
    for tag in candidates:
        tag = re.sub(r"[^a-z0-9_.-]", "-", str(tag).lower())[:128]
        if tag and tag not in tags:
            tags.append(tag)
    return tags[:64]


def _provider(value: Any) -> dict[str, Any]:
    kind = graylog_event_field_kind(value)
    if kind == "field":
        return {"type": "template-v1", "template": "${source." + value + "}", "require_values": False}
    if kind == "template":
        template = value if isinstance(value, str) else value["template"]
        return {"type": "template-v1", "template": template, "require_values": False}
    lookup = value["lookup"]
    return {"type": "lookup-v1", "table_name": lookup["table"], "key_field": lookup["key_field"]}


def gl_field_spec(rule: dict[str, Any], version: tuple[int, int, int]) -> dict[str, Any]:
    block = rule["configurations"]["graylog"]
    spec = {name: {"data_type": "string", "providers": [_provider(value)]} for name, value in (block.get("event_fields") or {}).items()}
    ids = attack_ids(rule)
    if version < (7, 2, 0) and ids and "attack_techniques" not in spec:
        spec["attack_techniques"] = {
            "data_type": "string",
            "providers": [{"type": "template-v1", "template": ",".join(ids), "require_values": False}],
        }
    return spec


def gl_config(rule: dict[str, Any], setup: dict[str, Any]) -> dict[str, Any]:
    block = rule["configurations"]["graylog"]
    schedule = block.get("schedule") or {}
    aliases = graylog_list(block.get("streams")) or graylog_list(setup.get("streams")) or []
    window = duration_seconds(schedule.get("window") or schedule.get("every") or "5m") * 1000
    every = window if schedule.get("cron") else duration_seconds(schedule.get("every") or "5m") * 1000
    config: dict[str, Any] = {
        "type": "aggregation-v1",
        "query": block["query"],
        "query_parameters": [],
        "filters": [],
        "streams": [setup["stream_ids"][alias] for alias in aliases],
        "stream_categories": graylog_list(block.get("stream_categories")) or [],
    }
    aggregation = block.get("aggregation")
    if aggregation:
        tree, series = parse_graylog_condition(aggregation["condition"])
        config.update(group_by=graylog_list(aggregation.get("group_by")) or [], series=series, conditions={"expression": tree})
    else:
        config.update(group_by=[], series=[], conditions={"expression": None})
    config.update(search_within_ms=window, execute_every_ms=every, use_cron_scheduling=bool(schedule.get("cron")))
    if schedule.get("cron"):
        config.update(cron_expression=schedule["cron"], cron_timezone=schedule.get("timezone", "UTC"))
    if not aggregation:
        config["event_limit"] = block.get("event_limit", 100)
    return config


def gl_definition(rule: dict[str, Any], setup: dict[str, Any], version: tuple[int, int, int]) -> dict[str, Any]:
    block = rule["configurations"]["graylog"]
    definition: dict[str, Any] = {
        "_scope": "DEFAULT",
        "title": gl_title(rule),
        "description": gl_description(rule, version),
        "priority": gl_priority(rule, version),
        "alert": block.get("alert", True),
    }
    if block.get("remediation"):
        definition["remediation_steps"] = block["remediation"]
    if block.get("summary") and version >= (7, 1, 0):
        definition["event_summary_template"] = block["summary"]
    if version >= (7, 2, 0):
        definition["tags"] = gl_tags(rule, setup)
        definition["tactics_techniques"] = attack_ids(rule)
    definition["config"] = gl_config(rule, setup)
    definition["field_spec"] = gl_field_spec(rule, version)
    definition["key_spec"] = graylog_list(block.get("event_key")) or []
    definition["notification_settings"] = {
        "grace_period_ms": (duration_seconds(block["grace_period"]) or 0) * 1000 if block.get("grace_period") else 0,
        "backlog_size": block.get("backlog", 0),
    }
    definition["notifications"] = [
        {"notification_id": setup["notification_ids"][alias]} for alias in graylog_list(block.get("notifications")) or []
    ]
    return definition


def build(rule: dict[str, Any], setup: dict[str, Any], server: str, op: str) -> dict[str, Any]:
    version = _version(server)
    definition = gl_definition(rule, setup, version)
    if op == "create":
        body = dict(definition, share_request=None) if version < (7, 0, 0) else {"entity": definition, "share_request": None}
        return {"method": "POST", "path": "/api/events/definitions?schedule=true", "body": body}
    schedule = "false" if op == "disable" else "true"
    return {"method": "PUT", "path": f"/api/events/definitions/{SAMPLE_ID}?schedule={schedule}", "body": dict(definition, id=SAMPLE_ID)}


GOLDENS = {
    "rule-graylog-aggregation-1.0.7.2.create.api.json": ("rule-graylog-aggregation-1.0.yaml", "7.2.2", "create"),
    "rule-graylog-aggregation-1.0.7.2.update.api.json": ("rule-graylog-aggregation-1.0.yaml", "7.2.2", "update"),
    "rule-graylog-aggregation-1.0.7.2.disable.api.json": ("rule-graylog-aggregation-1.0.yaml", "7.2.2", "disable"),
    "rule-graylog-aggregation-1.0.7.0.create.api.json": ("rule-graylog-aggregation-1.0.yaml", "7.0.16", "create"),
    "rule-graylog-aggregation-1.0.6.3.create.api.json": ("rule-graylog-aggregation-1.0.yaml", "6.3.5", "create"),
    "rule-graylog-filter-1.1.7.1.create.api.json": ("rule-graylog-filter-1.1.yaml", "7.1.12", "create"),
    "rule-graylog-filter-1.1.6.3.create.api.json": ("rule-graylog-filter-1.1.yaml", "6.3.5", "create"),
}


def _tenant_setup() -> dict[str, Any]:
    return tomllib.loads(_read(GOLDEN / "tenant.toml"))["tenants"][0]["setup"]


def _rule(name: str) -> dict[str, Any]:
    return yaml.safe_load(_read(FIXTURES / "valid" / name))


def render(request: dict[str, Any]) -> str:
    return json.dumps(request, indent=2, ensure_ascii=False) + "\n"


# --- tests -----------------------------------------------------------------------------------------


class SpecShapeTests(unittest.TestCase):
    def test_frontmatter_and_sections(self) -> None:
        text = _read(SPEC)
        self.assertIn("schema_id: platform::graylog::1.0", text)
        self.assertIn("status: normative", text)
        self.assertEqual(re.findall(r"^## (.+)$", text, flags=re.MULTILINE), SECTIONS)

    def test_constraint_and_advisory_tables(self) -> None:
        text = _read(SPEC)
        section = text[text.index("### Constraints") : text.index("Every implementation reports each code")]
        self.assertEqual(re.findall(r"^\| `(graylog_[a-z_]+)` \|", section, flags=re.MULTILINE), CONSTRAINTS)
        advisories = text[text.index("### Advisories") : text.index("### Query dialect")]
        self.assertEqual(re.findall(r"^\| `(graylog_[a-z_]+)` \|", advisories, flags=re.MULTILINE), ADVISORIES)
        validation = _read(ROOT / "specs" / "validation.md")
        for code in ADVISORIES:
            self.assertIn(f"| `{code}` | warning |", validation)
        paths = text[text.index("| Code | `field_path` |") : text.index("### Advisories")]
        for code in CONSTRAINTS:
            self.assertIn(f"`{code}`", paths)

    def test_priority_table(self) -> None:
        section = _read(SPEC).split("### Priority", 1)[1].split("###", 1)[0]
        for label, value in PRIORITY.items():
            self.assertRegex(section, rf"\| `{label}` \| {value}( |\b)")

    def test_version_rules(self) -> None:
        text = _read(SPEC)
        self.assertIn("Deploy MUST NOT send `id` on create.", text)
        self.assertIn("Every `PUT` MUST carry `?schedule=true` or `?schedule=false`.", text)
        self.assertIn("| 6.3.x | the definition, with `share_request` beside its fields |", text)
        self.assertIn("| 7.0.x | `{\"entity\": <definition>, \"share_request\": null}` |", text)
        self.assertIn("`^[0-9a-f]{24}$`", text)


class ConditionTests(unittest.TestCase):
    def test_compiles_to_graylog_tree(self) -> None:
        tree, series = parse_graylog_condition("count() >= 3 OR card(parent_image_lc) >= 2")
        self.assertEqual(
            series,
            [{"id": "count-", "type": "count"}, {"id": "card-parent_image_lc", "type": "card", "field": "parent_image_lc"}],
        )
        self.assertEqual(tree["expr"], "||")
        self.assertEqual(tree["left"], {"expr": ">=", "left": {"expr": "number-ref", "ref": "count-"}, "right": {"expr": "number", "value": 3}})

    def test_precedence_and_reuse(self) -> None:
        tree, series = parse_graylog_condition("NOT count() > 1 AND count() < 10 OR percentile(bytes, 95) > 2.5")
        self.assertEqual([s["id"] for s in series], ["count-", "percentile-bytes-95"])
        self.assertEqual(series[1]["percentile"], 95.0)
        self.assertEqual(tree["expr"], "||")
        self.assertEqual(tree["left"]["expr"], "&&")
        self.assertEqual(tree["left"]["left"]["expr"], "!")
        self.assertEqual(tree["right"]["right"], {"expr": "number", "value": 2.5})

    def test_refusals(self) -> None:
        for text in (
            "",
            "count() >= 3 or count() < 9",
            "total(bytes) > 1",
            "avg() > 1",
            "count(a, b) > 1",
            "percentile(bytes) > 1",
            "percentile(bytes, 101) > 1",
            "count() >= ",
            "(count() > 1",
            "count() = 1",
        ):
            with self.subTest(text=text), self.assertRaises(GraylogConditionError):
                parse_graylog_condition(text)


class GoldenTests(unittest.TestCase):
    def test_goldens_follow_the_spec(self) -> None:
        setup = _tenant_setup()
        for golden, (source, server, op) in GOLDENS.items():
            with self.subTest(golden=golden):
                expected = build(_rule(source), setup, server, op)
                self.assertEqual(json.loads(_read(GOLDEN / golden)), expected)
                self.assertEqual(_read(GOLDEN / golden), render(expected))

    def test_golden_set_is_complete(self) -> None:
        self.assertEqual(sorted(p.name for p in GOLDEN.glob("*.api.json")), sorted(GOLDENS))

    def test_version_differences(self) -> None:
        setup = _tenant_setup()
        rule = _rule("rule-graylog-aggregation-1.0.yaml")
        v63 = build(rule, setup, "6.3.5", "create")["body"]
        v72 = build(rule, setup, "7.2.2", "create")["body"]["entity"]
        self.assertNotIn("entity", v63)
        self.assertIsNone(v63["share_request"])
        for key in ("tags", "tactics_techniques", "event_summary_template"):
            self.assertNotIn(key, v63)
            self.assertIn(key, v72)
        self.assertIn("attack_techniques", v63["field_spec"])
        self.assertNotIn("attack_techniques", v72["field_spec"])
        self.assertEqual(v72["tactics_techniques"], ["T1059.001", "T1566.001", "TA0001", "TA0002"])
        self.assertEqual(v72["tags"][:2], ["office", "initial-access"])
        filter_rule = _rule("rule-graylog-filter-1.1.yaml")
        self.assertEqual(build(filter_rule, setup, "6.3.5", "create")["body"]["priority"], 1)
        self.assertEqual(build(filter_rule, setup, "7.1.12", "create")["body"]["entity"]["priority"], 0)


class ListingTests(unittest.TestCase):
    def test_platform_index(self) -> None:
        text = _read(INDEX)
        self.assertIn("opentide ships eleven detection platform integrations.", text)
        self.assertIn("| `graylog` | `platform::graylog::1.0` | [graylog-1.0.md](graylog-1.0.md) |", text)
        self.assertIn("| `graylog` | Graylog | yes* | yes‖ |", text)
        self.assertIn("`sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `carbon_black_cloud`, `elastic`, `graylog`", text)

    def test_spec_index_and_llms(self) -> None:
        self.assertIn("[specs/platforms/graylog-1.0.md](specs/platforms/graylog-1.0.md)", _read(ROOT / "SPECS.md"))
        self.assertIn("specs/platforms/graylog-1.0.md (schema_id: platform::graylog::1.0)", _read(ROOT / "llms.txt"))
        self.assertIn("| [0017](0017-graylog-platform.md) |", _read(ROOT / "rfcs" / "README.md"))

    def test_rule_specs_list_the_block(self) -> None:
        for name in ("rule-1.0.md", "rule-1.1.md"):
            self.assertIn(
                "| `graylog` | GraylogConfig | `platform::graylog::1.0` |",
                _read(ROOT / "specs" / "objects" / name),
            )

    def test_deployment_state_accepts_24_hex_ids(self) -> None:
        schema = json.loads(_read(ROOT / "schemas" / "deployment.state.1.0.schema.json"))
        self.assertEqual(schema["properties"]["platforms"]["properties"]["graylog"], {"$ref": "#/$defs/objectIdTenants"})
        self.assertIn("| `graylog` | 24 lower-case hex digits as a string", _read(ROOT / "specs" / "deployment-state.md"))
        self.assertIn("| `graylog` | yes: `POST /api/search/validate`", _read(ROOT / "specs" / "validation.md"))


class CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vocabs = load_vocabularies(ROOT / "vocabularies")

    def test_valid_fixtures_pass(self) -> None:
        for path in (
            FIXTURES / "platforms" / "graylog.yaml",
            FIXTURES / "valid" / "rule-graylog-aggregation-1.0.yaml",
            FIXTURES / "valid" / "rule-graylog-filter-1.1.yaml",
        ):
            with self.subTest(path=path.name):
                self.assertEqual(validate_fixture_file(path, self.vocabs), [])

    def test_invalid_fixtures_report_their_code(self) -> None:
        for name in (
            "rule-graylog-condition.yaml",
            "rule-graylog-event-field.yaml",
            "rule-graylog-event-key.yaml",
            "rule-graylog-schedule.yaml",
        ):
            with self.subTest(name=name):
                codes = _codes(validate_fixture_file(FIXTURES / "invalid" / name, self.vocabs))
                self.assertIn(EXPECTED_INVALID_CODES[name], codes)

    def test_block_codes(self) -> None:
        def block(**keys: Any) -> dict[str, Any]:
            return {"enabled": True, "schema": "platform::graylog::1.0", "status": "STAGING", "query": "EventID:1", **keys}

        def codes(**keys: Any) -> set[str]:
            return _codes(validate_graylog_block(block(**keys)))

        self.assertEqual(codes(), set())
        self.assertEqual(codes(query="  "), {"graylog_query_blank"})
        self.assertEqual(codes(streams="sysmon"), set())
        self.assertEqual(codes(streams=["a", "a"]), {"graylog_list_shape"})
        self.assertEqual(codes(notifications=[""]), {"graylog_list_shape"})
        self.assertEqual(codes(priority="Urgent"), {"graylog_priority"})
        self.assertEqual(codes(event_limit=0), {"graylog_event_limit"})
        self.assertEqual(codes(event_limit=10, aggregation={"condition": "count() > 1"}), {"graylog_event_limit"})
        self.assertEqual(codes(schedule={"every": "0m"}), {"graylog_schedule"})
        self.assertEqual(codes(schedule={"cron": "0 */5 * * * ?"}), {"graylog_schedule"})
        self.assertEqual(codes(schedule={"cron": "0 */5 * * * ?", "window": "5m", "timezone": "Mars/Base"}), {"graylog_schedule"})
        self.assertEqual(codes(schedule={"every": "PT5M", "window": "1h10m"}), set())
        self.assertEqual(codes(aggregation={"group_by": "source"}), {"graylog_aggregation"})
        self.assertEqual(codes(aggregation={"group_by": ["src ip"], "condition": "count() > 1"}), {"graylog_field_name"})
        self.assertEqual(codes(event_fields={"host": "source", "x": "${source.a}-${source.b}", "y": {"template": "LOLBin"}}), set())
        self.assertEqual(codes(event_fields={"owner": {"lookup": {"table": "t", "key_field": "source"}}}), set())
        self.assertEqual(codes(event_fields={"x": "two words"}), {"graylog_event_field"})
        self.assertEqual(codes(event_fields={"x": {"lookup": {"table": "t"}}}), {"graylog_event_field"})
        self.assertEqual(codes(event_fields={"host": "source"}, event_key="host"), set())
        self.assertEqual(codes(event_fields={"host": "source"}, event_key=["user"]), {"graylog_event_key"})

    def test_duration_grammar(self) -> None:
        self.assertEqual(duration_seconds("1h10m"), 4200)
        self.assertEqual(duration_seconds("PT1H10M"), 4200)
        self.assertEqual(duration_seconds("P1DT2H"), 93600)
        for bad in ("", "5", "1w", "m5", "PT", "P", "1.5h", "-5m", "5 m"):
            with self.subTest(bad=bad):
                self.assertIsNone(duration_seconds(bad))


if __name__ == "__main__":
    unittest.main()
