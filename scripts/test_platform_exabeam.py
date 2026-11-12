#!/usr/bin/env python3
"""Consistency tests for specs/platforms/exabeam-1.0.md, its fixtures, and the specs that list Exabeam.

The request bodies under fixtures/platforms/exabeam/ are the goldens implementations compare against.
These tests derive each body from its source rule fixture and the fixture tenant by the spec's rules
(name, description, severity, the compiled body, durations, outcomes, the --live search), so a golden
cannot drift from the text.
"""

from __future__ import annotations

import json
import re
import tomllib
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from object_fixtures import (
    EXPECTED_INVALID_CODES,
    exabeam_advisories,
    exabeam_duration,
    load_vocabularies,
    validate_exabeam_block,
    validate_fixture_file,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specs" / "platforms" / "exabeam-1.0.md"
INDEX = ROOT / "specs" / "platforms" / "index.md"
FIXTURES = ROOT / "fixtures"
GOLDEN = FIXTURES / "platforms" / "exabeam"
SECTIONS = ["Summary", "Requirements", "Definition", "Relationships", "Defaults & overrides", "Examples", "History"]
SAMPLE_RULE_ID = "016dbc1d-a727-43df-a143-9546dcc81a5a"
SAMPLE_NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)

SEVERITY = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low", "Informational": "none"}
UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
RECURRENCE = {"day": "DAILY", "week": "WEEKLY", "month": "MONTHLY", "days": "CUSTOM"}
CONSTRAINTS = [
    "exabeam_sequences",
    "exabeam_correlation",
    "exabeam_threshold_function",
    "exabeam_threshold_operator",
    "exabeam_threshold_value",
    "exabeam_group_by",
    "exabeam_duration",
    "exabeam_severity",
    "exabeam_outcome",
    "exabeam_email",
    "exabeam_schedule",
    "exabeam_name_length",
    "exabeam_context_table_trigger",
    "exabeam_name_duplicate",
]
ADVISORIES = ["exabeam_outcome_silent", "exabeam_correlation_window"]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _codes(errors: list[Any]) -> set[str]:
    return {error.code for error in errors}


# --- the spec's derivations ------------------------------------------------------------------------


def exa_name(rule: dict[str, Any]) -> str:
    return rule["configurations"]["exabeam"].get("name") or rule["name"]


def exa_description(rule: dict[str, Any]) -> str:
    """specs/platforms/exabeam-1.0.md#name-and-description."""
    text = " ".join(str(rule.get("description", "")).split())
    techniques: list[str] = []
    for technique in rule.get("techniques") or []:
        if technique not in techniques:
            techniques.append(technique)
    if techniques:
        text += "\n\nATT&CK: " + ", ".join(techniques)
        text += f"\nopentide: {rule['metadata']['uuid']}"
    else:
        text += f"\n\nopentide: {rule['metadata']['uuid']}"
    return text


def exa_severity(rule: dict[str, Any]) -> str:
    block = rule["configurations"]["exabeam"]
    if block.get("severity"):
        return block["severity"]
    return SEVERITY.get((rule.get("response") or {}).get("alert_severity"), "medium")


def exa_time(value: str) -> tuple[int, str]:
    parsed = exabeam_duration(value, "mhdw")
    assert parsed is not None, value
    return parsed[0], UNITS[parsed[1]]


def exa_value(value: Any) -> str:
    def one(v: Any) -> str:
        if isinstance(v, float) and v.is_integer():
            return str(int(v))
        return str(v)

    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(one(v) for v in value)
    return one(value)


def exa_condition(seq: dict[str, Any]) -> dict[str, Any]:
    group_by = seq.get("group_by") or []
    threshold = seq.get("threshold")
    condition: dict[str, Any] = {
        "triggerOnAnyMatch": threshold is None,
        "groupByOption": bool(group_by),
        "groupBy": list(group_by),
    }
    if threshold is None:
        return condition
    condition["functionType"] = threshold["function"]
    condition["subject"] = "field" if threshold.get("field") else "event"
    if threshold.get("field"):
        condition["field"] = threshold["field"]
    condition["operator"] = threshold["operator"]
    condition["value"] = exa_value(threshold.get("value"))
    condition["time"], condition["unit"] = exa_time(threshold["within"])
    return condition


def exa_outcomes(rule: dict[str, Any]) -> dict[str, Any]:
    block = rule["configurations"]["exabeam"]
    outcome = block.get("outcome", "alert")
    email = block.get("email")
    name = exa_name(rule)
    outcomes: dict[str, Any] = {
        "sendAlertTriage": outcome == "alert",
        "createCase": outcome == "case",
        "sendEmail": email is not None,
    }
    if outcome == "alert":
        outcomes["alertTriage"] = {"name": name}
    if outcome == "case":
        outcomes["case"] = {"description": name}
    if email is not None:
        outcomes["email"] = {
            "recipients": list(email["recipients"]),
            "subject": email.get("subject") or name,
            "attachCsv": bool(email.get("attach_csv", False)),
        }
    return outcomes


def exa_recurrence(rec: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"recurrenceType": RECURRENCE[rec["every"]], "startTime": rec["from"], "endTime": rec["to"]}
    if rec["every"] == "week":
        out["daysOfWeek"] = [d.upper() for d in rec["days"]]
    elif rec["every"] == "month":
        out["daysInMonth"] = list(rec.get("days") or [])
        out["lastDayOfMonth"] = bool(rec.get("last_day", False))
    elif rec["every"] == "days":
        out["dayFrom"] = rec["first"].upper()
        out["dayTo"] = rec["last"].upper()
    return out


def build_body(rule: dict[str, Any], setup: dict[str, Any], strategy: str = "RELEASE") -> dict[str, Any]:
    """specs/platforms/exabeam-1.0.md#compiled-body."""
    block = rule["configurations"]["exabeam"]
    sequences = []
    for seq in block["sequences"]:
        entry: dict[str, Any] = {}
        if seq.get("name"):
            entry["name"] = seq["name"]
        entry["query"] = seq["query"].strip()
        entry["condition"] = exa_condition(seq)
        sequences.append(entry)
    sequences_config: dict[str, Any] = {"sequences": sequences}
    if len(sequences) >= 2:
        correlation = block["correlation"]
        time, unit = exa_time(correlation["within"])
        sequences_config["commonProperties"] = {"groupBy": list(correlation.get("group_by") or []), "time": time, "unit": unit}
    sequences_config["outcomes"] = exa_outcomes(rule)
    body: dict[str, Any] = {
        "name": exa_name(rule),
        "description": exa_description(rule),
        "severity": exa_severity(rule),
        "enabled": strategy != "DISABLEMENT",
        "testMode": bool(block.get("test_mode", setup.get("test_mode", False))),
        "sequencesConfig": sequences_config,
    }
    suppression = block.get("suppression")
    if suppression:
        time, unit = exa_time(suppression["for"])
        suppress: dict[str, Any] = {"suppressOption": True, "suppressTime": time, "suppressUnit": unit}
        if suppression.get("group_by"):
            suppress["granularSuppressOption"] = True
            suppress["suppressGroupFields"] = list(suppression["group_by"])
        body["suppressConfig"] = suppress
    else:
        body["suppressConfig"] = {"suppressOption": False}
    if block.get("delay"):
        n, unit = exabeam_duration(block["delay"], "mh") or (0, "m")
        body["delayConfig"] = {"delay": True, "delayTimeInMinutes": n * (60 if unit == "h" else 1)}
    else:
        body["delayConfig"] = {"delay": False}
    if block.get("schedule"):
        body["scheduleConfig"] = {"recurrences": [exa_recurrence(r) for r in block["schedule"]]}
    return body


def build_request(rule: dict[str, Any], setup: dict[str, Any], method: str, strategy: str = "RELEASE") -> dict[str, Any]:
    if method == "POST":
        return {"method": "POST", "path": "/correlation-rules/v2/rules", "body": build_body(rule, setup, strategy)}
    return {"method": "PUT", "path": f"/correlation-rules/v2/rules/{SAMPLE_RULE_ID}", "body": build_body(rule, setup, strategy)}


def build_live_search(query: str, now: datetime = SAMPLE_NOW) -> dict[str, Any]:
    """specs/platforms/exabeam-1.0.md#query-validation: the --live filter check."""
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return {
        "method": "POST",
        "path": "/search/v2/events",
        "body": {
            "filter": query.strip(),
            "fields": ["*"],
            "startTime": (now - timedelta(minutes=15)).strftime(fmt),
            "endTime": now.strftime(fmt),
            "limit": 1,
        },
    }


GOLDENS: dict[str, tuple[str, str, str]] = {
    "rule-exabeam-threshold-1.0.create.api.json": ("rule-exabeam-threshold-1.0.yaml", "POST", "RELEASE"),
    "rule-exabeam-threshold-1.0.update.api.json": ("rule-exabeam-threshold-1.0.yaml", "PUT", "RELEASE"),
    "rule-exabeam-threshold-1.0.disable.api.json": ("rule-exabeam-threshold-1.0.yaml", "PUT", "DISABLEMENT"),
    "rule-exabeam-sequence-1.0.create.api.json": ("rule-exabeam-sequence-1.0.yaml", "POST", "RELEASE"),
}
LIVE_GOLDEN = "rule-exabeam-threshold-1.0.validate.api.json"


def _tenant_setup() -> dict[str, Any]:
    return tomllib.loads(_read(GOLDEN / "tenant.toml"))["tenants"][0]["setup"]


def _rule(name: str) -> dict[str, Any]:
    return yaml.safe_load(_read(FIXTURES / "valid" / name))


def expected_goldens() -> dict[str, dict[str, Any]]:
    setup = _tenant_setup()
    out = {golden: build_request(_rule(src), setup, method, strategy) for golden, (src, method, strategy) in GOLDENS.items()}
    threshold = _rule("rule-exabeam-threshold-1.0.yaml")
    out[LIVE_GOLDEN] = build_live_search(threshold["configurations"]["exabeam"]["sequences"][0]["query"])
    return out


# --- tests -----------------------------------------------------------------------------------------


class SpecShapeTests(unittest.TestCase):
    def test_frontmatter_and_sections(self) -> None:
        text = _read(SPEC)
        self.assertIn("schema_id: platform::exabeam::1.0", text)
        self.assertIn("status: normative", text)
        self.assertEqual(re.findall(r"^## (.+)$", text, flags=re.MULTILINE), SECTIONS)

    def test_constraint_and_advisory_tables(self) -> None:
        text = _read(SPEC)
        section = text[text.index("### Constraints") : text.index("Every implementation reports each code")]
        self.assertEqual(re.findall(r"^\| `(exabeam_[a-z_]+)` \|", section, flags=re.MULTILINE), CONSTRAINTS)
        advisories = text[text.index("### Advisories") : text.index("### Name and description")]
        self.assertEqual(re.findall(r"^\| `(exabeam_[a-z_]+)` \|", advisories, flags=re.MULTILINE), ADVISORIES)
        validation = _read(ROOT / "specs" / "validation.md")
        for code in ADVISORIES:
            self.assertIn(f"| `{code}` | warning |", validation)

    def test_severity_table(self) -> None:
        section = _read(SPEC).split("### Severity", 1)[1].split("###", 1)[0]
        for label, value in SEVERITY.items():
            self.assertIn(f"| `{label}` | `{value}` |", section)
        self.assertIn("| missing | `medium` |", section)

    def test_duration_table(self) -> None:
        section = _read(SPEC).split("### Durations", 1)[1].split("###", 1)[0]
        for written, (n, unit) in {"30m": (30, "minutes"), "4h": (4, "hours"), "1d": (1, "days")}.items():
            self.assertEqual(exa_time(written), (n, unit))
            self.assertIn(f'| `{written}` | `{{time: {n}, unit: "{unit}"}}` |', section)

    def test_state_backed_and_whole_body(self) -> None:
        text = _read(SPEC)
        self.assertIn("Every update MUST send the whole rule (`PUT`, which replaces the rule)", text)
        self.assertIn("Deploy MUST NOT use the import or export endpoints.", text)
        self.assertIn("`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`", text)


class GoldenTests(unittest.TestCase):
    def test_goldens_follow_the_spec(self) -> None:
        for golden, expected in expected_goldens().items():
            with self.subTest(golden=golden):
                self.assertEqual(json.loads(_read(GOLDEN / golden)), expected)
                # "Keys are sent in the order of this table": dict equality ignores order.
                self.assertEqual(json.dumps(json.loads(_read(GOLDEN / golden))), json.dumps(expected))

    def test_golden_set_is_complete(self) -> None:
        self.assertEqual(sorted(p.name for p in GOLDEN.glob("*.api.json")), sorted(expected_goldens()))

    def test_derivations(self) -> None:
        threshold = _rule("rule-exabeam-threshold-1.0.yaml")
        self.assertEqual(exa_severity(threshold), "high")
        self.assertIn("\n\nATT&CK: T1110.003\nopentide: 00000000-0000-4000-8003-000000000071", exa_description(threshold))
        sequence = _rule("rule-exabeam-sequence-1.0.yaml")
        self.assertEqual(exa_severity(sequence), "critical")
        body = build_body(sequence, _tenant_setup())
        self.assertEqual(body["sequencesConfig"]["commonProperties"], {"groupBy": ["host"], "time": 15, "unit": "minutes"})
        self.assertEqual(body["sequencesConfig"]["sequences"][1]["condition"]["subject"], "event")
        self.assertNotIn("field", body["sequencesConfig"]["sequences"][1]["condition"])
        self.assertEqual(exa_value([0.5, 2.0]), "0.5,2")
        self.assertEqual(exa_value(None), "")
        disabled = build_body(threshold, _tenant_setup(), "DISABLEMENT")
        self.assertIs(disabled["enabled"], False)

    def test_spec_example_matches_the_fixture(self) -> None:
        text = _read(SPEC)
        example = json.loads(text.split("Its sequence compiles to:\n\n```json\n", 1)[1].split("\n```", 1)[0])
        body = build_body(_rule("rule-exabeam-threshold-1.0.yaml"), _tenant_setup())
        self.assertEqual(example, body["sequencesConfig"]["sequences"][0])


class ListingTests(unittest.TestCase):
    def test_platform_index(self) -> None:
        text = _read(INDEX)
        self.assertIn("opentide ships twelve detection platform integrations.", text)
        self.assertIn("| `exabeam` | `platform::exabeam::1.0` | [exabeam-1.0.md](exabeam-1.0.md) |", text)
        self.assertIn("| `exabeam` | Exabeam New-Scale SIEM | yes* | yes‖‖ | Exabeam Query Language |", text)

    def test_spec_index_and_llms(self) -> None:
        specs = _read(ROOT / "SPECS.md")
        self.assertIn("[specs/platforms/exabeam-1.0.md](specs/platforms/exabeam-1.0.md)", specs)
        self.assertIn("[specs/languages/exabeam-1.0.md](specs/languages/exabeam-1.0.md)", specs)
        llms = _read(ROOT / "llms.txt")
        self.assertIn("specs/platforms/exabeam-1.0.md (schema_id: platform::exabeam::1.0)", llms)
        self.assertIn("specs/languages/exabeam-1.0.md", llms)
        self.assertIn("[0018](0018-exabeam-platform.md)", _read(ROOT / "rfcs" / "README.md"))

    def test_rule_specs_list_the_block_and_the_hunt_system(self) -> None:
        for name in ("rule-1.0.md", "rule-1.1.md"):
            text = _read(ROOT / "specs" / "objects" / name)
            self.assertIn("| `exabeam` | ExabeamConfig | `platform::exabeam::1.0` |", text)
            self.assertIn("`exabeam` is the Exabeam Query Language", text)

    def test_deployment_state_accepts_uuids(self) -> None:
        schema = json.loads(_read(ROOT / "schemas" / "deployment.state.1.0.schema.json"))
        self.assertEqual(schema["properties"]["platforms"]["properties"]["exabeam"], {"$ref": "#/$defs/uuidTenants"})
        pattern = schema["$defs"]["uuidTenants"]["additionalProperties"]["pattern"]
        self.assertEqual(pattern, "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        self.assertIn("| `exabeam` | A lower-case canonical UUID as a string", _read(ROOT / "specs" / "deployment-state.md"))

    def test_validation_lists_exabeam(self) -> None:
        text = _read(ROOT / "specs" / "validation.md")
        self.assertIn("| `exabeam` | yes, the filter only: Exabeam Search", text)


class CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vocabs = load_vocabularies(ROOT / "vocabularies")

    def test_valid_fixtures_pass(self) -> None:
        for path in (
            FIXTURES / "platforms" / "exabeam.yaml",
            FIXTURES / "valid" / "rule-exabeam-threshold-1.0.yaml",
            FIXTURES / "valid" / "rule-exabeam-sequence-1.0.yaml",
        ):
            with self.subTest(path=path.name):
                self.assertEqual(validate_fixture_file(path, self.vocabs), [])

    def test_invalid_fixtures_report_their_code(self) -> None:
        names = [name for name in EXPECTED_INVALID_CODES if name.startswith("rule-exabeam-")]
        self.assertEqual(len(names), 5)
        for name in names:
            with self.subTest(name=name):
                codes = _codes(validate_fixture_file(FIXTURES / "invalid" / name, self.vocabs))
                self.assertEqual(codes, {EXPECTED_INVALID_CODES[name]})

    def test_block_codes(self) -> None:
        def block(**keys: Any) -> dict[str, Any]:
            base: dict[str, Any] = {"enabled": True, "schema": "platform::exabeam::1.0", "status": "STAGING"}
            base["sequences"] = [{"query": 'activity_type:"app-login"'}]
            return {**base, **keys}

        def codes(**keys: Any) -> set[str]:
            return _codes(validate_exabeam_block(block(**keys)))

        def threshold(**keys: Any) -> list[dict[str, Any]]:
            t = {"function": "count", "operator": "more_than", "value": 5, "within": "10m", **keys}
            return [{"query": 'activity_type:"app-login"', "threshold": {k: v for k, v in t.items() if v is not None}}]

        self.assertEqual(codes(), set())
        self.assertEqual(codes(sequences=[]), {"exabeam_sequences"})
        self.assertEqual(codes(sequences=[{"query": "  "}]), {"exabeam_sequences"})
        two = [{"query": 'vendor:"a"'}, {"query": 'vendor:"b"'}]
        self.assertEqual(codes(sequences=two), {"exabeam_correlation"})
        self.assertEqual(codes(sequences=two, correlation={"within": "15m"}), set())
        self.assertEqual(codes(sequences=two, correlation={"within": "1h30m"}), {"exabeam_duration"})
        self.assertEqual(codes(sequences=threshold(function="median")), {"exabeam_threshold_function"})
        self.assertEqual(codes(sequences=threshold(function="sum")), {"exabeam_threshold_function"})
        self.assertEqual(codes(sequences=threshold(function="sum", field="bytes")), set())
        self.assertEqual(codes(sequences=threshold(function="value", field="dest_ip")), {"exabeam_threshold_operator"})
        self.assertEqual(
            codes(sequences=threshold(function="value", field="dest_ip", operator="not_in", value=["1.1.1.1"])), set()
        )
        self.assertEqual(
            codes(sequences=threshold(function="value", field="user", operator="changed", value=None)), {"exabeam_threshold_operator"}
        )
        self.assertEqual(codes(sequences=threshold(value=2.5)), {"exabeam_threshold_value"})
        self.assertEqual(codes(sequences=threshold(operator="between", value=[2, 10])), {"exabeam_threshold_operator"})
        self.assertEqual(codes(sequences=threshold(within="1w")), {"exabeam_duration"})
        self.assertEqual(
            codes(sequences=[{"query": 'vendor:"a"', "group_by": ["a", "b", "c", "d"]}]), {"exabeam_group_by"}
        )
        self.assertEqual(codes(severity="High"), {"exabeam_severity"})
        self.assertEqual(codes(outcome="webhook"), {"exabeam_outcome"})
        self.assertEqual(codes(email={"recipients": []}), {"exabeam_email"})
        self.assertEqual(codes(email={"recipients": ["soc@example.com"], "subject": "x"}), set())
        self.assertEqual(codes(suppression={"for": "2w", "group_by": ["user"]}), set())
        self.assertEqual(codes(suppression={"for": "0m"}), {"exabeam_duration"})
        self.assertEqual(codes(delay="3h"), set())
        self.assertEqual(codes(delay="181m"), {"exabeam_duration"})
        self.assertEqual(codes(schedule=[{"every": "week", "days": ["monday"], "from": "08:00Z", "to": "18:00Z"}]), set())
        self.assertEqual(codes(schedule=[{"every": "week", "days": ["mon"], "from": "08:00Z", "to": "18:00Z"}]), {"exabeam_schedule"})
        self.assertEqual(codes(schedule=[{"every": "day", "from": "8am", "to": "18:00Z"}]), {"exabeam_schedule"})
        self.assertEqual(codes(schedule=[{"every": "month", "from": "00:00Z", "to": "23:59Z", "last_day": True}]), set())
        self.assertEqual(codes(name="x" * 129), {"exabeam_name_length"})
        self.assertEqual(codes(sequences=[{"query": 'user != "SYSTEM"'}]), {"exabeam_not_equal"})
        self.assertEqual(codes(rule_id="016dbc1d-a727-43df-a143-9546dcc81a5a"), {"external_id_in_rule"})
        self.assertEqual(codes(tags=["x"]), {"unknown_field"})

    def test_review_round_block_codes(self) -> None:
        """Nested unknown keys, null as absent, and the context table found by the parser."""

        def check(**keys: Any) -> list[tuple[str, str]]:
            base: dict[str, Any] = {"enabled": True, "schema": "platform::exabeam::1.0", "status": "STAGING"}
            base["sequences"] = [{"query": 'activity_type:"app-login"'}]
            return [(e.code, e.path) for e in validate_exabeam_block({**base, **keys})]

        b = "configurations.exabeam"
        any_match = {"query": 'vendor:"a"'}
        counted = {"query": 'vendor:"a"', "threshold": {"function": "count", "operator": "more_than", "value": 1, "within": "5m"}}
        self.assertEqual(check(sequences=[{**any_match, "extra": 1}]), [("unknown_field", f"{b}.sequences.0.extra")])
        self.assertEqual(
            check(sequences=[{**counted, "threshold": {**counted["threshold"], "extra": 1}}]),
            [("unknown_field", f"{b}.sequences.0.threshold.extra")],
        )
        self.assertEqual(check(suppression={"for": "1h", "unit": "h"}), [("unknown_field", f"{b}.suppression.unit")])
        self.assertEqual(check(suppression={"group_by": ["user"]}), [("exabeam_duration", f"{b}.suppression.for")])
        self.assertEqual(check(suppression="1h"), [("exabeam_duration", f"{b}.suppression.for")])
        two = [any_match, any_match]
        self.assertEqual(
            check(sequences=two, correlation={"within": "15m", "extra": 1}), [("unknown_field", f"{b}.correlation.extra")]
        )
        self.assertEqual(check(email={"recipients": ["a@b.co"], "cc": []}), [("unknown_field", f"{b}.email.cc")])
        self.assertEqual(
            check(schedule=[{"every": "day", "from": "8:00Z", "to": "18:00Z", "tz": "UTC"}]),
            [("unknown_field", f"{b}.schedule.0.tz")],
        )
        self.assertEqual(check(sequences=["vendor:\"a\""]), [("exabeam_sequences", f"{b}.sequences.0")])
        # null is absent, at every level
        self.assertEqual(check(severity=None, suppression=None, delay=None, schedule=None, email=None), [])
        self.assertEqual(check(sequences=[{**any_match, "threshold": None, "group_by": None, "name": None}]), [])
        self.assertEqual(check(email={"recipients": ["a@b.co"], "subject": None, "attach_csv": None}), [])
        # anchored patterns: no trailing newline sneaks through
        self.assertEqual(check(delay="15m\n"), [("exabeam_duration", f"{b}.delay")])
        # a quoted " in " is not a context table
        quoted = {**counted, "query": 'message:"user signed in \'admin\'"'}
        self.assertEqual(check(sequences=[quoted]), [])
        table = {**counted, "query": 'user IN "Admins"'}
        self.assertEqual(check(sequences=[table]), [("exabeam_context_table_trigger", f"{b}.sequences.0.threshold")])
        # in / not_in items hold no comma and are not blank
        value = {"function": "value", "field": "dest_ip", "operator": "in", "within": "5m"}
        for bad in (["a,b"], [" "], []):
            with self.subTest(value=bad):
                seq = {"query": 'vendor:"a"', "threshold": {**value, "value": bad}}
                self.assertEqual(check(sequences=[seq]), [("exabeam_threshold_value", f"{b}.sequences.0.threshold")])

    def test_correlation_window_advisory(self) -> None:
        def seq(within: str | None) -> dict[str, Any]:
            if within is None:
                return {"query": 'vendor:"a"'}
            return {"query": 'vendor:"a"', "threshold": {"function": "count", "operator": "more_than", "value": 1, "within": within}}

        def advised(within: str, *windows: str | None) -> list[str]:
            block = {"sequences": [seq(w) for w in windows], "correlation": {"within": within}}
            return [e.code for e in exabeam_advisories(block)]

        # Exabeam's guide: 3- and 5-minute ordered sequences need "more than nine minutes".
        self.assertEqual(advised("9m", "3m", "5m"), ["exabeam_correlation_window"])
        self.assertEqual(advised("10m", "3m", "5m"), [])
        self.assertEqual(advised("5m", "3m", "5m"), ["exabeam_correlation_window"])
        self.assertEqual(advised("3m", None, None), ["exabeam_correlation_window"])
        self.assertEqual(advised("4m", None, None), [])
        self.assertEqual(advised("1h", "1h", None), ["exabeam_correlation_window"])
        self.assertEqual(advised("1h", "30m"), [])  # one sequence: no correlation window
        self.assertEqual(advised("15m", None, "10m"), [])  # the sequence fixture: 1 + 10 + 1 = 12
        self.assertEqual(exabeam_advisories({"outcome": "none", "sequences": []})[0].code, "exabeam_outcome_silent")
        self.assertEqual(exabeam_advisories({"outcome": "none", "email": {"recipients": ["a@b.co"]}}), [])


if __name__ == "__main__":
    unittest.main()
