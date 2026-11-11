#!/usr/bin/env python3
"""Consistency tests for specs/platforms/google-secops-1.0.md, specs/languages/yara-l-1.0.md, their fixtures, and the specs that list them.

The files under fixtures/platforms/google-secops/ are the goldens implementations compare against: the
YARA-L text deploy assembles for each rule (`<stem>.yaral`) and the requests deploy sends
(`<stem>.<step>.api.json`). These tests derive each golden from its rule fixture and the fixture tenant by
the spec's rules (rule name, meta, severity, ATT&CK, assembly, run state by strategy), so a golden cannot
drift from the text. Run this file with `--write` to regenerate them after a spec change.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
import unittest
from pathlib import Path
from typing import Any

import yaml

from object_fixtures import (
    EXPECTED_INVALID_CODES,
    load_vocabularies,
    validate_fixture_file,
    validate_google_secops_block,
    validate_yaral_body,
    yaral_sections,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specs" / "platforms" / "google-secops-1.0.md"
LANGUAGE = ROOT / "specs" / "languages" / "yara-l-1.0.md"
INDEX = ROOT / "specs" / "platforms" / "index.md"
FIXTURES = ROOT / "fixtures"
GOLDEN = FIXTURES / "platforms" / "google-secops"
SECTIONS = ["Summary", "Requirements", "Definition", "Relationships", "Defaults & overrides", "Examples", "History"]
SAMPLE_RULE_ID = "ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1"
RULES = {
    "rule-google-secops-process-1.0": "PREVIEW",
    "rule-google-secops-spray-1.0": "RELEASE",
}

SEVERITY = {"Informational": "Info", "Low": "Low", "Medium": "Medium", "High": "High", "Critical": "Critical"}
FREQUENCY_PREFERENCE = ["LIVE", "LIVE_CUSTOMIZABLE", "HOURLY_CUSTOMIZABLE", "DAILY"]
# specs/platforms/elastic-1.0.md#attck: stage -> tactic id, in table order; legacy stages renamed first.
TACTICS = {
    "Reconnaissance": "TA0043",
    "Resource Development": "TA0042",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Stealth": "TA0005",
    "Defense Impairment": "TA0112",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}
LEGACY_STAGES = {"Defense Evasion": "Stealth"}
CONSTRAINTS = [
    "google_secops_rule_name",
    "google_secops_severity",
    "google_secops_run_frequency",
    "google_secops_schedule",
    "google_secops_meta_key",
    "google_secops_name_duplicate",
]
ADVISORIES = [
    "google_secops_risk_score_missing",
    "google_secops_rule_id_literal",
    "google_secops_live_frequency_unavailable",
]
LANGUAGE_ERRORS = [
    "yaral_parse_error",
    "yaral_body_header",
    "yaral_query_alias",
    "yaral_section_missing",
    "yaral_section_order",
    "yaral_section_unavailable",
    "yaral_meta_duplicate",
    "yaral_reserved_identifier",
    "yaral_undefined_variable",
    "yaral_multi_event_match",
    "yaral_match_variable",
    "yaral_match_window",
    "yaral_condition_shape",
    "yaral_outcome_limit",
    "yaral_outcome_aggregation",
    "yaral_unknown_function",
    "yaral_function_unavailable",
    "yaral_unknown_udm_field",
    "yaral_enum_value",
    "yaral_type",
    "yaral_regex",
    "yaral_string_escape",
    "yaral_reference_list_limit",
    "yaral_option",
    "yaral_nocase_on_enum",
    "yaral_nesting_depth",
]
LANGUAGE_WARNINGS = [
    "yaral_deprecated_field",
    "yaral_unfiltered_event",
    "yaral_leading_wildcard_regex",
    "yaral_reference_list_deprecated",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _codes(errors: list[Any]) -> set[str]:
    return {error.code for error in errors}


def _techniques() -> dict[str, list[str]]:
    doc = tomllib.loads(_read(ROOT / "vocabularies" / "att&ck.vocab.toml"))
    return {key["id"]: list(key.get("tide.vocab.stages") or []) for key in doc["keys"] if "id" in key}


# --- the spec's derivations ------------------------------------------------------------------------


def rule_name(rule: dict[str, Any]) -> str:
    """specs/platforms/google-secops-1.0.md#rule-name."""
    block = rule["configurations"]["google_secops"]
    if block.get("name"):
        return block["name"]
    name = re.sub(r"[^a-z0-9]+", "_", rule["name"].lower()).strip("_")
    if not name:
        return "opentide_" + rule["metadata"]["uuid"].replace("-", "_")
    return "r_" + name if name[0].isdigit() else name


def severity(rule: dict[str, Any]) -> str:
    block = rule["configurations"]["google_secops"]
    if block.get("severity"):
        return block["severity"]
    return SEVERITY.get((rule.get("response") or {}).get("alert_severity"), "Medium")


def meta_value(text: str) -> str:
    """A YARA-L double-quoted string: backslash and quote escaped, control characters as spaces."""
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + "".join(" " if ord(ch) < 32 or ord(ch) == 127 else ch for ch in text) + '"'


def meta(rule: dict[str, Any], stages: dict[str, list[str]]) -> list[tuple[str, str]]:
    """specs/platforms/google-secops-1.0.md#meta. The fixtures have no detection_model, so techniques are the rule's own."""
    block = rule["configurations"]["google_secops"]
    authors: list[str] = []
    for author in [rule["metadata"].get("author"), *(block.get("contributors") or [])]:
        if author and author not in authors:
            authors.append(author)
    sev = severity(rule)
    entries = [
        ("author", ", ".join(authors)),
        ("description", " ".join(str(rule.get("description", "")).split())),
        ("severity", sev),
        ("priority", block.get("priority") or sev),
    ]
    techniques = sorted(set(rule.get("techniques") or []))
    tactic_stages = {LEGACY_STAGES.get(stage, stage) for t in techniques for stage in stages.get(t, [])}
    tactics = [tactic for stage, tactic in TACTICS.items() if stage in tactic_stages]
    if tactics:
        entries.append(("tactic", ",".join(tactics)))
    if techniques:
        entries.append(("technique", ",".join(techniques)))
    entries.append(("opentide_uuid", rule["metadata"]["uuid"]))
    entries.append(("opentide_version", str(rule["metadata"]["version"])))
    entries.extend((key, str(value)) for key, value in (block.get("meta") or {}).items())
    return entries


def assemble(rule: dict[str, Any], stages: dict[str, list[str]]) -> str:
    """specs/platforms/google-secops-1.0.md#assembled-rule."""
    body = rule["configurations"]["google_secops"]["query"].replace("\r\n", "\n").split("\n")
    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()
    lines = [f"rule {rule_name(rule)} {{", "  meta:"]
    lines += [f"    {key} = {meta_value(value)}" for key, value in meta(rule, stages)]
    lines.append("")
    lines += [("  " + line) if line.strip() else "" for line in body]
    lines.append("}")
    return "\n".join(lines) + "\n"


def instance(setup: dict[str, Any]) -> str:
    return f"projects/{setup['project']}/locations/{setup['location']}/instances/{setup['instance']}"


def seconds(duration: str) -> str:
    amount, unit = int(duration[:-1]), duration[-1]
    return f"{amount * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[unit]}s"


def run_state(rule: dict[str, Any], strategy: str, allowed: list[str]) -> tuple[str, dict[str, Any]]:
    """specs/platforms/google-secops-1.0.md#deploy: the deployment update for a strategy."""
    block = rule["configurations"]["google_secops"]
    if strategy == "DISABLEMENT":
        return "enabled,alerting", {"enabled": False, "alerting": False}
    alerting = block.get("alerting", strategy != "PREVIEW")
    frequency = block.get("run_frequency") or next(f for f in FREQUENCY_PREFERENCE if f in allowed)
    body: dict[str, Any] = {"enabled": True, "alerting": alerting, "runFrequency": frequency}
    schedule = block.get("schedule")
    if schedule:
        custom: dict[str, Any] = {}
        if "ensure_enrichment_completeness" in schedule:
            custom["ensureEnrichmentCompleteness"] = schedule["ensure_enrichment_completeness"]
        if "late_arriving_data_adjustment" in schedule:
            custom["lateArrivingDataAdjustment"] = seconds(schedule["late_arriving_data_adjustment"])
        body["scheduleCustomizations"] = custom
    return "enabled,alerting,runFrequency", body


def requests(rule: dict[str, Any], setup: dict[str, Any], strategy: str, stages: dict[str, list[str]]) -> dict[str, Any]:
    """Every golden request for one rule, keyed by step."""
    text = assemble(rule, stages)
    base = f"/v1/{instance(setup)}"
    rule_path = f"{base}/rules/{SAMPLE_RULE_ID}"
    mask, state = run_state(rule, strategy, FREQUENCY_PREFERENCE)
    off_mask, off = run_state(rule, "DISABLEMENT", FREQUENCY_PREFERENCE)
    return {
        "verify": {"method": "POST", "path": f"{base}:verifyRuleText", "body": {"ruleText": text}},
        "create": {"method": "POST", "path": f"{base}/rules", "body": {"text": text}},
        "deployment": {"method": "PATCH", "path": f"{rule_path}/deployment", "query": {"updateMask": mask}, "body": state},
        "disable": {"method": "PATCH", "path": f"{rule_path}/deployment", "query": {"updateMask": off_mask}, "body": off},
        "archive": [
            {"method": "PATCH", "path": f"{rule_path}/deployment", "query": {"updateMask": off_mask}, "body": off},
            {"method": "PATCH", "path": f"{rule_path}/deployment", "query": {"updateMask": "archived"}, "body": {"archived": True}},
        ],
    }


def _load(stem: str) -> dict[str, Any]:
    return yaml.safe_load(_read(FIXTURES / "valid" / f"{stem}.yaml"))


def _setup() -> dict[str, Any]:
    return tomllib.loads(_read(GOLDEN / "tenant.toml"))["tenants"][0]["setup"]


def write_goldens() -> None:
    stages = _techniques()
    for stem, strategy in RULES.items():
        rule = _load(stem)
        (GOLDEN / f"{stem}.yaral").write_text(assemble(rule, stages), encoding="utf-8")
        for step, body in requests(rule, _setup(), strategy, stages).items():
            (GOLDEN / f"{stem}.{step}.api.json").write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# --- tests -----------------------------------------------------------------------------------------


class SpecShapeTests(unittest.TestCase):
    def test_sections_in_order(self) -> None:
        for path in (SPEC, LANGUAGE):
            with self.subTest(spec=path.name):
                headings = re.findall(r"^## (.+)$", _read(path), flags=re.MULTILINE)
                self.assertEqual(headings, SECTIONS)

    def test_frontmatter(self) -> None:
        self.assertIn("schema_id: platform::google_secops::1.0", _read(SPEC))
        self.assertIn("spec: language-yara-l", _read(LANGUAGE))

    def test_every_code_is_documented_once_per_table(self) -> None:
        spec, language = _read(SPEC), _read(LANGUAGE)
        for code in CONSTRAINTS + ADVISORIES:
            with self.subTest(code=code):
                self.assertRegex(spec, rf"\| `{code}` \|")
        for code in LANGUAGE_ERRORS + LANGUAGE_WARNINGS:
            with self.subTest(code=code):
                self.assertEqual(len(re.findall(rf"^\| `{code}` \|", language, flags=re.MULTILINE)), 1)
        validation = _read(ROOT / "specs" / "validation.md")
        for code in ADVISORIES:
            self.assertIn(f"| `{code}` | warning |", validation)
        for code in LANGUAGE_WARNINGS:
            self.assertIn(f"`{code}`", validation)

    def test_highlighting_uses_existing_captures(self) -> None:
        legend = {
            "comment", "keyword", "operator", "operator.pipe", "function", "function.builtin", "type", "variable",
            "property", "string", "number", "boolean", "constant", "punctuation", "punctuation.bracket",
            "punctuation.delimiter", "error",
        }
        table = _read(LANGUAGE).split("### Highlighting", 1)[1].split("## Relationships", 1)[0]
        captures = set(re.findall(r"\| `([a-z.]+)` \|$", table, flags=re.MULTILINE))
        self.assertTrue(captures)
        self.assertLessEqual(captures, legend)


class GoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.stages = _techniques()
        cls.setup = _setup()

    def test_goldens_match_the_spec(self) -> None:
        for stem, strategy in RULES.items():
            rule = _load(stem)
            with self.subTest(rule=stem):
                self.assertEqual(_read(GOLDEN / f"{stem}.yaral"), assemble(rule, self.stages))
                for step, body in requests(rule, self.setup, strategy, self.stages).items():
                    golden = json.loads(_read(GOLDEN / f"{stem}.{step}.api.json"))
                    self.assertEqual(golden, body, f"{stem}.{step}")

    def test_no_stray_goldens(self) -> None:
        expected = {"tenant.toml"}
        for stem in RULES:
            expected.add(f"{stem}.yaral")
            expected.update(f"{stem}.{step}.api.json" for step in ("verify", "create", "deployment", "disable", "archive"))
        self.assertEqual({p.name for p in GOLDEN.iterdir()}, expected)

    def test_derivations(self) -> None:
        process = _load("rule-google-secops-process-1.0")
        self.assertEqual(rule_name(process), "office_application_spawns_encoded_powershell")
        self.assertEqual(rule_name({**process, "name": "2FA bypass!", "configurations": {"google_secops": {}}}), "r_2fa_bypass")
        self.assertEqual(dict(meta(process, self.stages))["tactic"], "TA0001,TA0002")
        self.assertEqual(dict(meta(process, self.stages))["author"], "Detection Engineering, Threat Hunting")
        spray = _load("rule-google-secops-spray-1.0")
        self.assertEqual(rule_name(spray), "password_spray_then_success")
        self.assertEqual(dict(meta(spray, self.stages))["tactic"], "TA0001,TA0003,TA0004,TA0005,TA0006")
        self.assertEqual(meta_value('a "b"\\c\nd'), '"a \\"b\\"\\\\c d"')

    def test_body_line_mapping(self) -> None:
        """Line n of query is line n + k + 3 of the assembled text, two columns to the right."""
        for stem in RULES:
            rule = _load(stem)
            body = rule["configurations"]["google_secops"]["query"].split("\n")
            assembled = assemble(rule, self.stages).split("\n")
            k = len(meta(rule, self.stages))
            for n, line in enumerate(body, start=1):
                if line.strip():
                    self.assertEqual(assembled[n + k + 3 - 1], "  " + line)

    def test_assembled_rule_is_a_rule(self) -> None:
        for stem in RULES:
            text = _read(GOLDEN / f"{stem}.yaral")
            inner = text.split("{", 1)[1].rsplit("}", 1)[0]
            names = [name for name, _, _ in yaral_sections(inner)]
            self.assertEqual(names[:2], ["meta", "events"])
            self.assertIn("condition", names)


class ListingTests(unittest.TestCase):
    def test_platform_index(self) -> None:
        text = _read(INDEX)
        self.assertIn("opentide ships eleven detection platform integrations.", text)
        self.assertIn("| `google_secops` | `platform::google_secops::1.0` | [google-secops-1.0.md](google-secops-1.0.md) |", text)
        self.assertIn("| `google_secops` | Google Security Operations (SIEM) | yes* | yes‖ | YARA-L 2.0 |", text)
        self.assertIn("`carbon_black_cloud`, `elastic`, `google_secops`\n", text)
        self.assertIn("| `google_secops` | yes:", _read(ROOT / "specs" / "validation.md"))

    def test_spec_index_and_llms(self) -> None:
        specs, llms = _read(ROOT / "SPECS.md"), _read(ROOT / "llms.txt")
        self.assertIn("[specs/platforms/google-secops-1.0.md](specs/platforms/google-secops-1.0.md)", specs)
        self.assertIn("[specs/languages/yara-l-1.0.md](specs/languages/yara-l-1.0.md)", specs)
        self.assertIn("specs/platforms/google-secops-1.0.md (schema_id: platform::google_secops::1.0)", llms)
        self.assertIn("specs/languages/yara-l-1.0.md", llms)
        self.assertIn("[0017](0017-google-secops-yara-l.md)", _read(ROOT / "rfcs" / "README.md"))

    def test_rule_specs_list_the_block(self) -> None:
        for name in ("rule-1.0.md", "rule-1.1.md"):
            self.assertIn(
                "| `google_secops` | GoogleSecopsConfig | `platform::google_secops::1.0` |",
                _read(ROOT / "specs" / "objects" / name),
            )

    def test_deployment_state_accepts_rule_ids(self) -> None:
        schema = json.loads(_read(ROOT / "schemas" / "deployment.state.1.0.schema.json"))
        self.assertEqual(schema["properties"]["platforms"]["properties"]["google_secops"], {"$ref": "#/$defs/secopsRuleTenants"})
        pattern = re.compile(schema["$defs"]["secopsRuleTenants"]["additionalProperties"]["pattern"])
        self.assertTrue(pattern.match(SAMPLE_RULE_ID))
        self.assertFalse(pattern.match(SAMPLE_RULE_ID + "@v_1704475682_607535000"))
        self.assertFalse(pattern.match(SAMPLE_RULE_ID[3:]))


class CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vocabs = load_vocabularies(ROOT / "vocabularies")

    def test_valid_fixtures_pass(self) -> None:
        for path in (FIXTURES / "platforms" / "google-secops.yaml", *(FIXTURES / "valid" / f"{s}.yaml" for s in RULES)):
            with self.subTest(path=path.name):
                self.assertEqual(validate_fixture_file(path, self.vocabs), [])

    def test_invalid_fixtures_report_their_code(self) -> None:
        names = [name for name in EXPECTED_INVALID_CODES if name.startswith("rule-google-secops-")]
        self.assertEqual(len(names), 5)
        for name in names:
            with self.subTest(name=name):
                codes = _codes(validate_fixture_file(FIXTURES / "invalid" / name, self.vocabs))
                self.assertIn(EXPECTED_INVALID_CODES[name], codes)

    def test_block_codes(self) -> None:
        body = "events:\n  $e.metadata.event_type = \"USER_LOGIN\"\ncondition:\n  $e\n"

        def block(**keys: Any) -> dict[str, Any]:
            return {"enabled": True, "schema": "platform::google_secops::1.0", "status": "STAGING", "query": body, **keys}

        self.assertEqual(validate_google_secops_block(block()), [])
        self.assertEqual(_codes(validate_google_secops_block(block(name="bad-name"))), {"google_secops_rule_name"})
        self.assertEqual(_codes(validate_google_secops_block(block(name="match"))), {"google_secops_rule_name"})
        self.assertEqual(_codes(validate_google_secops_block(block(severity="Informational"))), {"google_secops_severity"})
        self.assertEqual(_codes(validate_google_secops_block(block(priority="urgent"))), {"google_secops_severity"})
        self.assertEqual(_codes(validate_google_secops_block(block(run_frequency="HOURLY"))), {"google_secops_run_frequency"})
        self.assertEqual(
            _codes(validate_google_secops_block(block(run_frequency="LIVE", schedule={"ensure_enrichment_completeness": True}))),
            {"google_secops_schedule"},
        )
        self.assertEqual(
            _codes(validate_google_secops_block(block(run_frequency="HOURLY_CUSTOMIZABLE", schedule={"late_arriving_data_adjustment": "soon"}))),
            {"google_secops_schedule"},
        )
        self.assertEqual(
            validate_google_secops_block(block(run_frequency="HOURLY_CUSTOMIZABLE", schedule={"late_arriving_data_adjustment": "2h"})), []
        )
        for key in ("technique", "opentide_uuid", "not-an-identifier", "or"):
            with self.subTest(meta=key):
                self.assertEqual(_codes(validate_google_secops_block(block(meta={key: "x"}))), {"google_secops_meta_key"})
        self.assertEqual(_codes(validate_google_secops_block(block(meta={"count": 3}))), {"google_secops_meta_key"})

    def test_body_codes(self) -> None:
        path = "configurations.google_secops.query"
        ok = "events:\n  $e.metadata.event_type = \"USER_LOGIN\"\n  $u = $e.target.user.userid\nmatch:\n  $u over 10m\noutcome:\n  $n = count($e.metadata.id)\ncondition:\n  #e > 5\noptions:\n  allow_zero_values = true\n  suppression_window = 1h\n"
        self.assertEqual(validate_yaral_body(ok, path), [])
        self.assertEqual(_codes(validate_yaral_body(ok.replace("10m", "15d"), path)), {"yaral_match_window"})
        self.assertEqual(_codes(validate_yaral_body(ok.replace("10m", "10s"), path)), {"yaral_match_window"})
        self.assertEqual(validate_yaral_body(ok.replace("10m", "3d"), path), [])
        self.assertEqual(_codes(validate_yaral_body(ok.replace("over 10m", "by 4d"), path)), {"yaral_match_window"})
        export_first = ok.replace("options:", "export:\n  %hits.write_row(user: $u)\noptions:")
        self.assertEqual(validate_yaral_body(export_first, path), [])
        self.assertEqual(_codes(validate_yaral_body(ok.replace("allow_zero_values", "allow_nulls"), path)), {"yaral_option"})
        swapped = "condition:\n  $e\nevents:\n  $e.metadata.event_type = \"USER_LOGIN\"\n"
        self.assertEqual(_codes(validate_yaral_body(swapped, path)), {"yaral_section_order"})
        quoted = "events:\n  $e.metadata.description = \"condition: none\" // match: in a comment\n"
        self.assertEqual(_codes(validate_yaral_body(quoted, path)), {"yaral_section_missing"})
        block_comment = "events:\n  $e.metadata.event_type = \"USER_LOGIN\"\n/*\ncondition:\n*/\ncondition:\n  $e\n"
        self.assertEqual(validate_yaral_body(block_comment, path), [])
        self.assertEqual(_codes(validate_yaral_body("meta:\n  a = \"b\"\n" + ok, path)), {"yaral_body_header"})


if __name__ == "__main__":
    if "--write" in sys.argv:
        write_goldens()
        sys.exit(0)
    unittest.main()
