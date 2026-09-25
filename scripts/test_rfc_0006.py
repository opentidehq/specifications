#!/usr/bin/env python3
"""Consistency tests for RFC 0006 (Elastic Security platform).

The helpers are a reference reading of the RFC's normative tables. Every
example in the RFC is recompiled from those tables and the canonical ATT&CK
vocabulary, so an example that drifts from the rules fails here. This is not
the opentide deployer.
"""

from __future__ import annotations

import copy
import json
import re
import tomllib
import unittest
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RFC = ROOT / "rfcs" / "0006-elastic-security-platform.md"
ATTACK = ROOT / "vocabularies" / "att&ck.vocab.toml"
ALERT_SEVERITY = ROOT / "vocabularies" / "alert_severity.vocab.toml"

# Kibana `<Type>RuleCreateProps` properties, detection engine API 2023-10-31
# (elastic/kibana main, ess and serverless bundles are identical for these).
_KIBANA_COMMON = frozenset(
    """actions alert_suppression alias_purpose alias_target_id author
    building_block_type data_view_id description enabled exceptions_list
    false_positives filters from index interval investigation_fields language
    license max_signals meta name namespace note outcome output_index query
    references related_integrations required_fields response_actions
    risk_score risk_score_mapping rule_id rule_name_override saved_id setup
    severity severity_mapping tags threat throttle timeline_id timeline_title
    timestamp_override timestamp_override_fallback_disabled to type
    version""".split()
)
KIBANA_FIELDS = {
    "query": _KIBANA_COMMON,
    "eql": (_KIBANA_COMMON - {"saved_id"})
    | {"event_category_override", "tiebreaker_field", "timestamp_field"},
    "esql": _KIBANA_COMMON - {"data_view_id", "filters", "index", "saved_id"},
    "threshold": _KIBANA_COMMON | {"threshold"},
    "new_terms": (_KIBANA_COMMON - {"saved_id"})
    | {"history_window_start", "new_terms_fields"},
}
_KIBANA_REQUIRED_COMMON = {"name", "description", "type", "severity", "risk_score"}
KIBANA_REQUIRED = {
    "query": _KIBANA_REQUIRED_COMMON,
    "eql": _KIBANA_REQUIRED_COMMON | {"language", "query"},
    "esql": _KIBANA_REQUIRED_COMMON | {"language", "query"},
    "threshold": _KIBANA_REQUIRED_COMMON | {"query", "threshold"},
    "new_terms": _KIBANA_REQUIRED_COMMON
    | {"query", "new_terms_fields", "history_window_start"},
}

# specs/deployment.md status → strategy.
STATUS_STRATEGY = {
    "DESIGN": "INERT",
    "DEVELOPMENT": "PREVIEW",
    "IMPROVING": "PREVIEW",
    "STAGING": "PREVIEW",
    "ACCEPTANCE": "PREVIEW",
    "PRODUCTION": "RELEASE",
    "DISABLED": "DISABLEMENT",
    "REMOVED": "DELETION",
}
DEPLOYMENT_VALUES = {"ALWAYS", "STAGING", "PRODUCTION", "MANUAL", "FULL", "DEBUG"}
NON_ENTERPRISE_PREFIXES = ("Mobile : ", "Industrial : ")
RISK_BANDS = {"low": (0, 21), "medium": (22, 47), "high": (48, 73), "critical": (74, 100)}
UNIT_SECONDS = {"d": 86400, "h": 3600, "m": 60, "s": 1}
_ISO_DURATION = re.compile(r"P(?:(\d+)D)?(?:T(?=\d)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?")


def _text() -> str:
    return RFC.read_text(encoding="utf-8")


def _fence(anchor: str) -> tuple[str, str]:
    pattern = rf"<!-- rfc0006:{re.escape(anchor)} -->\n```(\w+)\n(.*?)\n```"
    match = re.search(pattern, _text(), flags=re.DOTALL)
    if not match:
        raise AssertionError(f"RFC 0006 is missing the {anchor!r} fenced block")
    return match.group(1), match.group(2)


def _yaml(anchor: str) -> Any:
    lang, body = _fence(anchor)
    assert lang == "yaml", anchor
    return yaml.safe_load(body)


def _json(anchor: str) -> Any:
    lang, body = _fence(anchor)
    assert lang == "json", anchor
    return json.loads(body)


def _table(anchor: str) -> list[dict[str, str]]:
    match = re.search(rf"<!-- rfc0006:{re.escape(anchor)} -->\n((?:\|.*\n)+)", _text())
    if not match:
        raise AssertionError(f"RFC 0006 is missing the {anchor!r} table")
    lines = match.group(1).strip().splitlines()

    def cells(line: str) -> list[str]:
        return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]

    header = [c.replace("`", "") for c in cells(lines[0])]
    return [dict(zip(header, cells(line))) for line in lines[2:]]


def _ticked(cell: str) -> list[str]:
    return re.findall(r"`([^`]+)`", cell)


def _attack() -> dict[str, dict[str, Any]]:
    data = tomllib.loads(ATTACK.read_text(encoding="utf-8"))
    return {entry["id"]: entry for entry in data["keys"]}


def _severity_table() -> dict[str, tuple[str, int]]:
    return {
        row["alert_severity"]: (row["severity"], int(row["risk_score"]))
        for row in _table("severity-table")
    }


def _tactics() -> dict[str, str]:
    return {row["Stage"]: row["Tactic ID"] for row in _table("tactic-table")}


def _mapping_fields() -> set[str]:
    fields: set[str] = set()
    for row in _table("mapping-table"):
        fields.update(_ticked(row["Kibana field"]))
    return fields


def _preserved_fields() -> set[str]:
    fields: set[str] = set()
    for row in _table("preserved-table"):
        fields.update(_ticked(row["Preserved field"]))
    return fields


def _forbidden_overrides() -> set[str]:
    return _mapping_fields() | _preserved_fields() | {"id", "version"}


def iso_seconds(value: str) -> int:
    match = _ISO_DURATION.fullmatch(value)
    if not match or value in ("P", "PT"):
        raise ValueError(value)
    days, hours, minutes, secs = (int(g or 0) for g in match.groups())
    total = ((days * 24 + hours) * 60 + minutes) * 60 + secs
    if total <= 0:
        raise ValueError(value)
    return total


def elastic_duration(value: str, units: str = "hms") -> tuple[int, str]:
    total = iso_seconds(value)
    for unit in units:
        if total % UNIT_SECONDS[unit] == 0:
            return total // UNIT_SECONDS[unit], unit
    raise AssertionError("unreachable: seconds always divide")


def date_math(value: str, units: str = "hms") -> str:
    amount, unit = elastic_duration(value, units)
    return f"{amount}{unit}"


def derive_threat(techniques: list[str], vocab: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    tactics = _tactics()
    grouped: dict[str, dict[str, set[str]]] = {}
    for tid in dict.fromkeys(techniques):
        entry = vocab[tid]
        if entry["name"].startswith(NON_ENTERPRISE_PREFIXES):
            continue
        parent = tid.split(".")[0]
        for stage in entry["tide.vocab.stages"]:
            subs = grouped.setdefault(stage, {}).setdefault(parent, set())
            if "." in tid:
                subs.add(tid)
    threat = []
    for stage, tactic_id in tactics.items():
        if stage not in grouped:
            continue
        techniques_out = []
        for parent in sorted(grouped[stage]):
            parent_entry = vocab[parent]
            technique: dict[str, Any] = {
                "id": parent,
                "name": parent_entry["name"],
                "reference": parent_entry["link"],
            }
            subs = sorted(grouped[stage][parent])
            if subs:
                technique["subtechnique"] = [
                    {
                        "id": sub,
                        "name": vocab[sub]["name"].removeprefix(parent_entry["name"] + ": "),
                        "reference": vocab[sub]["link"],
                    }
                    for sub in subs
                ]
            techniques_out.append(technique)
        threat.append(
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": tactic_id,
                    "name": stage,
                    "reference": f"https://attack.mitre.org/tactics/{tactic_id}/",
                },
                "technique": techniques_out,
            }
        )
    return threat


def check_block(block: dict[str, Any]) -> set[str]:
    codes: set[str] = set()
    rule_type = block["type"]
    alert = block.get("alert") or {}
    if ("threshold" in block) != (rule_type == "threshold"):
        codes.add("type_block")
    if ("new_terms" in block) != (rule_type == "new_terms"):
        codes.add("type_block")
    if "eql" in block and rule_type != "eql":
        codes.add("type_block")
    if rule_type in ("eql", "esql") and block.get("language"):
        codes.add("language")
    if rule_type == "esql" and (block.get("index") or block.get("data_view_id")):
        codes.add("esql_source")
    if block.get("index") and block.get("data_view_id"):
        codes.add("index_xor_data_view")
    suppression = alert.get("suppression")
    if suppression is not None:
        group_by = suppression.get("group_by")
        if rule_type == "threshold":
            if not suppression.get("duration") or group_by:
                codes.add("suppression_shape")
        elif not group_by or not 1 <= len(group_by) <= 3:
            codes.add("suppression_shape")
    new_terms = block.get("new_terms")
    if new_terms is not None and not 1 <= len(new_terms.get("fields") or []) <= 3:
        codes.add("new_terms_fields")
    threshold = block.get("threshold")
    if threshold is not None and (
        len(threshold.get("field") or []) > 5 or threshold.get("value", 0) < 1
    ):
        codes.add("threshold_fields")
    risk = alert.get("risk_score")
    if risk is not None and not (isinstance(risk, int) and 0 <= risk <= 100):
        codes.add("risk_score")
    durations = [
        (block.get("scheduling") or {}).get("frequency"),
        (block.get("scheduling") or {}).get("lookback"),
        (suppression or {}).get("duration"),
        (new_terms or {}).get("history_window"),
    ]
    for value in filter(None, durations):
        try:
            iso_seconds(value)
        except ValueError:
            codes.add("duration")
    if set(block.get("overrides") or {}) & _forbidden_overrides():
        codes.add("override_key")
    return codes


def base_path(setup: dict[str, Any]) -> str:
    url = setup["url"].rstrip("/")
    space = setup.get("space", "default")
    prefix = "" if space == "default" else f"/s/{space}"
    return f"{url}{prefix}/api/detection_engine/rules"


def compile_rule(rule: dict[str, Any], setup: dict[str, Any]) -> dict[str, Any]:
    block = rule["configurations"]["elastic"]
    rule_type = block["type"]
    alert = block.get("alert") or {}
    response = rule.get("response") or {}
    scheduling = block.get("scheduling") or {}
    status = block.get("status") or rule.get("status", "STAGING")
    level = alert.get("severity") or response.get("alert_severity") or "Informational"
    severity, risk_score = _severity_table()[level]
    if alert.get("risk_score") is not None:
        risk_score = alert["risk_score"]

    body: dict[str, Any] = {
        "rule_id": rule["metadata"]["uuid"],
        "type": rule_type,
        "name": block.get("name") or rule["name"],
        "description": rule["description"].rstrip(),
        "enabled": STATUS_STRATEGY[status] != "DISABLEMENT",
        "severity": severity,
        "risk_score": risk_score,
        "interval": date_math(scheduling.get("frequency", "PT5M")),
        "from": "now-" + date_math(scheduling.get("lookback", "PT6M")),
        "to": "now",
        "language": {"eql": "eql", "esql": "esql"}.get(
            rule_type, block.get("language") or "kuery"
        ),
        "query": block["query"].rstrip(),
    }
    if block.get("data_view_id"):
        body["data_view_id"] = block["data_view_id"]
    elif rule_type != "esql":
        index = block.get("index") or setup.get("index")
        if index:
            body["index"] = list(index)
    if (threshold := block.get("threshold")) is not None:
        body["threshold"] = {"field": list(threshold.get("field") or []), "value": threshold["value"]}
        if threshold.get("cardinality"):
            body["threshold"]["cardinality"] = [threshold["cardinality"]]
    if (new_terms := block.get("new_terms")) is not None:
        body["new_terms_fields"] = list(new_terms["fields"])
        body["history_window_start"] = "now-" + date_math(new_terms["history_window"], "dhms")
    for key, value in (block.get("eql") or {}).items():
        if value is not None:
            body[key] = value
    suppression = alert.get("suppression")
    if suppression is not None and setup.get("suppression", True):
        compiled: dict[str, Any] = {}
        if rule_type != "threshold":
            compiled["group_by"] = list(suppression["group_by"])
        if suppression.get("duration"):
            amount, unit = elastic_duration(suppression["duration"])
            compiled["duration"] = {"value": amount, "unit": unit}
        if rule_type != "threshold":
            compiled["missing_fields_strategy"] = suppression.get("missing_fields", "suppress")
        body["alert_suppression"] = compiled
    if alert.get("investigation_fields"):
        body["investigation_fields"] = {"field_names": list(alert["investigation_fields"])}
    for key in ("required_fields", "related_integrations", "false_positives", "setup"):
        if block.get(key):
            body[key] = copy.deepcopy(block[key])
    if block.get("building_block"):
        body["building_block_type"] = "default"
    body["tags"] = list(
        dict.fromkeys(["OpenTide", *(setup.get("tags") or []), *(block.get("tags") or [])])
    )
    metadata = rule["metadata"]
    authors = list(dict.fromkeys(filter(None, [metadata.get("author"), *(metadata.get("contributors") or [])])))
    if authors:
        body["author"] = authors
    public = (rule.get("references") or {}).get("public") or {}
    if public:
        body["references"] = [public[key] for key in sorted(public, key=int)]
    note = block.get("note") or ((response.get("procedure") or {}).get("analysis"))
    if note:
        body["note"] = note.rstrip()
    threat = derive_threat(list(rule.get("techniques") or []), _attack())
    if threat:
        body["threat"] = threat
    body.update(copy.deepcopy(block.get("overrides") or {}))
    return body


def esql_preflight(query: str) -> dict[str, str]:
    return {"query": query.rstrip() + "\n| LIMIT 0"}


def _setup(tenant: str) -> dict[str, Any]:
    _, body = _fence("platform-toml")
    config = tomllib.loads(body)
    return next(t for t in config["tenants"] if t["name"] == tenant)["setup"]


def _staging_setup() -> dict[str, Any]:
    return _setup("elastic-staging")


def _overlay(anchor: str) -> dict[str, Any]:
    rule = copy.deepcopy(_yaml("rule-query"))
    for key, value in _yaml(anchor).items():
        if key == "metadata":
            rule["metadata"] = {**rule["metadata"], **value}
        else:
            rule[key] = copy.deepcopy(value)
    return rule


OVERLAYS = {
    "rule-eql": "fragment-eql",
    "rule-esql": "fragment-esql",
    "rule-threshold": "fragment-threshold",
    "rule-new-terms": "fragment-new-terms",
}


class ExampleCompilationTests(unittest.TestCase):
    def test_example_a_body_matches_compilation(self) -> None:
        compiled = compile_rule(_yaml("rule-query"), _staging_setup())
        self.assertEqual(compiled, _json("body-query"))

    def test_example_a_target_url(self) -> None:
        url = base_path(_staging_setup())
        self.assertIn(f"`POST {url}`", _text())

    def test_overlay_fragments_are_subsets_of_compilation(self) -> None:
        for rule_anchor, fragment_anchor in OVERLAYS.items():
            with self.subTest(example=rule_anchor):
                compiled = compile_rule(_overlay(rule_anchor), _staging_setup())
                for key, value in _json(fragment_anchor).items():
                    self.assertIn(key, compiled)
                    self.assertEqual(compiled[key], value, key)

    def test_esql_sends_no_index(self) -> None:
        compiled = compile_rule(_overlay("rule-esql"), _staging_setup())
        self.assertNotIn("index", compiled)
        self.assertNotIn("data_view_id", compiled)

    def test_esql_preflight_body(self) -> None:
        block = _overlay("rule-esql")["configurations"]["elastic"]
        self.assertEqual(_json("esql-preflight"), esql_preflight(block["query"]))
        self.assertIn("POST <elasticsearch_url>/_query", _text())

    def test_prod_tenant_drops_suppression_and_adds_tenant_tags(self) -> None:
        prod = _setup("elastic-prod")
        self.assertIs(prod["suppression"], False)
        staged = compile_rule(_yaml("rule-query"), _staging_setup())
        compiled = compile_rule(_yaml("rule-query"), prod)
        self.assertNotIn("alert_suppression", compiled)
        self.assertEqual(compiled["tags"], ["OpenTide", "soc-prod", "Windows"])
        self.assertEqual(compiled["index"], staged["index"])
        without = {k: v for k, v in staged.items() if k not in ("alert_suppression", "tags")}
        self.assertEqual({k: v for k, v in compiled.items() if k != "tags"}, without)
        self.assertEqual(base_path(prod), "https://kibana.soc.example.internal:5601/api/detection_engine/rules")

    def test_esql_tenants_declare_elasticsearch_url(self) -> None:
        _, body = _fence("platform-toml")
        for tenant in tomllib.loads(body)["tenants"]:
            with self.subTest(tenant=tenant["name"]):
                self.assertRegex(tenant["setup"].get("elasticsearch_url", ""), r"^https://")

    def test_bodies_use_only_kibana_fields_and_carry_required_ones(self) -> None:
        rules = [_yaml("rule-query"), *(_overlay(a) for a in OVERLAYS)]
        for rule in rules:
            compiled = compile_rule(rule, _staging_setup())
            rule_type = compiled["type"]
            with self.subTest(type=rule_type):
                self.assertLessEqual(set(compiled), KIBANA_FIELDS[rule_type])
                self.assertLessEqual(KIBANA_REQUIRED[rule_type], set(compiled))
                self.assertNotIn("version", compiled)
                self.assertNotIn("id", compiled)
                self.assertIn(compiled["severity"], RISK_BANDS)
                low, high = RISK_BANDS[compiled["severity"]]
                self.assertTrue(low <= compiled["risk_score"] <= high)

    def test_valid_examples_pass_constraints(self) -> None:
        rules = {"rule-query": _yaml("rule-query"), **{a: _overlay(a) for a in OVERLAYS}}
        for anchor, rule in rules.items():
            with self.subTest(example=anchor):
                self.assertEqual(check_block(rule["configurations"]["elastic"]), set())

    def test_invalid_example_hits_exactly_the_declared_constraints(self) -> None:
        _, body = _fence("invalid")
        expected = set(re.search(r"# expect: (.*)", body).group(1).replace(" ", "").split(","))
        self.assertEqual(check_block(yaml.safe_load(body)["elastic"]), expected)


class TableConsistencyTests(unittest.TestCase):
    def test_constraint_codes_are_all_exercised_by_checker(self) -> None:
        table_codes = {row["Code"].strip("`") for row in _table("constraints-table")}
        probes = {
            "type_block": {"type": "query", "query": "x", "threshold": {"field": [], "value": 1}},
            "language": {"type": "eql", "query": "x", "language": "kuery"},
            "esql_source": {"type": "esql", "query": "FROM x", "data_view_id": "d"},
            "index_xor_data_view": {"type": "query", "query": "x", "index": ["a"], "data_view_id": "d"},
            "suppression_shape": {
                "type": "threshold",
                "query": "x",
                "threshold": {"field": [], "value": 1},
                "alert": {"suppression": {"group_by": ["a"], "duration": "PT1H"}},
            },
            "new_terms_fields": {
                "type": "new_terms",
                "query": "x",
                "new_terms": {"fields": ["a", "b", "c", "d"], "history_window": "P7D"},
            },
            "threshold_fields": {"type": "threshold", "query": "x", "threshold": {"field": [], "value": 0}},
            "risk_score": {"type": "query", "query": "x", "alert": {"risk_score": 101}},
            "duration": {"type": "query", "query": "x", "scheduling": {"frequency": "5m"}},
            "override_key": {"type": "query", "query": "x", "overrides": {"threat": []}},
        }
        self.assertEqual(table_codes, set(probes))
        for code, block in probes.items():
            with self.subTest(code=code):
                self.assertEqual(check_block(block), {code})

    def test_mapping_and_preserved_fields_are_kibana_fields(self) -> None:
        for field in _mapping_fields() | _preserved_fields():
            with self.subTest(field=field):
                self.assertIn(field, _KIBANA_COMMON | KIBANA_FIELDS["eql"] | KIBANA_FIELDS["threshold"] | KIBANA_FIELDS["new_terms"])

    def test_severity_table_covers_vocabulary_within_risk_bands(self) -> None:
        vocab = tomllib.loads(ALERT_SEVERITY.read_text(encoding="utf-8"))
        names = {entry["name"] for entry in vocab["keys"]}
        table = _severity_table()
        self.assertEqual(set(table), names)
        for level, (severity, score) in table.items():
            with self.subTest(level=level):
                low, high = RISK_BANDS[severity]
                self.assertTrue(low <= score <= high)

    def test_tactic_table_covers_every_enterprise_stage(self) -> None:
        tactics = _tactics()
        self.assertEqual(len(set(tactics.values())), len(tactics))
        for tactic_id in tactics.values():
            self.assertRegex(tactic_id, r"^TA\d{4}$")
        stages = {
            stage
            for entry in _attack().values()
            if not entry["name"].startswith(NON_ENTERPRISE_PREFIXES)
            for stage in entry["tide.vocab.stages"]
        }
        self.assertLessEqual(stages, set(tactics))

    def test_enterprise_subtechnique_names_carry_parent_prefix(self) -> None:
        vocab = _attack()
        for tid, entry in vocab.items():
            if "." not in tid or entry["name"].startswith(NON_ENTERPRISE_PREFIXES):
                continue
            with self.subTest(technique=tid):
                parent = vocab[tid.split(".")[0]]
                self.assertTrue(entry["name"].startswith(parent["name"] + ": "))

    def test_non_enterprise_techniques_are_skipped(self) -> None:
        self.assertEqual(derive_threat(["T0807"], _attack()), [])
        mobile = next(t for t, e in _attack().items() if e["name"].startswith("Mobile : "))
        self.assertEqual(derive_threat([mobile], _attack()), [])

    def test_duration_table(self) -> None:
        for row in _table("duration-table"):
            iso = row["ISO 8601"].strip("`")
            with self.subTest(duration=iso):
                interval, from_ = _ticked(row["interval / from"])
                self.assertEqual(interval, date_math(iso))
                self.assertEqual(from_, "now-" + date_math(iso))
                amount, unit = elastic_duration(iso)
                self.assertEqual(row["alert_suppression.duration"], f"`{{value: {amount}, unit: {unit}}}`")
                self.assertEqual(row["history_window_start"].strip("`"), "now-" + date_math(iso, "dhms"))


class PlatformConfigTests(unittest.TestCase):
    def test_platform_toml(self) -> None:
        _, body = _fence("platform-toml")
        config = tomllib.loads(body)
        self.assertEqual(config["platform"]["identifier"], "elastic")
        documented: set[str] = set()
        required: set[str] = set()
        for row in _table("setup-table"):
            names = _ticked(row["tenants.setup field"])
            documented.update(names)
            if row["Required"] == "yes":
                required.update(names)
        self.assertTrue(config["tenants"])
        for tenant in config["tenants"]:
            with self.subTest(tenant=tenant["name"]):
                self.assertIn(tenant["deployment"], DEPLOYMENT_VALUES)
                self.assertLessEqual(set(tenant["setup"]), documented)
                self.assertLessEqual(required, set(tenant["setup"]))
                self.assertRegex(tenant["setup"]["api_key"], r"^\$[A-Z0-9_]+$")
                self.assertRegex(tenant["setup"]["url"], r"^https://")

    def test_every_example_uses_the_platform_schema(self) -> None:
        anchors = ["rule-query", *OVERLAYS]
        for anchor in anchors:
            block = _yaml(anchor)["configurations"]["elastic"]
            self.assertEqual(block["schema"], "platform::elastic::1.0")


if __name__ == "__main__":
    unittest.main()
