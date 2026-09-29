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
    "threat_match": _KIBANA_COMMON
    | {
        "concurrent_searches", "items_per_search", "threat_filters", "threat_index",
        "threat_indicator_path", "threat_language", "threat_mapping", "threat_query",
    },
    "machine_learning": (_KIBANA_COMMON - {"data_view_id", "filters", "index", "language", "query", "saved_id"})
    | {"anomaly_threshold", "machine_learning_job_id"},
}
_KIBANA_REQUIRED_COMMON = {"name", "description", "type", "severity", "risk_score"}
KIBANA_REQUIRED = {
    "query": _KIBANA_REQUIRED_COMMON,
    "eql": _KIBANA_REQUIRED_COMMON | {"language", "query"},
    "esql": _KIBANA_REQUIRED_COMMON | {"language", "query"},
    "threshold": _KIBANA_REQUIRED_COMMON | {"query", "threshold"},
    "new_terms": _KIBANA_REQUIRED_COMMON
    | {"query", "new_terms_fields", "history_window_start"},
    "threat_match": _KIBANA_REQUIRED_COMMON
    | {"query", "threat_index", "threat_mapping", "threat_query"},
    "machine_learning": _KIBANA_REQUIRED_COMMON | {"anomaly_threshold", "machine_learning_job_id"},
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
_SHORT_DURATION = re.compile(r"(\d+)([smhd])")
_ISO_DURATION = re.compile(r"P(?:(\d+)D)?(?:T(?=\d)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?")
# Mapping types used by ECS fields (elastic/ecs generated/ecs/ecs_flat.yml, main, 2026-09).
ECS_FIELD_TYPES = frozenset(
    """keyword long date boolean object flattened float nested wildcard ip
    geo_point double scaled_float constant_keyword match_only_text""".split()
)


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


def duration_seconds(value: str) -> int:
    if short := _SHORT_DURATION.fullmatch(value):
        total = int(short.group(1)) * UNIT_SECONDS[short.group(2)]
    elif (match := _ISO_DURATION.fullmatch(value)) and value not in ("P", "PT"):
        days, hours, minutes, secs = (int(g or 0) for g in match.groups())
        total = ((days * 24 + hours) * 60 + minutes) * 60 + secs
    else:
        raise ValueError(value)
    if total <= 0:
        raise ValueError(value)
    return total


def elastic_duration(value: str, units: str = "dhms") -> tuple[int, str]:
    total = duration_seconds(value)
    for unit in units:
        if total % UNIT_SECONDS[unit] == 0:
            return total // UNIT_SECONDS[unit], unit
    raise AssertionError("unreachable: seconds always divide")


def date_math(value: str, units: str = "dhms") -> str:
    amount, unit = elastic_duration(value, units)
    return f"{amount}{unit}"


def field_types() -> set[str]:
    match = re.search(r"FieldType = Literal\[(.*?)\]", _text(), flags=re.DOTALL)
    if not match:
        raise AssertionError("RFC 0006 is missing the FieldType literal")
    return set(re.findall(r'"([a-z_]+)"', match.group(1)))


def related_integration(entry: str | dict[str, Any]) -> dict[str, str]:
    item = {"package": entry} if isinstance(entry, str) else dict(entry)
    item.setdefault("version", "*")
    return item


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


_REMOVED_FLAT = frozenset({
    "saved_id", "interval", "from",
    "timestamp_field", "event_category_override", "tiebreaker_field",
    "new_terms_fields", "history_window_start",
    "threat_index", "threat_query", "threat_language", "threat_mapping",
    "threat_filters", "threat_indicator_path",
    "concurrent_searches", "items_per_search",
    "machine_learning_job_id", "anomaly_threshold",
})
_RULE_TYPES = frozenset({
    "query", "eql", "esql", "threshold", "new_terms", "threat_match", "machine_learning",
})


def _pattern_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item for item in value)


def check_block(block: dict[str, Any]) -> set[str]:
    codes: set[str] = set()
    rule_type = block.get("type")
    if rule_type not in _RULE_TYPES or (_REMOVED_FLAT & set(block)):
        codes.add("type_block")
    if ("threshold" in block) != (rule_type == "threshold"):
        codes.add("type_block")
    new_terms = block.get("new_terms")
    if ("new_terms" in block) != (rule_type == "new_terms") or (
        rule_type == "new_terms" and (
            not isinstance(new_terms, dict)
            or "fields" not in new_terms
            or "history_window_start" not in new_terms
        )
    ):
        codes.add("type_block")
    if "eql" in block and rule_type != "eql":
        codes.add("type_block")
    threat = block.get("threat")
    if ("threat" in block) != (rule_type == "threat_match") or (
        rule_type == "threat_match" and (
            not isinstance(threat, dict)
            or any(key not in threat for key in ("index", "query", "mapping"))
        )
    ):
        codes.add("type_block")
    ml = block.get("machine_learning")
    if ("machine_learning" in block) != (rule_type == "machine_learning") or (
        rule_type == "machine_learning" and (
            not isinstance(ml, dict) or "job_id" not in ml or "anomaly_threshold" not in ml
        )
    ):
        codes.add("type_block")
    if rule_type != "machine_learning" and not block.get("query"):
        codes.add("type_block")
    if rule_type in ("eql", "esql", "machine_learning") and block.get("language"):
        codes.add("language")
    if rule_type in ("esql", "machine_learning") and (
        block.get("index") or block.get("data_view_id") or block.get("filters")
    ):
        codes.add("esql_source")
    if block.get("index") and block.get("data_view_id"):
        codes.add("index_xor_data_view")
    if "index" in block and not _pattern_list(block["index"]):
        codes.add("index_list")
    if isinstance(threat, dict) and "index" in threat and not _pattern_list(threat["index"]):
        codes.add("index_list")
    suppression = block.get("alert_suppression")
    if suppression is not None:
        group_by = suppression.get("group_by")
        if rule_type == "threshold":
            if not suppression.get("duration") or group_by:
                codes.add("suppression_shape")
        elif (
            not group_by
            or not 1 <= len(group_by) <= 3
            or len(set(group_by)) != len(group_by)
            or not all(group_by)
        ):
            codes.add("suppression_shape")
    if isinstance(new_terms, dict) and "fields" in new_terms and not 1 <= len(new_terms["fields"]) <= 3:
        codes.add("new_terms_fields")
    threshold = block.get("threshold")
    if isinstance(threshold, dict) and (
        len(threshold.get("field") or []) > 5 or threshold.get("value", 0) < 1
    ):
        codes.add("threshold_fields")
    risk = block.get("risk_score")
    if risk is not None and not (isinstance(risk, int) and 0 <= risk <= 100):
        codes.add("risk_score")
    scheduling = block.get("scheduling") or {}
    if "scheduling" in block and not isinstance(scheduling, dict):
        codes.add("duration")
        scheduling = {}
    history = new_terms.get("history_window_start") if isinstance(new_terms, dict) else None
    for value in filter(None, (
        scheduling.get("interval"), scheduling.get("from"),
        (suppression or {}).get("duration"), history,
    )):
        try:
            duration_seconds(value)
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
    response = rule.get("response") or {}
    # Deployment status is per platform block. The rule's own status is not read.
    status = block.get("status") or "STAGING"
    level = block.get("severity") or response.get("alert_severity") or "Informational"
    severity, risk_score = _severity_table()[level]
    if block.get("risk_score") is not None:
        risk_score = block["risk_score"]

    scheduling = block.get("scheduling") or {}
    body: dict[str, Any] = {
        "rule_id": rule["metadata"]["uuid"],
        "type": rule_type,
        "name": block.get("name") or rule["name"],
        "description": rule["description"].rstrip(),
        "enabled": STATUS_STRATEGY[status] != "DISABLEMENT",
        "severity": severity,
        "risk_score": risk_score,
        "interval": date_math(scheduling.get("interval", "5m")),
        "from": "now-" + date_math(scheduling.get("from", "6m")),
        "to": "now",
    }
    if rule_type == "eql":
        body["language"] = "eql"
    elif rule_type == "esql":
        body["language"] = "esql"
    elif rule_type != "machine_learning":
        body["language"] = block.get("language") or "kuery"
    if block.get("query") is not None:
        body["query"] = block["query"].rstrip()
    if block.get("data_view_id"):
        body["data_view_id"] = block["data_view_id"]
    elif rule_type not in ("esql", "machine_learning"):
        index = block.get("index") or setup.get("index")
        if isinstance(index, list) and index:
            body["index"] = list(index)
    if block.get("filters") is not None and rule_type not in ("esql", "machine_learning"):
        body["filters"] = copy.deepcopy(block["filters"])
    if (threshold := block.get("threshold")) is not None:
        body["threshold"] = {"field": list(threshold.get("field") or []), "value": threshold["value"]}
        if threshold.get("cardinality"):
            body["threshold"]["cardinality"] = [threshold["cardinality"]]
    if (new_terms := block.get("new_terms")) is not None:
        body["new_terms_fields"] = list(new_terms["fields"])
        body["history_window_start"] = "now-" + date_math(new_terms["history_window_start"])
    for key in ("timestamp_field", "event_category_override", "tiebreaker_field"):
        if (block.get("eql") or {}).get(key) is not None:
            body[key] = block["eql"][key]
    if (threat_match := block.get("threat")) is not None:
        body["threat_index"] = list(threat_match["index"])
        body["threat_query"] = threat_match["query"]
        if threat_match.get("language"):
            body["threat_language"] = threat_match["language"]
        if threat_match.get("filters") is not None:
            body["threat_filters"] = copy.deepcopy(threat_match["filters"])
        if threat_match.get("indicator_path") is not None:
            body["threat_indicator_path"] = threat_match["indicator_path"]
        for key, kibana_key in (("concurrent_searches", "concurrent_searches"), ("items_per_search", "items_per_search")):
            if threat_match.get(key) is not None:
                body[kibana_key] = threat_match[key]
        body["threat_mapping"] = [
            {"entries": [{**entry, "type": entry.get("type", "mapping")} for entry in group["entries"]]}
            for group in threat_match["mapping"]
        ]
    if (ml := block.get("machine_learning")) is not None:
        body["machine_learning_job_id"] = copy.deepcopy(ml["job_id"])
        body["anomaly_threshold"] = ml["anomaly_threshold"]
    for key in (
        "severity_mapping", "risk_score_mapping", "rule_name_override", "timestamp_override",
        "timestamp_override_fallback_disabled", "max_signals", "license", "actions",
        "response_actions", "timeline_id", "timeline_title", "meta",
    ):
        if block.get(key) is not None:
            body[key] = copy.deepcopy(block[key])
    suppression = block.get("alert_suppression")
    if suppression is not None and setup.get("suppression", True):
        compiled: dict[str, Any] = {}
        if rule_type != "threshold":
            compiled["group_by"] = list(suppression["group_by"])
        if suppression.get("duration"):
            amount, unit = elastic_duration(suppression["duration"], "hms")
            compiled["duration"] = {"value": amount, "unit": unit}
        if rule_type != "threshold":
            compiled["missing_fields_strategy"] = suppression.get("missing_fields_strategy", "suppress")
        body["alert_suppression"] = compiled
    if block.get("investigation_fields"):
        body["investigation_fields"] = {"field_names": list(block["investigation_fields"])}
    if block.get("required_fields"):
        body["required_fields"] = sorted(
            ({"name": field["name"], "type": field["type"]} for field in block["required_fields"]),
            key=lambda field: field["name"],
        )
    if block.get("related_integrations"):
        body["related_integrations"] = [related_integration(e) for e in block["related_integrations"]]
    for key in ("false_positives", "setup"):
        if block.get(key):
            body[key] = copy.deepcopy(block[key])
    if block.get("building_block"):
        body["building_block_type"] = "default"
    if block.get("exceptions_list") is not None or block.get("endpoint_exceptions"):
        lists = copy.deepcopy(block.get("exceptions_list") or [])
        endpoint = {
            "id": "endpoint_list", "list_id": "endpoint_list",
            "namespace_type": "agnostic", "type": "endpoint",
        }
        if block.get("endpoint_exceptions") and endpoint not in lists:
            lists.append(endpoint)
        body["exceptions_list"] = lists
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


EXAMPLES = (
    "rule-query", "rule-eql", "rule-esql", "rule-threshold",
    "rule-new-terms", "rule-threat", "rule-ml",
)


class ExampleCompilationTests(unittest.TestCase):
    def test_example_a_body_matches_compilation(self) -> None:
        compiled = compile_rule(_yaml("rule-query"), _staging_setup())
        self.assertEqual(compiled, _json("body-query"))

    def test_example_a_target_url(self) -> None:
        url = base_path(_staging_setup())
        self.assertIn(f"`POST {url}`", _text())

    def test_esql_sends_no_index(self) -> None:
        compiled = compile_rule(_yaml("rule-esql"), _staging_setup())
        self.assertNotIn("index", compiled)
        self.assertNotIn("data_view_id", compiled)
        self.assertNotIn("filters", compiled)
        self.assertEqual(compiled["language"], "esql")
        self.assertEqual(compiled["interval"], "15m")
        self.assertEqual(compiled["from"], "now-20m")

    def test_esql_preflight_body(self) -> None:
        block = _yaml("rule-esql")["configurations"]["elastic"]
        self.assertEqual(_json("esql-preflight"), esql_preflight(block["query"]))
        self.assertIn("POST <elasticsearch_url>/_query", _text())

    def test_prod_tenant_drops_suppression_and_adds_tenant_tags(self) -> None:
        prod = _setup("elastic-prod")
        self.assertIs(prod["suppression"], False)
        staged = compile_rule(_yaml("rule-query"), _staging_setup())
        compiled = compile_rule(_yaml("rule-query"), prod)
        self.assertNotIn("alert_suppression", compiled)
        self.assertEqual(compiled["tags"], ["OpenTide", "soc-prod", "Windows", "LOLBAS"])
        self.assertEqual(compiled["index"], staged["index"])
        without = {k: v for k, v in staged.items() if k not in ("alert_suppression", "tags")}
        self.assertEqual({k: v for k, v in compiled.items() if k != "tags"}, without)
        self.assertEqual(base_path(prod), "https://kibana.soc.example.internal:5601/api/detection_engine/rules")

    def test_tenants_declare_https_elasticsearch_url(self) -> None:
        _, body = _fence("platform-toml")
        for tenant in tomllib.loads(body)["tenants"]:
            with self.subTest(tenant=tenant["name"]):
                self.assertRegex(tenant["setup"]["elasticsearch_url"], r"^https://")

    def test_bodies_use_only_kibana_fields_and_carry_required_ones(self) -> None:
        rules = [_yaml(anchor) for anchor in EXAMPLES]
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
        rules = {anchor: _yaml(anchor) for anchor in EXAMPLES}
        for anchor, rule in rules.items():
            with self.subTest(example=anchor):
                self.assertEqual(check_block(rule["configurations"]["elastic"]), set())

    def test_threat_match_and_machine_learning_compile(self) -> None:
        threat = compile_rule(_yaml("rule-threat"), _staging_setup())
        self.assertEqual(check_block(_yaml("rule-threat")["configurations"]["elastic"]), set())
        self.assertEqual(threat["type"], "threat_match")
        self.assertEqual(threat["threat_index"], ["logs-ti_abusech.malware-*", "logs-ti_misp.indicator-*"])
        self.assertEqual(
            threat["threat_mapping"],
            [
                {"entries": [{"field": "file.hash.sha256", "type": "mapping", "value": "threat.indicator.file.hash.sha256"}]},
                {"entries": [
                    {"field": "file.hash.md5", "type": "mapping", "value": "threat.indicator.file.hash.md5"},
                    {"field": "file.path", "type": "mapping", "value": "threat.indicator.file.path", "negate": True},
                ]},
            ],
        )
        self.assertEqual(threat["threat_indicator_path"], "threat.indicator")
        self.assertEqual(threat["concurrent_searches"], 5)
        self.assertEqual(threat["threat"][0]["tactic"]["id"], "TA0002")
        ml = compile_rule(_yaml("rule-ml"), _staging_setup())
        self.assertEqual(check_block(_yaml("rule-ml")["configurations"]["elastic"]), set())
        self.assertEqual(ml["machine_learning_job_id"], ["high_count_network_events", "high_count_network_denies"])
        self.assertEqual(ml["anomaly_threshold"], 75)
        self.assertNotIn("query", ml)
        self.assertNotIn("language", ml)
        self.assertNotIn("index", ml)

    def test_advanced_settings_keep_their_kibana_names(self) -> None:
        rule = _yaml("rule-query")
        block = rule["configurations"]["elastic"]
        compiled = compile_rule(rule, _staging_setup())
        for key in (
            "max_signals", "timestamp_override", "timestamp_override_fallback_disabled",
            "rule_name_override", "license", "severity_mapping", "risk_score_mapping", "filters",
        ):
            self.assertEqual(compiled[key], block[key], key)
        self.assertEqual(compiled["interval"], "5m")
        self.assertEqual(compiled["from"], "now-6m")
        self.assertEqual(compiled["exceptions_list"][-1], {
            "id": "endpoint_list", "list_id": "endpoint_list",
            "namespace_type": "agnostic", "type": "endpoint",
        })

    def test_default_template_is_a_custom_query_with_a_pattern_list(self) -> None:
        rule = _yaml("rule-template")
        block = rule["configurations"]["elastic"]
        self.assertEqual(block["type"], "query")
        self.assertIsInstance(block["index"], list)
        self.assertEqual(check_block(block), set())
        compiled = compile_rule(rule, _staging_setup())
        self.assertEqual(compiled["index"], ["logs-*"])
        self.assertEqual(compiled["interval"], "5m")
        self.assertEqual(compiled["from"], "now-6m")
        self.assertNotIn("status", rule)

    def test_deployment_status_comes_from_the_elastic_block_only(self) -> None:
        rule = copy.deepcopy(_yaml("rule-query"))
        rule["status"] = "DISABLED"
        compiled = compile_rule(rule, _staging_setup())
        self.assertTrue(compiled["enabled"])
        rule["configurations"]["elastic"]["status"] = "DISABLED"
        rule["status"] = "PRODUCTION"
        compiled = compile_rule(rule, _staging_setup())
        self.assertFalse(compiled["enabled"])
        self.assertNotIn("status: ", _fence("rule-query")[1].split("configurations:")[0])

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
            "index_list": {"type": "query", "query": "x", "index": "logs-*"},
            "suppression_shape": {
                "type": "threshold",
                "query": "x",
                "threshold": {"field": [], "value": 1},
                "alert_suppression": {"group_by": ["a"], "duration": "1h"},
            },
            "new_terms_fields": {
                "type": "new_terms",
                "query": "x",
                "new_terms": {"fields": ["a", "b", "c", "d"], "history_window_start": "7d"},
            },
            "threshold_fields": {"type": "threshold", "query": "x", "threshold": {"field": [], "value": 0}},
            "risk_score": {"type": "query", "query": "x", "risk_score": 101},
            "duration": {"type": "query", "query": "x", "scheduling": {"interval": "5min", "from": "6m"}},
            "override_key": {"type": "query", "query": "x", "overrides": {"threat": []}},
        }
        self.assertEqual(table_codes, set(probes))
        for code, block in probes.items():
            with self.subTest(code=code):
                self.assertEqual(check_block(block), {code})
        self.assertEqual(
            check_block({"type": "query", "query": "x", "interval": "5m", "saved_id": "abc"}),
            {"type_block"},
        )

    def test_machine_learning_job_id_string_is_kept(self) -> None:
        rule = copy.deepcopy(_yaml("rule-ml"))
        rule["configurations"]["elastic"]["machine_learning"]["job_id"] = "rare_process_by_host"
        compiled = compile_rule(rule, _staging_setup())
        self.assertEqual(compiled["machine_learning_job_id"], "rare_process_by_host")

    def test_mapping_and_preserved_fields_are_kibana_fields(self) -> None:
        allowed = set().union(*KIBANA_FIELDS.values())
        for field in _mapping_fields() | _preserved_fields():
            with self.subTest(field=field):
                self.assertIn(field, allowed)

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
            written = row["Written"].strip("`")
            with self.subTest(duration=written):
                interval, from_ = _ticked(row["interval / from"])
                self.assertEqual(interval, date_math(written))
                self.assertEqual(from_, "now-" + date_math(written))
                amount, unit = elastic_duration(written, "hms")
                self.assertEqual(row["alert_suppression.duration"], f"`{{value: {amount}, unit: {unit}}}`")
                self.assertEqual(row["history_window_start"].strip("`"), "now-" + date_math(written))

    def test_duration_forms(self) -> None:
        self.assertEqual(duration_seconds("90s"), duration_seconds("PT90S"))
        self.assertEqual(duration_seconds("14d"), duration_seconds("P14D"))
        for bad in ("5min", "1w", "0m", "1.5h", "PT", "P", "5"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                duration_seconds(bad)

    def test_field_types_cover_ecs_and_examples(self) -> None:
        types = field_types()
        self.assertLessEqual(ECS_FIELD_TYPES, types)
        for anchor in EXAMPLES:
            required = _yaml(anchor)["configurations"]["elastic"].get("required_fields") or []
            with self.subTest(example=anchor):
                self.assertIsInstance(required, list)
                self.assertLessEqual({field["type"] for field in required}, types)

    def test_related_integration_shorthand(self) -> None:
        self.assertEqual(related_integration("windows"), {"package": "windows", "version": "*"})
        self.assertEqual(
            related_integration({"package": "aws", "integration": "cloudtrail", "version": "^2.0.0"}),
            {"package": "aws", "integration": "cloudtrail", "version": "^2.0.0"},
        )


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
        anchors = EXAMPLES
        for anchor in anchors:
            block = _yaml(anchor)["configurations"]["elastic"]
            self.assertEqual(block["schema"], "platform::elastic::1.0")


if __name__ == "__main__":
    unittest.main()
