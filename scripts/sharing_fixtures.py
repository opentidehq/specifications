#!/usr/bin/env python3
"""Conformance checks for sharing.toml fixtures and golden MISP Event JSON."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARING = ROOT / "fixtures" / "sharing"
TEMPLATE = ROOT / "schemas" / "misp" / "opentide.definition.json"
OBJECTS = {
    "rule": ROOT / "fixtures" / "valid" / "rule-1.0.yaml",
    "objective": ROOT / "fixtures" / "valid" / "objective-1.0.yaml",
    "threat": ROOT / "fixtures" / "valid" / "threat-1.0.yaml",
}

TLP_ORDER = ("clear", "green", "amber", "amber+strict", "red")
REMOVED = {
    "event_mode",
    "threat_level_source",
    "threat_level_id",
    "verify_event_org",
    "tag_namespace",
    "include_queries",
    "include_internal_references",
    "include_tenant_identifiers",
    "include_platform_blocks",
    "include_object_yaml",
}
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
IDENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

EXPECTED_INVALID = {
    "removed-event-mode.toml": "removed_key",
    "loose-max-tlp.toml": "target_policy_looser",
    "file-sharing-group.toml": "sharing_group_id_required",
    "missing-org.toml": "organisation_uuid_missing",
    "identifier-mismatch.toml": "identifier_mismatch",
}


def _load(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _errors(doc: dict) -> list[str]:
    errors: list[str] = []
    if "targets" not in doc and any(k.endswith(".toml") for k in ()):
        pass
    # A directory-shaped layout cannot appear inside one TOML document.
    # Callers reject a sharing/targets/ tree separately.
    targets = doc.get("targets")
    if not isinstance(targets, dict) or not targets:
        errors.append("targets_missing")
        return errors
    global_tlp = doc.get("max_tlp", "amber")
    global_red = bool(doc.get("allow_tlp_red", False))
    if global_tlp not in TLP_ORDER:
        errors.append("max_tlp_unknown")
    for key, target in targets.items():
        if not isinstance(target, dict):
            errors.append("target_not_table")
            continue
        if not IDENT_RE.match(key):
            errors.append("identifier_invalid")
        ident = target.get("identifier", key)
        if ident != key:
            errors.append("identifier_mismatch")
        if target.get("connector") != "misp" or target.get("schema") != "sharing::misp::1.0":
            errors.append("connector_unknown")
        target_tlp = target.get("max_tlp", global_tlp)
        if target_tlp not in TLP_ORDER or (
            global_tlp in TLP_ORDER and TLP_ORDER.index(target_tlp) > TLP_ORDER.index(global_tlp)
        ):
            errors.append("target_policy_looser")
        if target.get("allow_tlp_red", global_red) and not global_red:
            errors.append("target_policy_looser")
        misp = target.get("misp") if isinstance(target.get("misp"), dict) else {}
        for removed in REMOVED:
            if removed in target or removed in misp:
                errors.append("removed_key")
        org = misp.get("organisation_uuid")
        if not isinstance(org, str) or not UUID_RE.match(org):
            errors.append("organisation_uuid_missing")
        mode = misp.get("mode", "api")
        distribution = misp.get("distribution")
        group_id = misp.get("sharing_group_id", 0)
        group_uuid = misp.get("sharing_group_uuid") or ""
        if distribution == "sharing-group" and mode == "file" and group_id == 0:
            errors.append("sharing_group_id_required")
        if distribution == "sharing-group" and mode == "api" and not group_uuid and group_id == 0:
            errors.append("sharing_group_unresolved")
        if distribution not in (None, "sharing-group") and group_id not in (0, None):
            errors.append("sharing_group_id_must_be_zero")
    return errors


def check_sharing_fixtures() -> list[str]:
    problems: list[str] = []
    valid = SHARING / "valid" / "sharing.toml"
    if not valid.is_file():
        return ["missing fixtures/sharing/valid/sharing.toml"]
    valid_errors = _errors(_load(valid))
    if valid_errors:
        problems.append(f"{valid.relative_to(ROOT)}: unexpected {sorted(set(valid_errors))}")
    else:
        doc = _load(valid)
        ids = set(doc["targets"])
        if ids != {"misp-internal", "misp-isac"}:
            problems.append("valid sharing.toml must declare misp-internal and misp-isac")
        hosts = {
            doc["targets"]["misp-internal"]["connection"]["url"],
            doc["targets"]["misp-isac"]["connection"]["url"],
        }
        if len(hosts) != 2:
            problems.append("valid sharing.toml targets must use distinct hosts")

    invalid_dir = SHARING / "invalid"
    seen: set[str] = set()
    for path in sorted(invalid_dir.glob("*.toml")):
        seen.add(path.name)
        expected = EXPECTED_INVALID.get(path.name)
        found = _errors(_load(path))
        if expected is None:
            problems.append(f"{path.name}: no expected error code")
        elif expected not in found:
            problems.append(f"{path.name}: expected {expected}, got {sorted(set(found)) or 'none'}")
    for name in sorted(set(EXPECTED_INVALID) - seen):
        problems.append(f"missing invalid sharing fixture {name}")

    if not TEMPLATE.is_file():
        problems.append("missing schemas/misp/opentide.definition.json")
    else:
        template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        if template.get("version") != 5:
            problems.append("pinned opentide template must be version 5")
        if "schema" not in template.get("required", []):
            problems.append("pinned opentide template must require schema")
        values = template["attributes"]["opentide-type"].get("values_list")
        if values != ["threat", "objective", "rule"]:
            problems.append(f"opentide-type values_list changed: {values}")

    problems.extend(_check_golden_events())
    return problems


def _attr(event_object: dict, relation: str) -> str | None:
    for item in event_object.get("Attribute", []):
        if item.get("object_relation") == relation:
            return item.get("value")
    return None


def _check_golden_events() -> list[str]:
    problems: list[str] = []
    for family, source in OBJECTS.items():
        path = SHARING / "valid" / f"{family}-event.json"
        if not path.is_file():
            problems.append(f"missing {path.relative_to(ROOT)}")
            continue
        event = json.loads(path.read_text(encoding="utf-8"))["Event"]
        obj = event["Object"]
        if len(obj) != 1 or obj[0].get("name") != "opentide":
            problems.append(f"{path.name}: expected one opentide object")
            continue
        body = obj[0]
        if body.get("template_uuid") != "892fd46a-f69e-455c-8c4f-843a4b8f4295":
            problems.append(f"{path.name}: template uuid drift")
        if body.get("template_version") != 5:
            problems.append(f"{path.name}: template_version must be 5")
        if event.get("Attribute"):
            problems.append(f"{path.name}: Event attributes must be empty")
        if _attr(body, "opentide-type") != family:
            problems.append(f"{path.name}: opentide-type must be {family}")
        document = source.read_text(encoding="utf-8")
        if _attr(body, "opentide-object") != document:
            problems.append(f"{path.name}: opentide-object is not the verbatim fixture")
        if "tvm" in json.dumps(event) or "data-source" in json.dumps(event):
            problems.append(f"{path.name}: legacy detection mapping leaked")
    return problems
