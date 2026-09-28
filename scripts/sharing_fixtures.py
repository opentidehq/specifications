#!/usr/bin/env python3
"""Conformance checks for sharing.toml fixtures and golden MISP Event JSON."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SHARING = ROOT / "fixtures" / "sharing"
TEMPLATE = ROOT / "schemas" / "misp" / "opentide.definition.json"
TLP_VOCAB = ROOT / "vocabularies" / "tlp.vocab.toml"
OBJECTS = {
    "rule": ROOT / "fixtures" / "valid" / "rule-1.0.yaml",
    "objective": ROOT / "fixtures" / "valid" / "objective-1.0.yaml",
    "threat": ROOT / "fixtures" / "valid" / "threat-1.0.yaml",
}

FAMILIES = ("threat", "objective", "rule")
MISP_KEYS = {
    "name",
    "enabled",
    "url",
    "api_key",
    "max_tlp",
    "object_types",
    "rule_statuses",
    "organisation_uuid",
    "publish",
    "verify_ssl",
}
MISP_REQUIRED = ("name", "url", "api_key", "max_tlp")
KNOWN_INTEGRATIONS = {"misp": (MISP_KEYS, MISP_REQUIRED)}
TLP_DISTRIBUTION = {"clear": 1, "green": 1, "amber": 0, "amber+strict": 0, "red": 0}
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
NAME_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
ENV_REF_RE = re.compile(r"^\$\{[A-Z][A-Z0-9_]*\}$")
DOC_HOSTS = ("example.org", "example.net", "example.com")

EXPECTED_INVALID = {
    "unknown-distribution.toml": "unknown_key",
    "legacy-targets-table.toml": "unknown_key",
    "duplicate-name.toml": "duplicate_name",
    "missing-url.toml": "missing_field",
    "bad-name.toml": "name_invalid",
    "bad-max-tlp.toml": "max_tlp_unknown",
    "missing-max-tlp.toml": "missing_field",
    "bad-organisation-uuid.toml": "organisation_uuid_invalid",
    "bad-object-type.toml": "object_type_unknown",
}


def _load(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _tlp_tags() -> dict[str, str]:
    return {key["name"]: key["misp"] for key in _load(TLP_VOCAB)["keys"]}


def _is_block_array(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, dict) for item in value)


def _layer_errors(doc: dict) -> list[str]:
    """Errors that apply to one configuration layer before merge."""
    errors: list[str] = []
    seen: set[str] = set()
    for key, value in doc.items():
        if not _is_block_array(value):
            errors.append("unknown_key")
            continue
        for block in value:
            name = block.get("name")
            if not isinstance(name, str):
                errors.append("missing_field")
                continue
            if name in seen:
                errors.append("duplicate_name")
            seen.add(name)
    return errors


def _block_errors(doc: dict) -> list[str]:
    """Errors on the resolved (merged) configuration."""
    errors: list[str] = []
    tlp_names = set(_tlp_tags())
    for key, blocks in doc.items():
        if key not in KNOWN_INTEGRATIONS or not _is_block_array(blocks):
            continue
        allowed, required = KNOWN_INTEGRATIONS[key]
        for block in blocks:
            if any(field not in block for field in required):
                errors.append("missing_field")
            if set(block) - allowed:
                errors.append("unknown_key")
            name = block.get("name")
            if isinstance(name, str) and not NAME_RE.match(name):
                errors.append("name_invalid")
            max_tlp = block.get("max_tlp")
            if max_tlp is not None and max_tlp not in tlp_names:
                errors.append("max_tlp_unknown")
            org = block.get("organisation_uuid")
            if org is not None and not (isinstance(org, str) and UUID_RE.match(org)):
                errors.append("organisation_uuid_invalid")
            if any(item not in FAMILIES for item in block.get("object_types", FAMILIES)):
                errors.append("object_type_unknown")
    return errors


def _errors(doc: dict) -> list[str]:
    return _layer_errors(doc) + _block_errors(doc)


def merge_layers(*layers: dict) -> dict:
    """Merge sharing.toml layers: integration arrays merge by block name."""
    merged: dict[str, list[dict]] = {}
    for layer in layers:
        for key, blocks in layer.items():
            target = merged.setdefault(key, [])
            index = {block["name"]: block for block in target}
            for block in blocks:
                existing = index.get(block["name"])
                if existing is None:
                    copy = dict(block)
                    target.append(copy)
                    index[block["name"]] = copy
                else:
                    existing.update(block)
    return merged


def check_sharing_fixtures() -> list[str]:
    problems: list[str] = []
    valid_dir = SHARING / "valid"
    valid = valid_dir / "sharing.toml"
    if not valid.is_file():
        return ["missing fixtures/sharing/valid/sharing.toml"]
    doc = _load(valid)
    valid_errors = _errors(doc)
    if valid_errors:
        problems.append(f"{valid.relative_to(ROOT)}: unexpected {sorted(set(valid_errors))}")
    else:
        names = [block["name"] for block in doc.get("misp", [])]
        if names != ["misp-internal", "misp-isac"]:
            problems.append("valid sharing.toml must declare [[misp]] misp-internal and misp-isac")
        problems.extend(_hygiene(valid, doc))

    override_path = valid_dir / "override.toml"
    merged_path = valid_dir / "merged.toml"
    if not override_path.is_file() or not merged_path.is_file():
        problems.append("missing fixtures/sharing/valid/override.toml or merged.toml")
    else:
        override = _load(override_path)
        expected = _load(merged_path)
        layer_errors = _layer_errors(override)
        if layer_errors:
            problems.append(f"override.toml: unexpected {sorted(set(layer_errors))}")
        if merge_layers(doc, override) != expected:
            problems.append("merging override.toml onto sharing.toml does not yield merged.toml")
        merged_errors = _errors(expected)
        if merged_errors:
            problems.append(f"merged.toml: unexpected {sorted(set(merged_errors))}")
        problems.extend(_hygiene(override_path, override))

    invalid_dir = SHARING / "invalid"
    seen: set[str] = set()
    for path in sorted(invalid_dir.glob("*.toml")):
        seen.add(path.name)
        expected_code = EXPECTED_INVALID.get(path.name)
        found = _errors(_load(path))
        if expected_code is None:
            problems.append(f"{path.name}: no expected error code")
        elif expected_code not in found:
            problems.append(f"{path.name}: expected {expected_code}, got {sorted(set(found)) or 'none'}")
        elif set(found) != {expected_code}:
            problems.append(f"{path.name}: expected only {expected_code}, got {sorted(set(found))}")
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
        if values != list(FAMILIES):
            problems.append(f"opentide-type values_list changed: {values}")

    problems.extend(_check_golden_events())
    return problems


def _hygiene(path: Path, doc: dict) -> list[str]:
    """Fixtures carry placeholder credentials and documentation-reserved hosts only."""
    problems: list[str] = []
    hosts: set[str] = set()
    for blocks in doc.values():
        for block in blocks:
            api_key = block.get("api_key")
            if api_key is not None and not ENV_REF_RE.match(api_key):
                problems.append(f"{path.name}: api_key must be a ${{ENV_VAR}} reference")
            url = block.get("url")
            if url is None:
                continue
            host = urlparse(url).hostname or ""
            if not host.endswith(DOC_HOSTS):
                problems.append(f"{path.name}: {host} is not a documentation-reserved host")
            if host in hosts:
                problems.append(f"{path.name}: blocks must use distinct hosts")
            hosts.add(host)
    return problems


def _attr(event_object: dict, relation: str) -> str | None:
    for item in event_object.get("Attribute", []):
        if item.get("object_relation") == relation:
            return item.get("value")
    return None


def _check_golden_events() -> list[str]:
    import yaml

    problems: list[str] = []
    tags = _tlp_tags()
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
        document = source.read_text(encoding="utf-8")
        parsed = yaml.safe_load(document)
        tlp = parsed["metadata"]["tlp"]
        if body.get("template_uuid") != "892fd46a-f69e-455c-8c4f-843a4b8f4295":
            problems.append(f"{path.name}: template uuid drift")
        if body.get("template_version") != 5:
            problems.append(f"{path.name}: template_version must be 5")
        if event.get("Attribute"):
            problems.append(f"{path.name}: Event attributes must be empty")
        if _attr(body, "opentide-type") != family:
            problems.append(f"{path.name}: opentide-type must be {family}")
        if _attr(body, "opentide-object") != document:
            problems.append(f"{path.name}: opentide-object is not the verbatim fixture")
        if event.get("info") != parsed["name"][:255]:
            problems.append(f"{path.name}: info must be the object name")
        if event.get("distribution") != TLP_DISTRIBUTION[tlp]:
            problems.append(f"{path.name}: distribution must be {TLP_DISTRIBUTION[tlp]} for tlp {tlp}")
        if event.get("sharing_group_id") != 0:
            problems.append(f"{path.name}: sharing_group_id must be 0")
        if event.get("analysis") != 2:
            problems.append(f"{path.name}: analysis must be 2")
        if event.get("published") is not False:
            problems.append(f"{path.name}: published must be false")
        if not event.get("Tag") or event["Tag"][0].get("name") != tags[tlp]:
            problems.append(f"{path.name}: first tag must be {tags[tlp]}")
        if "tvm" in json.dumps(event) or "data-source" in json.dumps(event):
            problems.append(f"{path.name}: legacy detection mapping leaked")
    return problems
