#!/usr/bin/env python3
"""Conformance checks for deployment.state::1.0 shards and the legacy external-id keys.

Proves specs/deployment-state.md against fixtures/deployment/: the shard JSON
Schema, the filename / object_uuid rules JSON Schema cannot see, the writer's
canonical form, and the ``external_id_in_rule`` refusal on rule YAML.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "fixtures" / "deployment"
SCHEMA = ROOT / "schemas" / "deployment.state.1.0.schema.json"
RULE_FIXTURE_DIRS = (
    ROOT / "fixtures" / "valid",
    ROOT / "fixtures" / "platforms",
    ROOT / "fixtures" / "cross-object",
)

STATE_PLATFORMS = ("crowdstrike", "defender_for_endpoint", "sentinel_one")
LEGACY_MAP_KEYS = ("rule_id", "rule_id_bundle")
LEGACY_TENANT_PREFIX = "rule_id::"

# Invalid shard fixture -> (filename it is checked under, expected code).
# A shard's filename is part of its contract, and fixtures keep descriptive names.
_VALID_NAME = "00000000-0000-4000-8003-000000000010.json"
EXPECTED_INVALID_SHARDS = {
    "bad-schema.json": (_VALID_NAME, "deployment_state_shape"),
    "uuid-mismatch.json": ("00000000-0000-4000-8003-000000000011.json", "deployment_state_uuid_mismatch"),
    "noncanonical-uuid.json": ("00000000-0000-4000-8003-0000000000AB.json", "deployment_state_uuid_mismatch"),
    "numeric-id.json": (_VALID_NAME, "deployment_state_shape"),
    "leading-zero-defender-id.json": (_VALID_NAME, "deployment_state_shape"),
    "empty-id.json": (_VALID_NAME, "deployment_state_shape"),
    "whitespace-tenant.json": (_VALID_NAME, "deployment_state_shape"),
    "unsupported-platform.json": (_VALID_NAME, "deployment_state_platform"),
}
EXPECTED_INVALID_RULES = {
    "rule-with-rule-id.yaml": "external_id_in_rule",
    "rule-with-rule-id-tenant.yaml": "external_id_in_rule",
    "rule-with-rule-id-bundle.yaml": "external_id_in_rule",
}


def canonical_uuid(value: object) -> str | None:
    """Lowercase canonical form of *value*, or None when it is not a UUID."""
    if not isinstance(value, str):
        return None
    try:
        return str(uuid.UUID(value))
    except ValueError:
        return None


def render(doc: dict) -> str:
    """The exact bytes a writer emits: sorted keys, two-space indent, one trailing newline."""
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _schema() -> dict:
    return json.loads(SCHEMA.read_text(encoding="utf-8"))


def shard_codes(filename: str, text: str, schema: dict | None = None) -> list[str]:
    """Reader-side diagnostic codes for one shard stored as *filename*."""
    import jsonschema

    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return ["deployment_state_shape"]
    if not isinstance(doc, dict):
        return ["deployment_state_shape"]

    codes: list[str] = []
    stem = filename[: -len(".json")] if filename.endswith(".json") else filename
    object_uuid = doc.get("object_uuid")
    canonical = canonical_uuid(object_uuid)
    probe = dict(doc)
    if canonical is not None:
        if object_uuid != canonical or stem != canonical or stem != object_uuid:
            codes.append("deployment_state_uuid_mismatch")
        # Spelling is reported above; let the schema judge the rest.
        probe["object_uuid"] = canonical

    platforms = doc.get("platforms")
    if isinstance(platforms, dict):
        unsupported = [key for key in platforms if key not in STATE_PLATFORMS]
        if unsupported:
            codes.append("deployment_state_platform")
            probe["platforms"] = {k: v for k, v in platforms.items() if k in STATE_PLATFORMS}

    validator = jsonschema.Draft202012Validator(schema or _schema())
    if any(True for _ in validator.iter_errors(probe)):
        codes.append("deployment_state_shape")
    return codes


def directory_codes(names: list[str]) -> list[str]:
    """Codes for a shard directory listing: two names for one uuid fail closed."""
    seen: dict[str, str] = {}
    codes: list[str] = []
    for name in names:
        if not name.endswith(".json"):
            continue
        key = canonical_uuid(name[: -len(".json")]) or name[: -len(".json")].lower()
        if key in seen and seen[key] != name:
            codes.append("deployment_state_uuid_mismatch")
        seen.setdefault(key, name)
    return codes


def writer_problems(text: str) -> list[str]:
    """Ways *text* differs from what a writer emits. Readers may still accept it."""
    doc = json.loads(text)
    problems: list[str] = []
    if render(doc) != text:
        problems.append("not in canonical form (sorted keys, two-space indent, one trailing newline)")
    platforms = doc.get("platforms")
    if not platforms:
        problems.append("a shard with no binding must be deleted, not written")
    elif any(not tenants for tenants in platforms.values()):
        problems.append("an empty platform map must be removed")
    return problems


def is_legacy_key(key: object) -> bool:
    return isinstance(key, str) and (key in LEGACY_MAP_KEYS or key.startswith(LEGACY_TENANT_PREFIX))


def rule_codes(doc: object) -> list[str]:
    """``external_id_in_rule`` once per legacy key at the root of any platform block."""
    if not isinstance(doc, dict):
        return []
    configurations = doc.get("configurations")
    if not isinstance(configurations, dict):
        return []
    codes: list[str] = []
    for block in configurations.values():
        if isinstance(block, dict):
            codes.extend("external_id_in_rule" for key in block if is_legacy_key(key))
    return codes


def check_deployment_fixtures() -> list[str]:
    import yaml

    problems: list[str] = []
    if not SCHEMA.is_file():
        return [f"missing {SCHEMA.relative_to(ROOT)}"]
    schema = _schema()

    valid_dir = DEPLOYMENT / "valid"
    valid = sorted(valid_dir.glob("*.json"))
    if not valid:
        problems.append("missing fixtures/deployment/valid/*.json")
    for path in valid:
        text = path.read_text(encoding="utf-8")
        found = shard_codes(path.name, text, schema)
        if found:
            problems.append(f"{path.relative_to(ROOT)}: unexpected {sorted(set(found))}")
            continue
        for problem in writer_problems(text):
            problems.append(f"{path.relative_to(ROOT)}: {problem}")
        platforms = json.loads(text)["platforms"]
        if sorted(platforms) != list(STATE_PLATFORMS):
            problems.append(f"{path.relative_to(ROOT)}: must bind all three state-backed platforms")
    problems.extend(
        f"fixtures/deployment/valid: {code}" for code in directory_codes([p.name for p in valid])
    )

    invalid_dir = DEPLOYMENT / "invalid"
    seen: set[str] = set()
    for path in sorted(invalid_dir.glob("*.json")):
        seen.add(path.name)
        expectation = EXPECTED_INVALID_SHARDS.get(path.name)
        if expectation is None:
            problems.append(f"{path.name}: no expected error code")
            continue
        filename, expected = expectation
        found = shard_codes(filename, path.read_text(encoding="utf-8"), schema)
        if set(found) != {expected}:
            problems.append(f"{path.name}: expected only {expected}, got {sorted(set(found)) or 'none'}")
    for path in sorted(invalid_dir.glob("*.yaml")):
        seen.add(path.name)
        expected = EXPECTED_INVALID_RULES.get(path.name)
        if expected is None:
            problems.append(f"{path.name}: no expected error code")
            continue
        found = rule_codes(yaml.safe_load(path.read_text(encoding="utf-8")))
        if set(found) != {expected}:
            problems.append(f"{path.name}: expected only {expected}, got {sorted(set(found)) or 'none'}")
    expected_names = set(EXPECTED_INVALID_SHARDS) | set(EXPECTED_INVALID_RULES)
    for name in sorted(expected_names - seen):
        problems.append(f"missing invalid deployment fixture {name}")

    # No conformance rule fixture may carry a vendor id: they would all fail validation.
    for directory in RULE_FIXTURE_DIRS:
        for path in sorted(directory.glob("*.yaml")):
            if rule_codes(yaml.safe_load(path.read_text(encoding="utf-8"))):
                problems.append(f"{path.relative_to(ROOT)}: carries a legacy external-id key")
    return problems
