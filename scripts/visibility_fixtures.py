#!/usr/bin/env python3
"""Conformance checks for visibility.toml fixtures (visibility::1.0)."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VISIBILITY = ROOT / "fixtures" / "visibility"

TOP_LEVEL = {"assets", "logsources", "detectors"}
REQUIRED = ("name", "description", "system")
KEYS = {*REQUIRED, "tenants", "assets", "references", "columns"}
# opentide 0.20.0 keys; each fails validation.
PLURAL_KEYS = {"tables", "indexes", "sourcetypes", "macros", "indices", "data_views", "ecs"}
KQL_TYPES = {"bool", "datetime", "decimal", "dynamic", "guid", "int", "long", "real", "string", "timespan"}
COLUMN_TYPES = {
    "sentinel": KQL_TYPES,
    "defender_for_endpoint": KQL_TYPES,
    "splunk": {"string", "number", "boolean"},
    "elastic": {
        "binary", "boolean", "byte", "constant_keyword", "date", "date_nanos", "double",
        "flattened", "float", "geo_point", "half_float", "integer", "ip", "keyword", "long",
        "match_only_text", "nested", "object", "scaled_float", "short", "text",
        "unsigned_long", "version", "wildcard",
    },
}
COLUMN_KEYS = {"type", "description"}

EXPECTED_INVALID = {
    "plural-key.toml": "plural_dataset_key",
    "ecs.toml": "plural_dataset_key",
    "unknown-key.toml": "unknown_key",
    "duplicate-name.toml": "duplicate_name",
    "empty-name.toml": "empty_name",
    "missing-name.toml": "missing_field",
    "missing-description.toml": "missing_field",
    "missing-system.toml": "missing_field",
    "column-bad-type.toml": "column_type_unknown",
    "column-missing-type.toml": "missing_field",
    "column-unknown-key.toml": "unknown_key",
    "columns-not-a-table.toml": "columns_not_a_table",
    "columns-unsupported-system.toml": "columns_unsupported_system",
    "unknown-asset.toml": "asset_unknown",
    "unknown-top-level.toml": "unknown_key",
}


def _load(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8-sig"))


def _column_errors(columns: object, system: object) -> list[str]:
    if not isinstance(columns, dict):
        return ["columns_not_a_table"]
    types = COLUMN_TYPES.get(system) if isinstance(system, str) else None
    if types is None:
        return ["columns_unsupported_system"]
    errors: list[str] = []
    for column, spec in columns.items():
        if not column.strip():
            errors.append("empty_name")
        if not isinstance(spec, dict) or "type" not in spec:
            errors.append("missing_field")
            continue
        if set(spec) - COLUMN_KEYS:
            errors.append("unknown_key")
        if spec["type"] not in types:
            errors.append("column_type_unknown")
    return errors


def _source_errors(source: dict, assets: set[str]) -> list[str]:
    errors = ["missing_field" for key in REQUIRED if key not in source]
    for key in source:
        if key in PLURAL_KEYS:
            errors.append("plural_dataset_key")
        elif key not in KEYS:
            errors.append("unknown_key")
    if isinstance(source.get("name"), str) and not source["name"].strip():
        errors.append("empty_name")
    errors.extend("asset_unknown" for asset in source.get("assets", []) if asset not in assets)
    if "columns" in source:
        errors.extend(_column_errors(source["columns"], source.get("system")))
    return errors


def errors(doc: dict) -> list[str]:
    found: list[str] = ["unknown_key" for key in doc if key not in TOP_LEVEL]
    if "logsources" not in doc:
        found.append("missing_field")
    assets = {asset.get("name") for asset in doc.get("assets", [])}
    names: set[tuple[str, str]] = set()
    for source in doc.get("logsources", []):
        found.extend(_source_errors(source, assets))
        key = (source.get("system"), source.get("name"))
        if all(isinstance(part, str) for part in key):
            if key in names:
                found.append("duplicate_name")
            names.add(key)
    for detector in doc.get("detectors", []):
        found.extend("asset_unknown" for asset in detector.get("assets", []) if asset not in assets)
    return found


def check_visibility_fixtures() -> list[str]:
    problems: list[str] = []
    valid = VISIBILITY / "valid" / "visibility.toml"
    if not valid.is_file():
        return ["missing fixtures/visibility/valid/visibility.toml"]
    found = errors(_load(valid))
    if found:
        problems.append(f"{valid.relative_to(ROOT)}: unexpected {sorted(set(found))}")

    seen: set[str] = set()
    for path in sorted((VISIBILITY / "invalid").glob("*.toml")):
        seen.add(path.name)
        expected = EXPECTED_INVALID.get(path.name)
        found = errors(_load(path))
        if expected is None:
            problems.append(f"{path.name}: no expected error code")
        elif set(found) != {expected}:
            problems.append(f"{path.name}: expected only {expected}, got {sorted(set(found)) or 'none'}")
    for name in sorted(set(EXPECTED_INVALID) - seen):
        problems.append(f"missing invalid visibility fixture {name}")

    return problems


if __name__ == "__main__":
    issues = check_visibility_fixtures()
    for issue in issues:
        print(issue)
    raise SystemExit(1 if issues else 0)
