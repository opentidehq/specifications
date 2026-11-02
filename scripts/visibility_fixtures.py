#!/usr/bin/env python3
"""Conformance checks for visibility.toml fixtures (visibility::1.0)."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VISIBILITY = ROOT / "fixtures" / "visibility"

TOP_LEVEL = {"assets", "logsources", "detectors"}
COMMON_KEYS = {"name", "description", "system", "tenants", "assets", "references", "columns"}
DATASET_KEYS = {
    "sentinel": {"table"},
    "defender_for_endpoint": {"table"},
    "splunk": {"index", "sourcetype", "macro"},
    "elastic": {"index", "data_view", "ecs"},
}
ALL_DATASET_KEYS = {"table", "index", "sourcetype", "macro", "data_view", "ecs"}
PLURAL_KEYS = {
    "tables": "table",
    "indexes": "index",
    "sourcetypes": "sourcetype",
    "macros": "macro",
    "indices": "index",
    "data_views": "data_view",
}
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
COLUMN_KEYS = {"name", "type", "description"}

EXPECTED_INVALID = {
    "plural-key.toml": "plural_dataset_key",
    "wrong-system-key.toml": "dataset_key_system",
    "two-datasets.toml": "multiple_datasets",
    "macro-with-index.toml": "multiple_datasets",
    "empty-name.toml": "empty_name",
    "duplicate-name.toml": "duplicate_name",
    "duplicate-dataset.toml": "duplicate_dataset",
    "columns-on-wildcard.toml": "columns_on_wildcard",
    "columns-without-dataset.toml": "columns_without_dataset",
    "column-bad-type.toml": "column_type_unknown",
    "column-missing-type.toml": "missing_field",
    "duplicate-column.toml": "duplicate_column",
    "no-name-no-dataset.toml": "missing_field",
    "missing-system.toml": "missing_field",
    "unknown-key.toml": "unknown_key",
    "unknown-top-level.toml": "unknown_key",
    "unknown-asset.toml": "asset_unknown",
}


def _load(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8-sig"))


def dataset(source: dict) -> str | None:
    """The dataset a log source declares, as its default name."""
    for key in ("table", "macro", "data_view"):
        if isinstance(source.get(key), str):
            return source[key]
    index, sourcetype = source.get("index"), source.get("sourcetype")
    if isinstance(index, str) and isinstance(sourcetype, str):
        return f"{index}:{sourcetype}"
    return index if isinstance(index, str) else sourcetype if isinstance(sourcetype, str) else None


def _dataset_keys(source: dict) -> set[str]:
    return {key for key in ("table", "index", "sourcetype", "macro", "data_view") if key in source}


def _source_errors(source: dict, assets: set[str]) -> list[str]:
    errors: list[str] = []
    system = source.get("system")
    if not isinstance(system, str):
        return ["missing_field"]
    for key in source:
        if key in PLURAL_KEYS:
            errors.append("plural_dataset_key")
        elif key in ALL_DATASET_KEYS:
            if key not in DATASET_KEYS.get(system, set()):
                errors.append("dataset_key_system")
        elif key not in COMMON_KEYS:
            errors.append("unknown_key")
    keys = _dataset_keys(source)
    if len(keys) > 1 and keys != {"index", "sourcetype"}:
        errors.append("multiple_datasets")
    for key in keys:
        value = source[key]
        if not isinstance(value, str) or not value.strip():
            errors.append("empty_name")
    if "name" not in source and not keys:
        errors.append("missing_field")
    if isinstance(source.get("name"), str) and not source["name"].strip():
        errors.append("empty_name")
    errors.extend("asset_unknown" for asset in source.get("assets", []) if asset not in assets)
    columns = source.get("columns")
    if columns is not None:
        name = dataset(source)
        if not keys:
            errors.append("columns_without_dataset")
        elif name is not None and "*" in name:
            errors.append("columns_on_wildcard")
        seen: set[str] = set()
        for column in columns:
            if "name" not in column or "type" not in column:
                errors.append("missing_field")
                continue
            if set(column) - COLUMN_KEYS:
                errors.append("unknown_key")
            if not str(column["name"]).strip():
                errors.append("empty_name")
            if column["name"] in seen:
                errors.append("duplicate_column")
            seen.add(column["name"])
            if column["type"] not in COLUMN_TYPES.get(system, set()):
                errors.append("column_type_unknown")
    return errors


def errors(doc: dict) -> list[str]:
    found: list[str] = ["unknown_key" for key in doc if key not in TOP_LEVEL]
    if "logsources" not in doc:
        found.append("missing_field")
    assets = {asset.get("name") for asset in doc.get("assets", [])}
    names: set[tuple[str, str]] = set()
    datasets: set[tuple[str, str]] = set()
    for source in doc.get("logsources", []):
        found.extend(_source_errors(source, assets))
        system = source.get("system")
        if not isinstance(system, str):
            continue
        name = source.get("name") or dataset(source)
        if name is not None:
            if (system, name) in names:
                found.append("duplicate_name")
            names.add((system, name))
        identity = dataset(source)
        if identity is not None and _dataset_keys(source) and not any(k in source for k in PLURAL_KEYS):
            if (system, identity) in datasets:
                found.append("duplicate_dataset")
            datasets.add((system, identity))
    for detector in doc.get("detectors", []):
        found.extend("asset_unknown" for asset in detector.get("assets", []) if asset not in assets)
    return found


SPLIT_ORDER = (
    ("tables", "table"),
    ("indexes", "index"),
    ("sourcetypes", "sourcetype"),
    ("macros", "macro"),
    ("indices", "index"),
    ("data_views", "data_view"),
)
CARRIED = ("description", "system", "tenants", "assets", "references")


def migrate(doc: dict) -> tuple[dict, dict[str, list[str]]]:
    """Split plural dataset lists into one log source per dataset (visibility.md, Migration)."""
    sources: list[dict] = []
    renamed: dict[str, list[str]] = {}
    for source in doc.get("logsources", []):
        if not any(key in source for key in PLURAL_KEYS):
            sources.append(source)
            continue
        carried = {key: source[key] for key in CARRIED if key in source}
        split: list[dict] = []
        for plural, singular in SPLIT_ORDER:
            for name in source.get(plural, []):
                entry = {**carried, singular: name}
                if plural == "indices" and "ecs" in source:
                    entry["ecs"] = source["ecs"]
                split.append(entry)
        if len(split) == 1 and "name" in source:
            split[0]["name"] = source["name"]
        else:
            for entry in split:
                entry["name"] = dataset(entry)
            if "name" in source:
                renamed[source["name"]] = [entry["name"] for entry in split]
        sources.extend(split)
    return {**{k: v for k, v in doc.items() if k != "logsources"}, "logsources": sources}, renamed


def migrate_references(references: list[str], renamed: dict[str, list[str]]) -> list[str]:
    out: list[str] = []
    for reference in references:
        out.extend(renamed.get(reference, [reference]))
    return out


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

    migration = VISIBILITY / "migration"
    before, expected = _load(migration / "v0.20.0.toml"), _load(migration / "expected.toml")
    if "plural_dataset_key" not in errors(before):
        problems.append("migration/v0.20.0.toml must use the plural keys")
    migrated, renamed = migrate(before)
    if migrated != expected:
        problems.append("migrating migration/v0.20.0.toml does not yield migration/expected.toml")
    if errors(expected):
        problems.append(f"migration/expected.toml: unexpected {sorted(set(errors(expected)))}")
    references = _load(migration / "references.toml")
    if migrate_references(references["before"], renamed) != references["after"]:
        problems.append("migration/references.toml: signal references do not migrate as listed")
    return problems


if __name__ == "__main__":
    issues = check_visibility_fixtures()
    for issue in issues:
        print(issue)
    raise SystemExit(1 if issues else 0)
