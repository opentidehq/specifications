#!/usr/bin/env python3
"""Validate specifications repo: vocabulary TOML files and fixture layout."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VOCAB_DIR = ROOT / "vocabularies"
VOCAB_SCHEMA = ROOT / "schemas" / "vocabulary.schema.json"
PINS_DIR = ROOT / "schemas" / "pins"
FIXTURES = ROOT / "fixtures"
VOCAB_SUFFIX = ".vocab.toml"
CONTRACT_PATTERN = re.compile(r"^\d+\.\d+$")


def _load_json_schema() -> dict:
    return json.loads(VOCAB_SCHEMA.read_text(encoding="utf-8"))


def _validate_vocab_file(path: Path, schema: dict) -> list[str]:
    errors: list[str] = []
    stem = path.name[: -len(VOCAB_SUFFIX)]
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        return [f"{path}: TOML parse error: {exc}"]

    if "version" in doc:
        errors.append(
            f"{path}: top-level 'version' is not permitted; use per-key version on [[keys]] entries"
        )

    field = doc.get("field")
    if field != stem:
        errors.append(f"{path}: field '{field}' does not match filename stem '{stem}'")

    keys = doc.get("keys") or []
    seen_names: set[str] = set()
    seen_ids: set[str] = set()
    key_mode = doc.get("key", "name")
    for index, entry in enumerate(keys):
        version = entry.get("version")
        if not version:
            errors.append(f"{path}: keys[{index}] missing required 'version'")
        elif not CONTRACT_PATTERN.match(str(version)):
            errors.append(f"{path}: keys[{index}].version invalid format: {version!r}")

        removed = entry.get("removed")
        if removed is not None and not CONTRACT_PATTERN.match(str(removed)):
            errors.append(f"{path}: keys[{index}].removed invalid format: {removed!r}")

        identity = entry.get("id") if key_mode == "id" else entry.get("name")
        if identity is None:
            errors.append(f"{path}: keys[{index}] missing identity ({key_mode})")
            continue

        bucket = seen_ids if key_mode == "id" else seen_names
        if identity in bucket:
            errors.append(f"{path}: duplicate key {key_mode}={identity!r}")
        bucket.add(identity)

    try:
        import jsonschema

        jsonschema.validate(doc, schema)
    except ImportError:
        errors.append("jsonschema package required: pip install jsonschema")
    except jsonschema.ValidationError as exc:
        errors.append(f"{path}: schema validation failed: {exc.message}")

    return errors


def _validate_pin_files() -> list[str]:
    errors: list[str] = []
    required = ["threat.toml", "objective.toml", "rule.toml"]
    for name in required:
        path = PINS_DIR / name
        if not path.is_file():
            errors.append(f"missing required pin file: {path.relative_to(ROOT)}")
            continue
        try:
            doc = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            errors.append(f"{path}: TOML parse error: {exc}")
            continue

        if not doc:
            errors.append(f"{path}: pin file is empty")
            continue

        for section, pins in doc.items():
            if not isinstance(pins, dict):
                errors.append(f"{path}: section {section!r} must be a table of field pins")
                continue
            if section == "extends":
                continue
            for field_path, contract in pins.items():
                if field_path == "extends":
                    continue
                if not isinstance(contract, str) or "::" not in contract:
                    errors.append(
                        f"{path}: [{section}] {field_path!r} must be a versioned contract (field::M.m)"
                    )
                    continue
                revision = contract.split("::", 1)[1]
                if not CONTRACT_PATTERN.match(revision):
                    errors.append(
                        f"{path}: [{section}] {field_path!r} contract revision invalid: {contract!r}"
                    )

    return errors


def _check_fixtures() -> list[str]:
    errors: list[str] = []
    required = [
        FIXTURES / "valid" / "rule-1.0.yaml",
        FIXTURES / "valid" / "threat-1.0.yaml",
        FIXTURES / "valid" / "objective-1.0.yaml",
        FIXTURES / "invalid" / "rule-missing-metadata.yaml",
        FIXTURES / "cross-object" / "rule-references-objective.yaml",
    ]
    for path in required:
        if not path.is_file():
            errors.append(f"missing required fixture: {path.relative_to(ROOT)}")
    return errors


def main() -> int:
    errors: list[str] = []

    if not VOCAB_SCHEMA.is_file():
        errors.append(f"missing {VOCAB_SCHEMA.relative_to(ROOT)}")
        print("\n".join(errors), file=sys.stderr)
        return 1

    schema = _load_json_schema()
    vocab_files = sorted(VOCAB_DIR.glob(f"*{VOCAB_SUFFIX}"))
    if not vocab_files:
        errors.append(f"no vocabulary files in {VOCAB_DIR.relative_to(ROOT)}/")

    for path in vocab_files:
        errors.extend(_validate_vocab_file(path, schema))

    errors.extend(_validate_pin_files())
    errors.extend(_check_fixtures())

    if errors:
        print("validation failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    pin_count = len(list(PINS_DIR.glob("*.toml"))) if PINS_DIR.is_dir() else 0
    print(
        f"validation OK ({len(vocab_files)} vocabularies, {pin_count} pin files, fixtures present)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
