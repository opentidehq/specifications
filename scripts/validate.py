#!/usr/bin/env python3
"""Validate specifications repo: vocabulary TOML files and fixture layout."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VOCAB_DIR = ROOT / "vocabularies"
VOCAB_SCHEMA = ROOT / "schemas" / "vocabulary.schema.json"
FIXTURES = ROOT / "fixtures"
VOCAB_SUFFIX = ".vocab.toml"


def _load_json_schema() -> dict:
    return json.loads(VOCAB_SCHEMA.read_text(encoding="utf-8"))


def _validate_vocab_file(path: Path, schema: dict) -> list[str]:
    errors: list[str] = []
    stem = path.name[: -len(VOCAB_SUFFIX)]
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        return [f"{path}: TOML parse error: {exc}"]

    field = doc.get("field")
    if field != stem:
        errors.append(f"{path}: field '{field}' does not match filename stem '{stem}'")

    try:
        import jsonschema

        jsonschema.validate(doc, schema)
    except ImportError:
        errors.append("jsonschema package required: pip install jsonschema")
    except jsonschema.ValidationError as exc:
        errors.append(f"{path}: schema validation failed: {exc.message}")

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

    errors.extend(_check_fixtures())

    if errors:
        print("validation failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"validation OK ({len(vocab_files)} vocabularies, fixtures present)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
