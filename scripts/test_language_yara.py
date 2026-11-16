#!/usr/bin/env python3
"""Consistency tests for specs/languages/yara-1.0.md, harfanglab-1.0 and bitdefender-1.0, their fixtures, and the specs that list them."""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any

from object_fixtures import (
    EXPECTED_INVALID_CODES,
    load_vocabularies,
    validate_fixture_file,
    validate_harfanglab_block,
    validate_yara_signature,
)
from object_fixtures import YARA_MODULES

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specs" / "languages" / "yara-1.0.md"
HARFANGLAB = ROOT / "specs" / "platforms" / "harfanglab-1.0.md"
BITDEFENDER = ROOT / "specs" / "platforms" / "bitdefender-1.0.md"
FIXTURES = ROOT / "fixtures"
SECTIONS = ["Summary", "Requirements", "Definition", "Relationships", "Defaults & overrides", "Examples", "History"]

ERRORS = [
    "yara_parse_error",
    "yara_include",
    "yara_signature_alias",
    "yara_empty_signature",
    "yara_duplicate_rule",
    "yara_duplicate_string",
    "yara_duplicate_tag",
    "yara_undefined_string",
    "yara_unreferenced_string",
    "yara_undefined_identifier",
    "yara_rule_identifier_conflict",
    "yara_unknown_module",
    "yara_module_not_imported",
    "yara_unknown_module_member",
    "yara_type",
    "yara_regexp",
    "yara_hex_string",
    "yara_string_modifier",
    "yara_number_out_of_range",
    "yara_x_only_syntax",
]
WARNINGS = [
    "yara_slow_pattern",
    "yara_entrypoint_deprecated",
    "yara_suspicious_expression",
    "yara_module_unconfirmed",
    "yara_meta_missing",
]
# YARA-X 1.23.0's default modules, less `vt` (RFC 0020).
MODULES = ["console", "crx", "cuckoo", "dex", "dotnet", "elf", "hash", "lnk", "macho", "math", "pe", "string", "time", "zip"]
REFUSED_MODULES = ["magic", "vt", "msi", "olecf", "vba"]
RETIRED = ["yara_x_incompatible"]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _codes(errors: list[Any]) -> set[str]:
    return {error.code for error in errors}


def _table_codes(text: str, start: str, end: str) -> list[str]:
    section = text[text.index(start) : text.index(end)]
    return re.findall(r"^\| `([a-z_]+)` \|", section, flags=re.MULTILINE)


RULE = 'rule A {\n  meta:\n    context = "file"\n  strings:\n    $a = "x"\n  condition:\n    $a\n}\n'


class SpecShapeTests(unittest.TestCase):
    def test_frontmatter_and_sections(self) -> None:
        text = _read(SPEC)
        self.assertIn("spec: language-yara", text)
        self.assertIn('version: "1.6"', text)
        self.assertIn("status: normative", text)
        self.assertEqual(re.findall(r"^## (.+)$", text, flags=re.MULTILINE), SECTIONS)

    def test_yara_x_is_the_reference_language(self) -> None:
        text = _read(SPEC)
        language = text.split("### Language", 1)[1].split("### Modules", 1)[0]
        self.assertIn("**YARA as YARA-X 1.x compiles it**", language)
        self.assertIn("Identifiers have no length limit.", language)
        self.assertNotIn("libyara 4.5 compiles it", text)
        self.assertNotIn("libyara4", text)
        for heading in ("#### Stricter than libyara", "#### YARA-X-only syntax", "#### Matching differences"):
            self.assertIn(heading, language)

    def test_retired_codes(self) -> None:
        text = _read(SPEC)
        self.assertEqual(_table_codes(text, "#### Retired codes", "### Platform profiles"), RETIRED)
        self.assertIn("MUST NOT report the retired code `yara_x_incompatible`", text)

    def test_diagnostics_tables(self) -> None:
        text = _read(SPEC)
        self.assertEqual(_table_codes(text, "#### Errors", "#### Warnings"), ERRORS)
        self.assertEqual(_table_codes(text, "#### Warnings", "#### Retired codes"), WARNINGS)

    def test_validation_lists_the_warnings(self) -> None:
        text = _read(ROOT / "specs" / "validation.md")
        section = text.split("### Language diagnostics", 1)[1].split("###", 1)[0]
        for code in WARNINGS:
            self.assertIn(f"`{code}`", section)
        self.assertIn("`yara_x_incompatible` is retired and never reported", section)
        self.assertIn("| `harfanglab_yara_context` | warning |", text)

    def test_modules_and_dialect(self) -> None:
        text = _read(SPEC)
        modules = text.split("### Modules", 1)[1].split("###", 1)[0]
        for module in MODULES + REFUSED_MODULES:
            self.assertIn(f"`{module}`", modules)
        self.assertIn("`console`, `crx`, `cuckoo`, `dex`, `dotnet`, `elf`, `hash`, `lnk`, `macho`, `math`, `pe`, `string`, `time`, and `zip`", modules)
        self.assertEqual(sorted(YARA_MODULES), MODULES)
        self.assertIn("| `yara_x_syntax` | `refused` | `refused` |", text)
        self.assertIn("| Confirmed modules | `pe`, `elf`, `math`, `hash`, `time` | `pe`, `elf`, `math`, `hash`, `time` |", text)


class HarfangLabSpecTests(unittest.TestCase):
    def test_version_and_constraints(self) -> None:
        text = _read(HARFANGLAB)
        self.assertIn('version: "1.5"', text)
        profile = text.split("### YARA profile", 1)[1].split("###", 1)[0]
        self.assertIn("`yara_x_syntax: refused`", profile)
        self.assertNotIn("libyara4", profile)
        self.assertEqual(
            _table_codes(text, "### Constraints", "### YARA profile"),
            [
                "harfanglab_rule_kind",
                "harfanglab_yara_form",
                "harfanglab_yara_section_header",
                "harfanglab_yara_import",
                "harfanglab_yara_rule_name",
            ],
        )
        self.assertNotIn("- When both are present, deploy MUST publish `sigma`", text)
        self.assertIn("| `signature` | string | yes |", text)

    def test_platform_index(self) -> None:
        text = _read(ROOT / "specs" / "platforms" / "index.md")
        self.assertIn("| `harfanglab` | HarfangLab | yes* | **no**§ | Sigma or YARA |", text)
        self.assertIn("At most one of `sigma` and `yara` (`harfanglab_rule_kind`)", text)

    def test_listings(self) -> None:
        self.assertIn("[specs/languages/yara-1.0.md](specs/languages/yara-1.0.md)", _read(ROOT / "SPECS.md"))
        self.assertIn("specs/languages/yara-1.0.md", _read(ROOT / "llms.txt"))
        self.assertIn("[0015](0015-yara-language.md)", _read(ROOT / "rfcs" / "README.md"))
        self.assertIn("## language-yara 1.0", _read(ROOT / "CHANGELOG.md"))
        self.assertIn("## language-yara 1.6", _read(ROOT / "CHANGELOG.md"))
        self.assertIn("[0020](0020-yara-x-reference-language.md)", _read(ROOT / "rfcs" / "README.md"))
        self.assertIn("| YARA language | 1.6 |", _read(ROOT / "SPECS.md"))

    def test_bitdefender_profile(self) -> None:
        text = _read(BITDEFENDER)
        self.assertIn('version: "1.5"', text)
        profile = text.split("### YARA profile", 1)[1].split("###", 1)[0]
        self.assertIn("`yara_x_syntax: refused`", profile)
        self.assertNotIn("libyara4", profile)


class CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vocabs = load_vocabularies(ROOT / "vocabularies")

    def test_valid_fixtures_pass(self) -> None:
        for path in (
            FIXTURES / "platforms" / "harfanglab-yara-signature.yaml",
            FIXTURES / "platforms" / "harfanglab-yara.yaml",
            FIXTURES / "platforms" / "harfanglab-sigma.yaml",
        ):
            with self.subTest(path=path.name):
                self.assertEqual(validate_fixture_file(path, self.vocabs), [])

    def test_invalid_fixtures_report_their_code(self) -> None:
        for name in (
            "rule-harfanglab-sigma-and-yara.yaml",
            "rule-harfanglab-yara-both-forms.yaml",
            "rule-harfanglab-yara-include.yaml",
            "rule-yara-signature-alias.yaml",
            "rule-yara-unknown-module.yaml",
        ):
            with self.subTest(name=name):
                codes = _codes(validate_fixture_file(FIXTURES / "invalid" / name, self.vocabs))
                self.assertIn(EXPECTED_INVALID_CODES[name], codes)

    def test_signature_checks(self) -> None:
        self.assertEqual(validate_yara_signature(RULE, "s"), [])
        self.assertEqual(_codes(validate_yara_signature("private rule A { condition: true }\n", "s")), {"yara_empty_signature"})
        self.assertEqual(_codes(validate_yara_signature(RULE + RULE, "s")), {"yara_duplicate_rule"})
        self.assertEqual(_codes(validate_yara_signature('include "x.yar"\n' + RULE, "s")), {"yara_include"})
        self.assertEqual(_codes(validate_yara_signature("   ", "s")), {"yara_empty_signature"})

    def test_modules(self) -> None:
        for module in MODULES:
            with self.subTest(module=module):
                self.assertEqual(validate_yara_signature(f'import "{module}"\n' + RULE, "s"), [])
        for module in REFUSED_MODULES:
            with self.subTest(module=module):
                codes = _codes(validate_yara_signature(f'import "{module}"\n' + RULE, "s"))
                self.assertEqual(codes, {"yara_unknown_module"})

    def test_decomposed_section_header(self) -> None:
        block = {"yara": {"meta": {"context": ["file"], "os": "Windows"}, "strings": "strings:\n$a = \"x\"", "condition": "$a"}}
        self.assertEqual(_codes(validate_harfanglab_block(block)), {"harfanglab_yara_section_header"})
        block["yara"]["strings"] = '$a = "x"'
        self.assertEqual(validate_harfanglab_block(block), [])


if __name__ == "__main__":
    unittest.main()
