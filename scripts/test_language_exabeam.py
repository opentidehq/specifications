#!/usr/bin/env python3
"""Conformance tests for specs/languages/exabeam-1.0.md.

The reference checker (exabeam_language.py) runs every conformance query, the spec's own
examples, and the published Exabeam queries quoted in RFC 0017. The tests also tie the
spec's diagnostic and highlight tables to the checker, so neither can drift from the other.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from exabeam_language import CAPTURES, ERRORS, WARNINGS, analyze

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specs" / "languages" / "exabeam-1.0.md"
RFC = ROOT / "rfcs" / "0017-exabeam-platform.md"
LANG = ROOT / "fixtures" / "languages" / "exabeam"
SECTIONS = ["Summary", "Requirements", "Definition", "Relationships", "Defaults & overrides", "Examples", "History"]
CATALOGUE_CODES = {"exabeam_unknown_field", "exabeam_string_field_number"}
# The HighlightSpec legend in opentidehq/language-server highlights/spec.toml (0.3.0).
HIGHLIGHT_LEGEND = {
    "comment", "keyword", "operator", "operator.pipe", "function", "function.builtin", "type", "variable",
    "property", "string", "number", "boolean", "constant", "punctuation", "punctuation.bracket",
    "punctuation.delimiter", "error", "tide.keyword", "tide.property", "tide.uuid", "tide.schema",
    "markdown.heading", "markdown.emphasis", "markdown.strong", "markdown.code", "markdown.link",
    "markdown.list", "markdown.quote", "macro",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _profile(path: Path) -> str:
    return path.name.split(".")[-2]


def _table_codes(text: str, heading: str, until: str) -> list[str]:
    section = text[text.index(heading) : text.index(until)]
    return re.findall(r"^\| `(exabeam_[a-z_0-9]+)` \|", section, flags=re.MULTILINE)


class SpecShapeTests(unittest.TestCase):
    def test_frontmatter_and_sections(self) -> None:
        text = _read(SPEC)
        self.assertIn("spec: language-exabeam", text)
        self.assertIn("status: draft", text)
        self.assertEqual(re.findall(r"^## (.+)$", text, flags=re.MULTILINE), SECTIONS)

    def test_diagnostic_tables_match_the_checker(self) -> None:
        text = _read(SPEC)
        errors = _table_codes(text, "#### Errors", "#### Warnings")
        warnings = _table_codes(text, "#### Warnings", "#### Reserved words")
        self.assertEqual(set(errors), ERRORS)
        self.assertEqual(set(warnings), WARNINGS)
        self.assertEqual(len(errors), len(set(errors)))
        self.assertFalse(set(errors) & set(warnings))

    def test_language_id_is_not_eql(self) -> None:
        text = _read(SPEC)
        self.assertIn("The opentide language id is **`exabeam`**, and a query file ends in **`.exabeam`**.", text)
        self.assertIn("opentide never does, because `eql` is Elastic's Event Query Language", text)

    def test_highlight_table_uses_existing_captures(self) -> None:
        text = _read(SPEC)
        section = text[text.index("### Highlighting") : text.index("### Diagnostics")]
        table_captures = set(re.findall(r"\| `([a-z.]+)` \|\n", section))
        self.assertEqual(table_captures, set(CAPTURES))
        self.assertLessEqual(set(CAPTURES), HIGHLIGHT_LEGEND)

    def test_validation_lists_the_warnings(self) -> None:
        text = _read(ROOT / "specs" / "validation.md")
        for code in WARNINGS:
            self.assertIn(f"`{code}`", text)


class ConformanceTests(unittest.TestCase):
    def test_valid_queries_are_clean(self) -> None:
        paths = sorted((LANG / "valid").glob("*.exabeam"))
        self.assertGreaterEqual(len(paths), 8)
        for path in paths:
            with self.subTest(path=path.name):
                self.assertEqual(analyze(_read(path), _profile(path)).codes, [])

    def test_each_invalid_query_reports_its_code(self) -> None:
        paths = sorted((LANG / "invalid").glob("*.exabeam"))
        for path in paths:
            code = path.name.split(".")[0]
            with self.subTest(path=path.name):
                self.assertEqual(set(analyze(_read(path), _profile(path)).codes), {code})

    def test_every_catalogue_free_code_has_a_fixture(self) -> None:
        covered = {p.name.split(".")[0] for p in (LANG / "invalid").glob("*.exabeam")}
        self.assertEqual(covered, (ERRORS | WARNINGS) - CATALOGUE_CODES)

    def test_highlight_goldens(self) -> None:
        paths = sorted((LANG / "highlight").glob("*.exabeam"))
        self.assertGreaterEqual(len(paths), 3)
        for path in paths:
            with self.subTest(path=path.name):
                text = _read(path)
                golden = json.loads(_read(path.with_suffix(".tokens.json")))
                tokens = analyze(text, _profile(path)).tokens
                self.assertEqual(
                    [{"text": text[t.start : t.end], "range": [t.start, t.end], "capture": t.capture} for t in tokens],
                    golden,
                )
                self.assertLessEqual({t["capture"] for t in golden}, set(CAPTURES))

    def test_spec_examples_parse(self) -> None:
        text = _read(SPEC)
        examples = text.split("## Examples", 1)[1]
        blocks = re.findall(r"```text\n(.*?)\n```", examples, flags=re.DOTALL)
        self.assertEqual(len(blocks), 3)
        self.assertEqual(analyze(blocks[0], "rule").codes, [])
        self.assertEqual(analyze(blocks[1], "rule").codes, [])
        self.assertEqual(analyze(blocks[2], "search").codes, [])
        self.assertEqual(analyze(blocks[2], "rule").codes, ["exabeam_advanced_in_rule"])

    def test_spec_example_table(self) -> None:
        rows = {
            'user != "SYSTEM"': ["exabeam_not_equal"],
            'subject:"app" NOT vendor:"Exabeam"': ["exabeam_implicit_operator"],
            'process_command_line: contains("-enc")': ["exabeam_unknown_function"],
            "src_ip:[fd00::/8]": ["exabeam_ipv6_range"],
            'user IN "Executives" OR src_ip IN "Admins"': ["exabeam_context_table_or", "exabeam_context_table_or"],
        }
        text = _read(SPEC)
        for query, codes in rows.items():
            with self.subTest(query=query):
                self.assertIn(f"| `{query}` |", text)
                self.assertEqual(analyze(query, "rule").codes, codes)

    def test_published_exabeam_queries_parse(self) -> None:
        """The queries RFC 0017 quotes from Exabeam's own content are clean under their profile."""
        text = _read(RFC)
        block = text.split("**Real content.**", 1)[1].split("```text\n", 1)[1].split("\n```", 1)[0]
        lines = block.splitlines()
        self.assertEqual(len(lines), 4)
        for line in lines[:3]:
            self.assertEqual(analyze(line, "rule").codes, [], line)
        self.assertEqual(analyze(lines[3], "search").codes, [])


class SemanticsTests(unittest.TestCase):
    def test_profiles(self) -> None:
        query = 'SELECT user WHERE activity_type:"app-login"'
        self.assertEqual(analyze(query, "rule").codes, ["exabeam_advanced_in_rule"])
        self.assertEqual(analyze(query, "search").codes, [])
        self.assertTrue(analyze('vendor:"a" | SELECT vendor', "search").advanced)
        self.assertFalse(analyze('vendor:"a" AND NOT b:"c"', "search").advanced)

    def test_operators_any_case_keywords_one_case(self) -> None:
        self.assertEqual(analyze('vendor:"a" and not user:"b"', "rule").codes, [])
        self.assertEqual(analyze('select user where vendor:"a"', "search").codes, [])
        self.assertEqual(analyze('SELECT user Where vendor:"a"', "search").codes, ["exabeam_keyword_case"])

    def test_regex_is_re2(self) -> None:
        for pattern, ok in (
            ("^a+b$", True),
            ("(?i)admin", True),
            ("(a)\\\\1", False),
            ("foo(?=bar)", False),
            ("a{2,", True),
            ("[a-", False),
        ):
            with self.subTest(pattern=pattern):
                codes = analyze(f'process_name:RGX("{pattern}")', "rule").codes
                self.assertEqual(codes == [], ok, codes)

    def test_ranges(self) -> None:
        cases = {
            "count:[1 TO 5]": [],
            "count:[1 TO *]": [],
            "count:[* TO *]": ["exabeam_range"],
            "count:[5 TO 1]": ["exabeam_range"],
            "count:[1 TO 5}": ["exabeam_range"],
            "src_ip:[10.0.0.9 TO 10.0.0.1]": ["exabeam_range"],
            "src_ip:[10.0.0.0/33]": ["exabeam_range"],
            "count:[1 TO 10.0.0.1]": ["exabeam_range"],
        }
        for query, codes in cases.items():
            with self.subTest(query=query):
                self.assertEqual(analyze(query, "rule").codes, codes)

    def test_time_fields_take_ranges(self) -> None:
        self.assertEqual(analyze("approxLogTime:[1730000000000 TO *]", "rule").codes, [])
        self.assertEqual(analyze('approxLogTime:"1730000000000"', "rule").codes, ["exabeam_time_exact"])

    def test_foreach_scope(self) -> None:
        ok = 'vendor:"a" | FOREACH host [ SELECT user WHERE src_host: @host ]'
        self.assertEqual(analyze(ok, "search").codes, [])
        self.assertEqual(analyze("src_host: @host", "search").codes, ["exabeam_foreach_reference"])

    def test_highlight_examples(self) -> None:
        def caps(query: str, profile: str = "rule") -> list[tuple[str, str]]:
            return [(query[t.start : t.end], t.capture) for t in analyze(query, profile).tokens]

        self.assertEqual(
            caps('src_ip:[10.0.0.0/8]'),
            [("src_ip", "property"), (":", "operator"), ("[", "punctuation.bracket"), ("10.0.0.0/8", "constant"), ("]", "punctuation.bracket")],
        )
        self.assertEqual(
            caps('user IN "Admins"."Name"'),
            [("user", "property"), ("IN", "keyword"), ('"Admins"', "type"), (".", "punctuation.delimiter"), ('"Name"', "type")],
        )
        self.assertIn(("!=", "error"), caps('user != "x"'))
        self.assertIn(("RGXi", "function.builtin"), caps('a:RGXi("x")'))
        self.assertIn(("true", "boolean"), caps("parsed:true"))
        self.assertIn(("null", "constant"), caps("dest_port:null"))


if __name__ == "__main__":
    unittest.main()
