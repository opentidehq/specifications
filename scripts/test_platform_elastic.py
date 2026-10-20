#!/usr/bin/env python3
"""Consistency tests for specs/platforms/elastic-1.0.md and the specs that list Elastic.

The RFC 0007 reference reading (`test_rfc_0007`) is reused, so the normative
spec and the accepted RFC cannot drift apart silently. Where the spec amends the
RFC (compound shorthand durations), the amendment is tested here on its own.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from typing import Any

import yaml

import test_rfc_0007 as rfc
from object_fixtures import validate_elastic_block

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specs" / "platforms" / "elastic-1.0.md"
INDEX = ROOT / "specs" / "platforms" / "index.md"
SENTINEL = ROOT / "specs" / "platforms" / "sentinel-1.0.md"
VALIDATION = ROOT / "specs" / "validation.md"
SECTIONS = ["Summary", "Requirements", "Definition", "Relationships", "Defaults & overrides", "Examples", "History"]

UNIT_SECONDS = {"d": 86400, "h": 3600, "m": 60, "s": 1}
_SHORTHAND = re.compile(r"(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?")
_ISO = re.compile(r"P(?:(\d+)D)?(?:T(?=\d)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _frontmatter(text: str) -> dict[str, str]:
    block = text.split("---", 2)[1]
    pairs = (line.split(":", 1) for line in block.strip().splitlines())
    return {key.strip(): value.strip().strip('"') for key, value in pairs}


def _section(text: str, heading: str) -> str:
    """The section under `heading`, up to the next heading of the same or a higher level.

    Lines inside code fences are not headings: a YAML comment reads `# ...`.
    """
    level = len(heading.split(" ", 1)[0])
    lines = text[text.index(f"\n{heading}\n") + 1 :].splitlines(keepends=True)
    out, fenced = [lines[0]], False
    for line in lines[1:]:
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and (match := re.match(r"(#{1,6}) ", line)) and len(match.group(1)) <= level:
            break
        out.append(line)
    return "".join(out)


def _tables(text: str) -> list[list[dict[str, str]]]:
    tables = []
    for block in re.findall(r"((?:^\|.*\n)+)", text, flags=re.MULTILINE):
        lines = block.strip().splitlines()
        if len(lines) < 2 or not set(lines[1]) <= set("|-: "):
            continue

        def cells(line: str) -> list[str]:
            return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]

        header = [c.replace("`", "") for c in cells(lines[0])]
        tables.append([dict(zip(header, cells(line))) for line in lines[2:]])
    return tables


def _table(text: str, first_header: str) -> list[dict[str, str]]:
    for table in _tables(text):
        if table and next(iter(table[0])) == first_header:
            return table
    raise AssertionError(f"no table headed {first_header!r}")


def _rows(text: str, first_header: str) -> list[dict[str, str]]:
    """Every row of every table whose first column is `first_header`."""
    return [row for table in _tables(text) if table and next(iter(table[0])) == first_header for row in table]


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in _frontmatter(text)["version"].split("."))


def _fences(text: str, lang: str) -> list[str]:
    return re.findall(rf"```{lang}\n(.*?)\n```", text, flags=re.DOTALL)


def duration_seconds(value: str, *, allow_zero: bool = False) -> int:
    """The duration grammar of elastic-1.0.md: compound shorthand or ISO 8601."""
    if value and (short := _SHORTHAND.fullmatch(value)):
        parts = short.groups()
    elif value not in ("P", "PT") and (iso := _ISO.fullmatch(value)):
        parts = iso.groups()
    else:
        raise ValueError(value)
    days, hours, minutes, secs = (int(part or 0) for part in parts)
    total = ((days * 24 + hours) * 60 + minutes) * 60 + secs
    if total == 0 and not allow_zero:
        raise ValueError(value)
    return total


def single_unit(value: str, units: str = "dhms") -> tuple[int, str]:
    total = duration_seconds(value)
    unit = next(u for u in units if total % UNIT_SECONDS[u] == 0)
    return total // UNIT_SECONDS[unit], unit


class ElasticSpecShapeTests(unittest.TestCase):
    def test_frontmatter_and_sections(self) -> None:
        text = _read(SPEC)
        meta = _frontmatter(text)
        self.assertEqual(meta["spec"], "platform-elastic")
        self.assertEqual(meta["version"], "1.0")
        self.assertEqual(meta["schema_id"], "platform::elastic::1.0")
        self.assertEqual(meta["status"], "normative")
        self.assertEqual(re.findall(r"^## (.+)$", text, flags=re.MULTILINE), SECTIONS)

    def test_identity_is_metadata_uuid_and_never_stored(self) -> None:
        text = _read(SPEC)
        self.assertIn("Kibana `rule_id` is the rule's `metadata.uuid`", text)
        self.assertRegex(text, r"Elastic never stores (an )?external id")

    def test_links_resolve(self) -> None:
        problems = []
        rule_specs = [ROOT / "specs" / "objects" / name for name in ("rule-1.0.md", "rule-1.1.md")]
        for path in (SPEC, SENTINEL, INDEX, VALIDATION, *rule_specs):
            text = _read(path)
            for target in re.findall(r"\]\(([^)\s]+)\)", text):
                if re.match(r"^[a-z]+:", target):
                    continue
                file_part, _, anchor = target.partition("#")
                dest = (path.parent / file_part).resolve() if file_part else path
                if not dest.exists():
                    problems.append(f"{path.name}: {target}")
                elif anchor and dest.suffix == ".md":
                    slugs = {
                        re.sub(r"[^\w\- ]", "", m.group(1).strip().lower()).replace(" ", "-")
                        for m in re.finditer(r"^#{1,6} (.+)$", _read(dest), flags=re.MULTILINE)
                    }
                    if anchor not in slugs:
                        problems.append(f"{path.name}: {target} (anchor)")
        self.assertEqual(problems, [])


class ElasticSpecMatchesRfcTests(unittest.TestCase):
    """Tables the spec carries over from RFC 0007 stay identical to it."""

    def test_constraint_codes(self) -> None:
        spec_codes = {row["Code"].strip("`") for row in _table(_read(SPEC), "Code")}
        rfc_codes = {row["Code"].strip("`") for row in rfc._table("constraints-table")}
        self.assertEqual(spec_codes, rfc_codes)

    def test_retired_flat_keys(self) -> None:
        row = next(r for r in _table(_read(SPEC), "Code") if r["Code"] == "`type_block`")
        listed = set(re.findall(r"`([a-z_]+)`", row["Constraint"].split("invalid at the block root:", 1)[1]))
        self.assertEqual(listed, set(rfc._REMOVED_FLAT))

    def test_severity_table(self) -> None:
        spec = {row["alert_severity"]: (row["severity"], int(row["risk_score"])) for row in _table(_read(SPEC), "alert_severity")}
        self.assertEqual(spec, rfc._severity_table())

    def test_tactic_table(self) -> None:
        spec = {row["Stage"]: row["Tactic id"] for row in _table(_read(SPEC), "Stage")}
        self.assertEqual(spec, rfc._tactics())

    def test_tactic_aliases(self) -> None:
        spec = {row["Legacy stage"]: row["Stage"] for row in _table(_read(SPEC), "Legacy stage")}
        self.assertEqual(spec, rfc._tactic_aliases())

    def test_preserved_fields(self) -> None:
        spec: set[str] = set()
        for row in _table(_read(SPEC), "Preserved field"):
            spec.update(rfc._ticked(row["Preserved field"]))
        self.assertEqual(spec, rfc._preserved_fields())

    def test_compiled_body_fields(self) -> None:
        spec: set[str] = set()
        for row in _table(_read(SPEC), "Detection-engine field"):
            spec.update(rfc._ticked(row["Detection-engine field"]))
        # rule_id is stated in prose (a `rule_id` table row reads as a legacy block key);
        # concurrent_searches and items_per_search are never compiled.
        self.assertEqual(spec | {"rule_id", "concurrent_searches", "items_per_search"}, rfc._mapping_fields())
        self.assertLessEqual(spec, set().union(*rfc.KIBANA_FIELDS.values()))

    def test_tenant_setup_fields(self) -> None:
        spec = {(row["tenants.setup field"], row["Required"]) for row in _table(_read(SPEC), "tenants.setup field")}
        ours = {(name.strip("`"), "yes" if req == "yes" else "no") for name, req in spec}
        theirs = {(row["tenants.setup field"].strip("`"), row["Required"]) for row in rfc._table("setup-table")}
        self.assertEqual(ours, theirs)

    def test_field_types(self) -> None:
        row = next(r for r in _rows(_read(SPEC), "Field") if r["Field"] == "`type`" and "mapping type" in r["Description"])
        self.assertEqual(set(re.findall(r"`([a-z_]+)`", row["Description"])), rfc.field_types())


class ElasticSpecExampleTests(unittest.TestCase):
    def _examples(self) -> str:
        return _section(_read(SPEC), "## Examples")

    def test_minimal_block_compiles_to_the_body_shown(self) -> None:
        blocks = _fences(self._examples(), "yaml")
        rule = {
            "name": "Rule name",
            "metadata": {
                "uuid": "00000000-0000-4000-8000-000000000000",
                "schema": "rule::1.0",
                "author": "Detection Engineering",
            },
            "description": "What this rule detects.\n",
            "techniques": [],
            "response": {"alert_severity": "Medium"},
            **yaml.safe_load(blocks[0]),
        }
        body = json.loads(_fences(self._examples(), "json")[0])
        self.assertEqual(rfc.compile_rule(rule, {}), body)
        self.assertEqual(rfc.check_block(rule["configurations"]["elastic"]), set())

    def test_type_snippets_pass_the_constraints(self) -> None:
        snippets = re.split(r"^# .*$", _fences(self._examples(), "yaml")[1], flags=re.MULTILINE)
        blocks = [yaml.safe_load(s) for s in snippets if s.strip()]
        self.assertEqual({b["type"] for b in blocks}, set(rfc._RULE_TYPES) - {"query"})
        for block in blocks:
            with self.subTest(type=block["type"]):
                self.assertEqual(rfc.check_block(block), set())
                self.assertEqual(validate_elastic_block(block), [])

    def test_invalid_block_reports_its_three_codes(self) -> None:
        block = yaml.safe_load(_fences(self._examples(), "yaml")[2])["elastic"]
        expected = {"esql_source", "language", "suppression_shape"}
        self.assertEqual(rfc.check_block(block), expected)
        self.assertEqual({e.code for e in validate_elastic_block(block)}, expected)

    def test_fixtures_are_the_rfc_examples(self) -> None:
        fixture = yaml.safe_load(_read(ROOT / "fixtures" / "valid" / "rule-elastic-1.0.yaml"))
        self.assertEqual(fixture, rfc._yaml("rule-query"))
        invalid = yaml.safe_load(_read(ROOT / "fixtures" / "invalid" / "rule-elastic-esql-index.yaml"))
        rfc_invalid = yaml.safe_load(rfc._fence("invalid")[1])["elastic"]
        self.assertEqual(invalid["configurations"]["elastic"], rfc_invalid)
        platform = yaml.safe_load(_read(ROOT / "fixtures" / "platforms" / "elastic.yaml"))
        self.assertEqual(platform["configurations"], yaml.safe_load(_fences(self._examples(), "yaml")[0])["configurations"])


class DurationTests(unittest.TestCase):
    def test_table_follows_the_conversion_rule(self) -> None:
        rows = _table(_section(_read(SPEC), "### Durations"), "Written")
        written = [row["Written"].strip("`") for row in rows]
        self.assertTrue({"1h10m", "2m30s", "1d2h"} <= set(written))
        for row in rows:
            value = row["Written"].strip("`")
            with self.subTest(duration=value):
                amount, unit = single_unit(value)
                interval, from_ = rfc._ticked(row["interval / from"])
                self.assertEqual(interval, f"{amount}{unit}")
                self.assertEqual(from_, f"now-{amount}{unit}")
                amount, unit = single_unit(value, "hms")
                self.assertEqual(row["alert_suppression.duration"], f"`{{value: {amount}, unit: {unit}}}`")
                self.assertEqual(row["history_window_start"].strip("`"), from_)

    def test_grammar(self) -> None:
        same = [("1h10m", "PT1H10M"), ("1d2h", "P1DT2H"), ("2m30s", "PT2M30S"), ("14d", "P14D"), ("90s", "PT90S")]
        for short, iso in same:
            with self.subTest(short=short):
                self.assertEqual(duration_seconds(short), duration_seconds(iso))
        self.assertEqual(duration_seconds("0m", allow_zero=True), 0)
        for bad in ("5min", "1w", "P1W", "0m", "1.5h", "PT", "P", "P1DT", "5", "", "1m1h", "1h1h", "1H", "pt1h", " 5m", "-5m"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                duration_seconds(bad)

    def test_single_unit_forms_agree_with_the_rfc(self) -> None:
        for value in ("5m", "90s", "60m", "1d", "14d", "PT1H", "P14D", "PT90S"):
            with self.subTest(duration=value):
                self.assertEqual(duration_seconds(value), rfc.duration_seconds(value))


class ListingTests(unittest.TestCase):
    def test_platforms_index(self) -> None:
        text = _read(INDEX)
        self.assertGreaterEqual(_version(text), (1, 2))
        self.assertIn("opentide ships eight detection platform integrations.", text)
        self.assertNotIn("not yet in this matrix", text)
        self.assertIn("| `elastic` | `platform::elastic::1.0` | [elastic-1.0.md](elastic-1.0.md) |", text)
        self.assertRegex(text, r"\| `elastic` \| Elastic Security \| yes\* \| yes† \| KQL, Lucene, EQL, or ES\\\|QL")
        self.assertIn("`carbon_black_cloud`, `elastic`\n", text)
        self.assertIn("| `elastic` | `metadata.uuid` is the Kibana `rule_id`", text)
        self.assertRegex(text, r"\n\| `elastic` \| `type`, `status`, and `query`")
        self.assertIn("| 1.2 | 2026-10-19 |", text)

    def test_validation(self) -> None:
        text = _read(VALIDATION)
        self.assertGreaterEqual(_version(text), (1, 3))
        self.assertIn("| `elastic` | yes, live only", text)
        self.assertIn("rule-elastic-esql-index.yaml", text)
        self.assertIn("| 1.3 | 2026-10-19 | `elastic` joins query validation", text)

    def test_rule_specs(self) -> None:
        row = "| `elastic` | ElasticConfig | `platform::elastic::1.0` | [elastic-1.0.md](../platforms/elastic-1.0.md) |"
        for name in ("rule-1.0.md", "rule-1.1.md"):
            text = _read(ROOT / "specs" / "objects" / name)
            with self.subTest(spec=name):
                self.assertIn(row, text)
                self.assertIn("| 2026-10-19 | `configurations.elastic`", text)

    def test_index_files(self) -> None:
        specs = _read(ROOT / "SPECS.md")
        changelog = _read(ROOT / "CHANGELOG.md")
        for path in (SPEC, SENTINEL, INDEX, VALIDATION):
            meta = _frontmatter(_read(path))
            rel = path.relative_to(ROOT).as_posix()
            with self.subTest(spec=rel):
                self.assertRegex(specs, rf"\| {re.escape(meta['version'])} \| [^|]+ \| normative \| \[{re.escape(rel)}\]")
                self.assertIn(f"## {meta['spec']} {meta['version']}\n", changelog)
        self.assertIn("- specs/platforms/elastic-1.0.md (schema_id: platform::elastic::1.0)", _read(ROOT / "llms.txt"))
        self.assertIn("specs/platforms/elastic-1.0", json.loads(_read(ROOT / "site" / "meta.json"))["pages"])


class SentinelDurationTests(unittest.TestCase):
    def test_durations_accept_shorthand(self) -> None:
        text = _read(SENTINEL)
        self.assertGreaterEqual(_version(text), (1, 1))
        self.assertEqual(_frontmatter(text)["schema_id"], "platform::sentinel::1.0")
        for key in ("frequency", "lookback", "grouping_lookback"):
            with self.subTest(key=key):
                row = next(line for line in text.splitlines() if line.startswith(f"| `{key}` |"))
                self.assertIn("[Duration](#durations)", row)
                self.assertNotIn("ISO 8601 duration", row)
        section = _section(text, "### Durations")
        self.assertIn("ISO 8601 is the documented form", section)
        for value in ("`1h10m`", "`1d2h`", "elastic-1.0.md#durations"):
            self.assertIn(value, section)
        self.assertIn("| 1.1 | 2026-10-19 |", text)


if __name__ == "__main__":
    unittest.main()
