#!/usr/bin/env python3
"""Consistency tests for RFC 0010 (deployment external ids) and the specs it accepted."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RFC = ROOT / "rfcs" / "0010-deployment-external-ids.md"
STATE = ROOT / "specs" / "deployment-state.md"
PLATFORMS = ROOT / "specs" / "platforms"

CATALOGUE = {
    "external_id_in_rule": "error",
    "external_id_missing": "warning",
    "external_id_shape": "error",
    "external_id_conflict": "error",
    "external_id_unused": "warning",
    "deployment_state_ignored": "error before a create",
    "deployment_state_unpersisted": "error",
    "deployment_state_write_failed": "error",
    "deployment_state_uuid_mismatch": "error",
    "deployment_state_platform": "error",
    "deployment_state_shape": "error",
    "deployment_state_conflict": "CI replay diagnostic",
    "yaml_parse": "error",
    "invalid_uuid": "error",
}

BUMPED = {
    "specs/platforms/index.md": "1.1",
    "specs/platforms/defender-for-endpoint-1.0.md": "1.1",
    "specs/platforms/sentinel-one-1.0.md": "1.1",
    "specs/platforms/crowdstrike-1.0.md": "1.1",
    "specs/platforms/harfanglab-1.0.md": "1.1",
    "specs/platforms/carbon-black-cloud-1.0.md": "1.1",
    "specs/workspace.md": "1.2",
    "specs/deployment.md": "1.1",
    "specs/validation.md": "1.1",
    "specs/sharing.md": "1.1",
    "specs/deployment-state.md": "1.1",
}

SECTIONS = ["Summary", "Requirements", "Definition", "Relationships", "Defaults & overrides", "Examples", "History"]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _frontmatter(text: str) -> dict[str, str]:
    block = text.split("---", 2)[1]
    pairs = (line.split(":", 1) for line in block.strip().splitlines())
    return {key.strip(): value.strip().strip('"') for key, value in pairs}


def _section(text: str, heading: str, level: str = "###") -> str:
    start = text.index(f"\n{level} {heading}\n")
    rest = text[start + 1 :]
    match = re.search(rf"\n#{{1,{len(level)}}} ", rest)
    return rest[: match.start()] if match else rest


def _slug(heading: str) -> str:
    text = heading.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(text: str) -> set[str]:
    return {_slug(m.group(1)) for m in re.finditer(r"^#{1,6} (.+)$", text, flags=re.MULTILINE)}


class Rfc0010HeaderTests(unittest.TestCase):
    def test_accepted_header(self) -> None:
        text = _read(RFC)
        self.assertTrue(text.startswith("# RFC 0010: Deployment external ids\n"))
        for line in (
            "- **RFC:** 0010",
            "- **Status:** accepted",
            "- **Revised:** 2026-10-16",
            "- **Accepted:** 2026-10-16",
            "- **Issue:** [#30](https://github.com/opentidehq/specifications/issues/30)",
            "- **PR:** [#32](https://github.com/opentidehq/specifications/pull/32)",
            "- **Implementation issue:** [opentide#396](https://github.com/opentidehq/opentide/issues/396)",
            "- **Implementation PR:** [opentide#555](https://github.com/opentidehq/opentide/pull/555)",
        ):
            self.assertIn(line, text)
        self.assertNotIn("Numbering note", text)
        self.assertNotIn("RFC 0008", text)
        self.assertNotIn("Leaning", text)

    def test_questions_are_decisions(self) -> None:
        section = _section(_read(RFC), "Unresolved questions", "##")
        self.assertIn("None. The questions the draft left open are decided", section)
        self.assertIn("generated production job commits every shard change", section)
        self.assertIn("Orphan shards are retained", section)
        self.assertIn("There are no aliases", section)

    def test_contract_is_in_the_detailed_design(self) -> None:
        text = _read(RFC)
        for needle in (
            "deployment_state_unpersisted",
            "--persist-state-externally",
            "`external_id_missing` | **warning**",
            "cancel-in-progress: false",
            "resource_group: opentide-production",
            "${{ always() && steps.deploy.outcome != 'skipped' }}",
            "and(always(), eq(variables['OPENTIDE_DEPLOY_STARTED'], 'true'))",
            "refs/opentide/deployment-state/<commit>",
            "git diff -z --name-only",
            "opentide deploy replay-state",
            "`external_id_recorded`",
            "core.excludesFile",
            "opentide#554",
        ):
            self.assertIn(needle, text, needle)

    def test_index_rows(self) -> None:
        readme = _read(ROOT / "rfcs" / "README.md")
        self.assertIn("| [0010](0010-deployment-external-ids.md) | Deployment external ids | accepted |", readme)
        self.assertNotIn("0008-deployment-external-ids", readme)
        self.assertFalse((ROOT / "rfcs" / "0008-deployment-external-ids.md").exists())
        llms = _read(ROOT / "llms.txt")
        for entry in (
            "- specs/deployment-state.md (schema_id: deployment.state::1.0)",
            "- schemas/deployment.state.1.0.schema.json",
            "- fixtures/deployment/",
            "- rfcs/0010-deployment-external-ids.md",
        ):
            self.assertIn(entry, llms)
        self.assertNotIn("0008-deployment-external-ids", llms)


class DeploymentStateSpecTests(unittest.TestCase):
    def test_frontmatter_and_section_order(self) -> None:
        text = _read(STATE)
        meta = _frontmatter(text)
        self.assertEqual(meta["spec"], "deployment-state")
        self.assertEqual(meta["schema_id"], "deployment.state::1.0")
        self.assertEqual(meta["status"], "normative")
        found = re.findall(r"^## (.+)$", text, flags=re.MULTILINE)
        self.assertEqual(found, SECTIONS)

    def test_catalogue_is_exactly_the_contract(self) -> None:
        section = _section(_read(STATE), "Diagnostics")
        rows = re.findall(r"^\| `([a-z_]+)` \| ([^|]+) \|", section, flags=re.MULTILINE)
        self.assertEqual([code for code, _ in rows], list(CATALOGUE))
        for code, level in rows:
            self.assertTrue(level.strip().startswith(CATALOGUE[code]), (code, level))

    def test_decision_table(self) -> None:
        section = _section(_read(STATE), "Deploy decisions")
        self.assertIn("| `external_id_missing` | **warning** |", section)
        self.assertIn("| `deployment_state_unpersisted` | error |", section)
        order = [section.index(code) for code in (
            "external_id_in_rule", "external_id_missing", "deployment_state_ignored` | error",
            "deployment_state_unpersisted", "deployment_state_write_failed",
        )]
        self.assertEqual(order, sorted(order))

    def test_ci_requirements_one_to_seven(self) -> None:
        section = _section(_read(STATE), "Continuous integration")
        numbers = re.findall(r"^(\d)\. \*\*", section, flags=re.MULTILINE)
        self.assertEqual(numbers, [str(n) for n in range(1, 8)])

    def test_elastic_never_stores_ids(self) -> None:
        for path in (STATE, PLATFORMS / "index.md"):
            text = _read(path)
            self.assertRegex(text, r"Elastic never stores (an )?external id")
            self.assertIn("metadata.uuid", text)


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


class SpecVersionTests(unittest.TestCase):
    def test_versions_bumped_with_history(self) -> None:
        """Each spec RFC 0010 touched is at least at that version, with its history.

        Later changes may bump a spec further, so the current version is only
        required to be no older than the RFC 0010 one.
        """
        specs = _read(ROOT / "SPECS.md")
        changelog = _read(ROOT / "CHANGELOG.md")
        for rel, version in BUMPED.items():
            text = _read(ROOT / rel)
            meta = _frontmatter(text)
            current = meta["version"]
            self.assertGreaterEqual(_version_key(current), _version_key(version), rel)
            self.assertIn(f"| {version} | 2026-10-16 |", text, rel)
            self.assertIn(f"## {meta['spec']} {version}", changelog, rel)
            self.assertRegex(specs, rf"\| {re.escape(current)} \| [^|]+ \| normative \| \[{re.escape(rel)}\]")

    def test_platform_schema_ids_unchanged(self) -> None:
        for path in sorted(PLATFORMS.glob("*-1.0.md")):
            meta = _frontmatter(_read(path))
            self.assertTrue(meta["schema_id"].endswith("::1.0"), path.name)
            self.assertNotRegex(_read(path), r"^\| `rule_id(_bundle)?` \|", path.name)

    def test_no_loader_alias_left(self) -> None:
        text = _read(PLATFORMS / "index.md")
        self.assertNotIn("Loader alias", text)
        self.assertNotIn("folds every `rule_id::<tenant>`", text)
        self.assertIn("No loader folds them into a field", text)


class LinkTests(unittest.TestCase):
    """Links this change added resolve, including their anchors."""

    WHOLE = [RFC, STATE]
    TOUCHED = [ROOT / "SPECS.md", ROOT / "CHANGELOG.md", *(ROOT / rel for rel in BUMPED)]
    NEW_TARGETS = ("deployment-state", "0010-deployment-external-ids", "external-rule-ids", "fixtures/deployment")

    def _problems(self, path: Path, only_new: bool) -> list[str]:
        problems: list[str] = []
        for target in re.findall(r"\]\(([^)\s]+)\)", _read(path)):
            if re.match(r"^[a-z]+:", target):
                continue
            if only_new and not any(marker in target for marker in self.NEW_TARGETS):
                continue
            file_part, _, anchor = target.partition("#")
            dest = (path.parent / file_part).resolve() if file_part else path
            if not dest.exists():
                problems.append(f"{path.relative_to(ROOT)}: {target}")
            elif anchor and dest.suffix == ".md" and anchor not in _anchors(_read(dest)):
                problems.append(f"{path.relative_to(ROOT)}: {target} (anchor)")
        return problems

    def test_links_resolve(self) -> None:
        problems = [p for path in self.WHOLE for p in self._problems(path, only_new=False)]
        problems += [p for path in self.TOUCHED for p in self._problems(path, only_new=True)]
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
