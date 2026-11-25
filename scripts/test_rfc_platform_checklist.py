"""Platform RFCs meet the bar of .agents/skills/platform-rfc/SKILL.md.

Every RFC whose header carries `- **Type:** platform` must hold the sections and artefacts the
skill's checklist lists: the complete and minimal YAML blocks, the field table, every validation
code, the vendor request, tenant setup, the deploy lifecycle, the upgrade path, and a test plan.
A thin platform RFC (decisions and links only) fails here instead of in review.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RFCS = ROOT / "rfcs"
SKILL = ROOT / ".agents" / "skills" / "platform-rfc" / "SKILL.md"
MARKER = "- **Type:** platform"

TOP_SECTIONS = [
    "Summary",
    "Motivation",
    "Research",
    "Detailed design",
    "Drawbacks",
    "Alternatives",
    "Unresolved questions",
    "References",
]
# Words a `###` or `####` heading must contain, numbering ignored ("### 2. Shape" → "shape").
DESIGN_HEADINGS = [
    "affected specs",
    "complete block",
    "minimal block",
    "block fields",
    "validation",
    "derived fields",
    "request",
    "tenant setup",
    "deploy lifecycle",
    "query validation",
    "fixtures",
    "upgrade",
]
HEADER_LINES = ["- **Status:**", "- **Issue:**", "- **Implementation:**"]
STATUSES = ["PREVIEW", "RELEASE", "UNIVERSAL", "DISABLEMENT", "DELETION", "INERT"]


def platform_rfcs() -> list[Path]:
    rfcs = RFCS.glob("[0-9][0-9][0-9][0-9]-*.md")
    return sorted(p for p in rfcs if p.name != "0000-template.md" and re.search(r"^- \*\*Type:\*\* platform$", p.read_text(encoding="utf-8"), flags=re.MULTILINE))


def headings(text: str, levels: str) -> list[str]:
    found = re.findall(rf"^(?:{levels}) (.+)$", text, flags=re.MULTILINE)
    return [re.sub(r"^\d+(\.\d+)*\.?\s+", "", h).strip().lower() for h in found]


def section(text: str, words: str) -> str:
    """The body of the first `###`/`####` heading containing *words*, up to the next heading of that level or higher."""
    for match in re.finditer(r"^(#{3,4}) (.+)$", text, flags=re.MULTILINE):
        if words in match.group(2).lower():
            rest = text[match.end():]
            stop = re.search(rf"^#{{1,{len(match.group(1))}}} ", rest, flags=re.MULTILINE)
            return rest[: stop.start()] if stop else rest
    return ""


def code_blocks(text: str, lang: str) -> list[str]:
    return re.findall(rf"```{lang}\n(.*?)```", text, flags=re.S)


def problems(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    found: list[str] = []
    for line in HEADER_LINES:
        if line not in text:
            found.append(f"header line {line!r}")
    top = headings(text, "##")
    for name in TOP_SECTIONS:
        if name.lower() not in top:
            found.append(f"## {name}")
    if not any("test plan" in h for h in headings(text, "##|###|####")):
        found.append("a heading containing 'test plan'")
    sub = headings(text, "###|####")
    for words in DESIGN_HEADINGS:
        if not any(words in h for h in sub):
            found.append(f"a ### or #### heading containing {words!r}")
    complete = section(text, "complete block")
    if not any(b.startswith("configurations:\n") for b in code_blocks(complete, "yaml")):
        found.append("a `configurations:` YAML block under the complete-block heading")
    minimal = section(text, "minimal block")
    if not any(b.startswith("configurations:\n") for b in code_blocks(minimal, "yaml")):
        found.append("a `configurations:` YAML block under the minimal-block heading")
    fields = section(text, "block fields")
    if not re.search(r"^\|[^\n]*Type[^\n]*Required[^\n]*Default[^\n]*\|$", fields, flags=re.MULTILINE):
        found.append("a field table (Type, Required, Default columns) under the block-fields heading")
    validation = section(text, "validation")
    if not re.search(r"^\| Code \|", validation, flags=re.MULTILINE):
        found.append("a `| Code |` table under the validation heading")
    request = section(text, "request")
    if not (code_blocks(request, "json") or code_blocks(text, "json")):
        found.append("the vendor request body as a ```json block")
    if not code_blocks(section(text, "tenant setup"), "toml"):
        found.append("a ```toml tenant setup example under the tenant-setup heading")
    lifecycle = section(text, "deploy lifecycle")
    for status in STATUSES:
        if status not in lifecycle:
            found.append(f"status {status} in the deploy lifecycle")
    if "--json" not in lifecycle or "dry run" not in lifecycle.lower():
        found.append("the plan, dry run, and --json rows in the deploy lifecycle")
    return found


class PlatformRfcChecklistTests(unittest.TestCase):
    def test_platform_rfcs_meet_the_checklist(self) -> None:
        rfcs = platform_rfcs()
        self.assertTrue(rfcs, f"no RFC carries {MARKER!r}")
        for path in rfcs:
            with self.subTest(rfc=path.name):
                self.assertEqual(problems(path), [])

    def test_guidance_points_at_the_skill(self) -> None:
        self.assertTrue(SKILL.exists())
        for path in (ROOT / "AGENTS.md", RFCS / "0000-template.md", RFCS / "README.md", ROOT / ".agents" / "skills" / "publish-rfc" / "SKILL.md"):
            self.assertIn("platform-rfc", path.read_text(encoding="utf-8"), path)

    def test_skill_lists_what_the_test_checks(self) -> None:
        skill = SKILL.read_text(encoding="utf-8").lower()
        for words in DESIGN_HEADINGS:
            self.assertIn(words, skill, words)
        self.assertIn("test plan", skill)

    def test_a_thin_rfc_fails(self) -> None:
        # The template is not a platform RFC; checked as one, it lacks the artefacts.
        with tempfile.TemporaryDirectory() as directory:
            thin = Path(directory) / "9999-thin.md"
            thin.write_text((RFCS / "0000-template.md").read_text(encoding="utf-8"), encoding="utf-8")
            found = problems(thin)
        self.assertIn("a ### or #### heading containing 'complete block'", found)
        self.assertIn("## Research", found)


if __name__ == "__main__":
    unittest.main()
