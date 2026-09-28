#!/usr/bin/env python3
"""Consistency tests for RFC 0006 (sharing on the production merge)."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RFC = ROOT / "rfcs" / "0006-sharing-ci.md"
SHARING = ROOT / "specs" / "sharing.md"
WORKSPACE = ROOT / "specs" / "workspace.md"
RFC_0005 = ROOT / "rfcs" / "0005-sharing-system.md"


def _ci_section() -> str:
    text = SHARING.read_text(encoding="utf-8")
    start = text.index("### Continuous integration")
    end = text.index("### Workspace paths")
    return text[start:end]


class Rfc0006TextTests(unittest.TestCase):
    def test_rfc_is_accepted(self) -> None:
        text = RFC.read_text(encoding="utf-8")
        self.assertIn("**Status:** accepted", text)
        self.assertIn("opentide share push --changed", text)
        self.assertIn("deploy --plan PRODUCTION", text)
        self.assertIn(
            "**Also ship `opentide share preview --changed` on pull requests.** Rejected.",
            text,
        )
        self.assertIn("**Always emit the sharing stage.** Rejected.", text)
        self.assertIn("--sharing` / `--no-sharing`", text)
        self.assertIn("Sharing on the default branch", text)

    def test_shipped_job_is_default_branch_only(self) -> None:
        section = _ci_section()
        self.assertIn("opentide share push --changed", section)
        self.assertIn("github.event_name", section)
        self.assertIn("pull_request", section)
        self.assertIn('CI_PIPELINE_SOURCE` is not `merge_request_event`', section)
        self.assertIn("Build.Reason` is not `PullRequest`", section)
        self.assertIn("MUST NOT contain any other `opentide share` command", section)
        self.assertNotIn("share_preview", section)

    def test_changed_refuses_a_pull_request(self) -> None:
        section = _ci_section()
        self.assertIn(
            "during a pull request or merge request MUST fail preflight",
            section,
        )
        self.assertIn("MUST NOT contact the destination", section)

    def test_empty_diff_is_success(self) -> None:
        text = SHARING.read_text(encoding="utf-8")
        self.assertIn("A `--changed` run whose diff is empty", text)
        self.assertIn("MUST exit 0 instead", text)

    def test_setup_stage_defaults_off(self) -> None:
        text = SHARING.read_text(encoding="utf-8")
        self.assertIn('Checkbox under "CI workflow features": "Sharing on the default branch"', text)
        self.assertIn("`--sharing` / `--no-sharing`", text)
        self.assertIn("| `--no-sharing` |", text)
        self.assertIn("Block `enabled` and the sharing stage are separate switches", text)
        self.assertIn("Setup MUST NOT prompt for a URL, an API key, or a block `name`", text)

    def test_workspace_job_table(self) -> None:
        text = WORKSPACE.read_text(encoding="utf-8")
        self.assertIn("| `share` | push to the default branch only, and only when setup selected the sharing stage |", text)
        self.assertIn("defaults the stage off", text)
        self.assertIn("MUST NOT emit it", text)

    def test_rfc_0005_points_here(self) -> None:
        text = RFC_0005.read_text(encoding="utf-8")
        self.assertIn("Superseded** by [RFC 0006](0006-sharing-ci.md)", text)
        self.assertNotIn("Usage-guide material, not a spec requirement", text)


if __name__ == "__main__":
    unittest.main()
