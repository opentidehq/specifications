#!/usr/bin/env python3
"""Consistency tests for RFC 0005 (sharing / MISP)."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from share_exit import share_exit_code

ROOT = Path(__file__).resolve().parents[1]
RFC = ROOT / "rfcs" / "0005-sharing-system.md"


def _rfc_text() -> str:
    return RFC.read_text(encoding="utf-8")


def _golden_event() -> dict:
    text = _rfc_text()
    match = re.search(r"```json\n(\{.*?\n\})\n```", text, flags=re.DOTALL)
    if not match:
        raise AssertionError("RFC 0005 is missing the §7.8 golden JSON fence")
    return json.loads(match.group(1))


class ShareExitPartitionTests(unittest.TestCase):
    def test_preflight_is_one(self) -> None:
        self.assertEqual(share_exit_code(preflight=True, actions=[]), 1)

    def test_policy_skips_only_are_zero(self) -> None:
        self.assertEqual(
            share_exit_code(preflight=False, actions=["skipped_tlp", "skipped_status"]),
            0,
        )

    def test_all_success_is_zero(self) -> None:
        self.assertEqual(
            share_exit_code(preflight=False, actions=["created", "unchanged"]),
            0,
        )

    def test_sole_org_mismatch_is_one(self) -> None:
        self.assertEqual(
            share_exit_code(
                actions=["failed"],
                failure_reasons=["org_mismatch"],
            ),
            1,
        )

    def test_http_5xx_only_is_one(self) -> None:
        self.assertEqual(
            share_exit_code(
                actions=["failed", "failed"],
                failure_reasons=["http_5xx", "http_5xx"],
            ),
            1,
        )

    def test_sharing_group_unresolved_before_events_is_one(self) -> None:
        self.assertEqual(share_exit_code(preflight=True, actions=[]), 1)

    def test_auth_failure_with_no_success_is_two(self) -> None:
        self.assertEqual(
            share_exit_code(
                actions=["failed"],
                target_failed=True,
                failure_reasons=["authentication"],
            ),
            2,
        )

    def test_connectivity_only_is_two(self) -> None:
        self.assertEqual(
            share_exit_code(actions=["failed"], failure_reasons=["connectivity"]),
            2,
        )

    def test_mixed_object_outcomes_on_one_target_are_three(self) -> None:
        self.assertEqual(
            share_exit_code(preflight=False, actions=["created", "failed"]),
            3,
        )

    def test_auth_failure_after_another_target_succeeded_is_three(self) -> None:
        self.assertEqual(
            share_exit_code(
                preflight=False,
                actions=["created"],
                target_failed=True,
            ),
            3,
        )

    def test_every_outcome_maps_to_a_code(self) -> None:
        cases = [
            {"preflight": True, "actions": []},
            {"actions": []},
            {"actions": ["skipped_tlp"]},
            {"actions": ["created"]},
            {"actions": ["failed"], "failure_reasons": ["org_mismatch"]},
            {"actions": ["failed"], "failure_reasons": ["authentication"]},
            {"actions": ["created", "failed"]},
            {"actions": ["retracted"], "target_failed": True, "failure_reasons": ["connectivity"]},
        ]
        for kwargs in cases:
            with self.subTest(**kwargs):
                code = share_exit_code(**kwargs)
                self.assertIn(code, {0, 1, 2, 3})


class Rfc0005TextTests(unittest.TestCase):
    def test_rfc_file_exists(self) -> None:
        self.assertTrue(RFC.is_file())

    def test_exit_table_is_an_ordered_partition(self) -> None:
        text = _rfc_text()
        self.assertIn("MUST choose **exactly one** code using this order", text)
        self.assertIn("total failure that is not solely auth/connectivity", text)
        self.assertIn("a sole-target run of only `org_mismatch` / HTTP 5xx is `1`", text)
        self.assertIn("only auth/connectivity is `2`", text)

    def test_no_design_threats_drawback(self) -> None:
        self.assertNotIn("DESIGN threats never reach MISP", _rfc_text())
        self.assertIn("DESIGN/non-PRODUCTION **rules**", _rfc_text())

    def test_signal_data_is_not_concatenated(self) -> None:
        text = _rfc_text()
        self.assertNotIn("concatenated unique `signals[].data`", text)
        self.assertIn("MUST NOT stringify or concatenate the mapping", text)

    def test_chaining_uses_presence_not_also_shared(self) -> None:
        text = _rfc_text()
        self.assertNotIn("when the target threat is also shared", text)
        self.assertIn("when the chained threat Event is **present**", text)

    def test_file_mode_sharing_group_uuid_alone_is_invalid(self) -> None:
        text = _rfc_text()
        self.assertIn("a UUID alone is not enough", text)
        self.assertIn("UUID-only file config (`sharing_group_id = 0`) MUST fail", text)

    def test_extends_uuid_not_gated_on_published(self) -> None:
        text = _rfc_text()
        self.assertIn("MUST NOT depend on MISP `published`", text)
        self.assertIn("A `state.json` `remote_event_uuid` MUST NOT by itself make a parent Event **present**", text)


class Rfc0005GoldenJsonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.event = _golden_event()["Event"]

    def test_omits_extends_uuid(self) -> None:
        self.assertNotIn("extends_uuid", self.event)

    def test_omits_data_platform(self) -> None:
        blob = json.dumps(self.event)
        self.assertNotIn("data-platform", blob)

    def test_data_source_is_sentinel(self) -> None:
        attrs = self.event["Object"][0]["Attribute"]
        sources = [item["value"] for item in attrs if item.get("object_relation") == "data-source"]
        self.assertEqual(sources, ["sentinel"])

    def test_detection_status_title_case(self) -> None:
        attrs = self.event["Object"][0]["Attribute"]
        status = [item["value"] for item in attrs if item.get("object_relation") == "status"]
        self.assertEqual(status, ["Production"])

    def test_bookkeeping_omits_optional_uuid_tag(self) -> None:
        names = [tag["name"] for tag in self.event["Tag"]]
        self.assertTrue(any(name.startswith("opentide:family=") for name in names))
        self.assertFalse(any("opentide:uuid=" in name for name in names))

    def test_unpublished_amber_clamped_distribution(self) -> None:
        self.assertFalse(self.event["published"])
        self.assertEqual(self.event["distribution"], 0)
        self.assertEqual(self.event["threat_level_id"], 1)


if __name__ == "__main__":
    unittest.main()
