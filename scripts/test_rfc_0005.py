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
        self.assertIn("only auth/connectivity is `2`", text)

    def test_targets_live_in_one_sharing_file(self) -> None:
        text = _rfc_text()
        self.assertIn("named table `[targets.<identifier>]`", text)
        self.assertIn("`sharing/targets/*` | **No**", text)
        self.assertNotIn("Each `.toml` file directly under `sharing/targets/`", text)

    def test_document_transport_not_detection_objects(self) -> None:
        text = _rfc_text()
        self.assertIn("exactly one instance of the upstream", text)
        self.assertIn("Nothing is removed from that document", text)

    def test_file_mode_sharing_group_uuid_alone_is_invalid(self) -> None:
        text = _rfc_text()
        self.assertIn("a UUID alone is not enough", text)
        self.assertIn("UUID-only file config (`sharing_group_id = 0`) MUST fail", text)

    def test_template_version_five(self) -> None:
        text = _rfc_text()
        self.assertIn("template version 5", text)
        self.assertIn("`threat`, `objective`, `rule`", text)


class Rfc0005GoldenJsonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.event = _golden_event()["Event"]

    def test_omits_extends_uuid(self) -> None:
        self.assertNotIn("extends_uuid", self.event)

    def test_omits_data_platform(self) -> None:
        blob = json.dumps(self.event)
        self.assertNotIn("data-platform", blob)
        self.assertNotIn("data-source", blob)

    def test_single_opentide_object(self) -> None:
        objects = self.event["Object"]
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0]["name"], "opentide")
        relations = [item["object_relation"] for item in objects[0]["Attribute"]]
        self.assertIn("opentide-object", relations)
        self.assertNotIn("status", relations)

    def test_unpublished_amber_clamped_distribution(self) -> None:
        self.assertFalse(self.event["published"])
        self.assertEqual(self.event["distribution"], 0)
        self.assertEqual(self.event["threat_level_id"], 1)


if __name__ == "__main__":
    unittest.main()
