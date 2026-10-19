#!/usr/bin/env python3
"""Unit and fixture tests for deployment.state::1.0 shards and external_id_in_rule."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml

from deployment_state_fixtures import (
    EXPECTED_INVALID_RULES,
    EXPECTED_INVALID_SHARDS,
    check_deployment_fixtures,
    directory_codes,
    render,
    rule_codes,
    shard_codes,
    writer_problems,
)

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "fixtures" / "deployment"
UUID = "00000000-0000-4000-8003-000000000010"
NAME = f"{UUID}.json"
HEX = "00000000-0000-4000-8003-0000000000ab"


def _shard(platforms: dict, **extra: object) -> dict:
    return {"schema": "deployment.state::1.0", "object_uuid": UUID, "platforms": platforms, **extra}


def _codes(doc: dict, filename: str = NAME) -> set[str]:
    return set(shard_codes(filename, render(doc)))


class DeploymentFixtureTests(unittest.TestCase):
    def test_checker_passes_on_repository_fixtures(self) -> None:
        self.assertEqual(check_deployment_fixtures(), [])

    def test_every_invalid_fixture_has_an_expectation(self) -> None:
        names = {p.name for p in (DEPLOYMENT / "invalid").iterdir()}
        self.assertEqual(names, set(EXPECTED_INVALID_SHARDS) | set(EXPECTED_INVALID_RULES))

    def test_valid_fixture_is_writer_output(self) -> None:
        text = (DEPLOYMENT / "valid" / NAME).read_text(encoding="utf-8")
        self.assertEqual(shard_codes(NAME, text), [])
        self.assertEqual(writer_problems(text), [])


class ShardReaderTests(unittest.TestCase):
    def test_valid_single_binding(self) -> None:
        self.assertEqual(_codes(_shard({"defender_for_endpoint": {"Contoso": "12345"}})), set())

    def test_zero_is_a_canonical_decimal(self) -> None:
        self.assertEqual(_codes(_shard({"sentinel_one": {"s1": "0"}})), set())

    def test_unknown_root_keys_are_preserved_not_rejected(self) -> None:
        self.assertEqual(_codes(_shard({"crowdstrike": {"cs": "abc"}}, written_by="0.12")), set())

    def test_reader_tolerates_empty_maps_but_writer_does_not(self) -> None:
        for platforms in ({}, {"crowdstrike": {}}):
            doc = _shard(platforms)
            self.assertEqual(_codes(doc), set())
            self.assertTrue(writer_problems(render(doc)))

    def test_filename_must_equal_object_uuid(self) -> None:
        doc = _shard({"crowdstrike": {"cs": "abc"}})
        other = "00000000-0000-4000-8003-000000000011.json"
        self.assertEqual(_codes(doc, other), {"deployment_state_uuid_mismatch"})

    def test_uppercase_filename_is_a_mismatch(self) -> None:
        doc = _shard({"crowdstrike": {"cs": "abc"}}, object_uuid=HEX)
        self.assertEqual(_codes(doc, f"{HEX}.json"), set())
        self.assertEqual(_codes(doc, f"{HEX.upper()}.json"), {"deployment_state_uuid_mismatch"})

    def test_uppercase_object_uuid_is_a_mismatch_not_shape(self) -> None:
        doc = _shard({"crowdstrike": {"cs": "abc"}}, object_uuid=HEX.upper())
        self.assertEqual(_codes(doc, f"{HEX.upper()}.json"), {"deployment_state_uuid_mismatch"})
        self.assertEqual(_codes(doc, f"{HEX}.json"), {"deployment_state_uuid_mismatch"})

    def test_braced_or_unhyphenated_uuid_is_a_mismatch(self) -> None:
        for spelling in (HEX.replace("-", ""), "{" + HEX + "}", "urn:uuid:" + HEX):
            doc = _shard({"crowdstrike": {"cs": "abc"}}, object_uuid=spelling)
            self.assertEqual(_codes(doc, f"{spelling}.json"), {"deployment_state_uuid_mismatch"}, spelling)

    def test_non_uuid_object_uuid_is_shape(self) -> None:
        doc = _shard({"crowdstrike": {"cs": "abc"}}, object_uuid="not-a-uuid")
        self.assertIn("deployment_state_shape", _codes(doc, "not-a-uuid.json"))

    def test_tenant_whitespace_and_empty_tenant(self) -> None:
        for tenant in (" contoso", "contoso ", "", "\t"):
            doc = _shard({"defender_for_endpoint": {tenant: "1"}})
            self.assertEqual(_codes(doc), {"deployment_state_shape"}, tenant)

    def test_inner_tenant_whitespace_is_allowed(self) -> None:
        self.assertEqual(_codes(_shard({"crowdstrike": {"falcon prod": "x"}})), set())

    def test_decimal_platforms_reject_non_canonical_ids(self) -> None:
        for platform in ("defender_for_endpoint", "sentinel_one"):
            for value in ("012", "-1", "+1", "1.0", "", " 1", "abc"):
                doc = _shard({platform: {"t": value}})
                self.assertEqual(_codes(doc), {"deployment_state_shape"}, (platform, value))

    def test_ids_must_be_strings(self) -> None:
        for platform, value in (("defender_for_endpoint", 12345), ("crowdstrike", 7), ("sentinel_one", None)):
            self.assertEqual(_codes(_shard({platform: {"t": value}})), {"deployment_state_shape"})

    def test_crowdstrike_is_verbatim_but_not_blank(self) -> None:
        self.assertEqual(_codes(_shard({"crowdstrike": {"t": "00ab"}})), set())
        for value in ("", "   "):
            self.assertEqual(_codes(_shard({"crowdstrike": {"t": value}})), {"deployment_state_shape"})

    def test_platforms_without_state_are_rejected(self) -> None:
        for platform in ("sentinel", "splunk", "harfanglab", "carbon_black_cloud", "elastic"):
            doc = _shard({platform: {"t": "1"}})
            self.assertEqual(_codes(doc), {"deployment_state_platform"}, platform)

    def test_missing_required_fields_and_bad_json(self) -> None:
        for key in ("schema", "object_uuid", "platforms"):
            doc = _shard({"crowdstrike": {"t": "x"}})
            del doc[key]
            self.assertIn("deployment_state_shape", _codes(doc), key)
        self.assertEqual(shard_codes(NAME, "{not json"), ["deployment_state_shape"])
        self.assertEqual(shard_codes(NAME, "[]"), ["deployment_state_shape"])

    def test_case_variant_shard_files_fail_closed(self) -> None:
        self.assertEqual(directory_codes([NAME, f"{HEX}.json"]), [])
        self.assertEqual(
            directory_codes([f"{HEX}.json", f"{HEX.upper()}.json"]),
            ["deployment_state_uuid_mismatch"],
        )


class WriterFormTests(unittest.TestCase):
    def test_render_sorts_keys_and_ends_with_one_newline(self) -> None:
        text = render({"schema": "s", "platforms": {"b": {"z": "1", "a": "2"}}, "object_uuid": "u"})
        self.assertTrue(text.endswith("}\n") and not text.endswith("\n\n"))
        self.assertLess(text.index('"object_uuid"'), text.index('"platforms"'))
        self.assertLess(text.index('"a"'), text.index('"z"'))
        self.assertIn('\n  "platforms"', text)

    def test_unsorted_or_compact_text_is_not_writer_output(self) -> None:
        doc = _shard({"crowdstrike": {"t": "x"}})
        self.assertTrue(writer_problems(json.dumps(doc)))
        self.assertTrue(writer_problems(render(doc).rstrip("\n")))


class ExternalIdInRuleTests(unittest.TestCase):
    def _rule(self, block: dict, platform: str = "defender_for_endpoint") -> dict:
        return {"configurations": {platform: block}}

    def test_every_legacy_spelling_on_any_platform(self) -> None:
        for platform in ("defender_for_endpoint", "sentinel_one", "crowdstrike", "sentinel", "splunk", "elastic"):
            for key in ("rule_id", "rule_id_bundle", "rule_id::Contoso"):
                codes = rule_codes(self._rule({key: {"Contoso": 1}, "enabled": True}, platform))
                self.assertEqual(codes, ["external_id_in_rule"], (platform, key))

    def test_nested_keys_are_not_legacy(self) -> None:
        block = {"alert": {"rule_id": 1}, "query": "rule_id::x", "exclusions": [{"rule_id_bundle": {}}]}
        self.assertEqual(rule_codes(self._rule(block)), [])

    def test_similar_names_are_not_legacy(self) -> None:
        self.assertEqual(rule_codes(self._rule({"rule_ids": 1, "my_rule_id": 2})), [])

    def test_invalid_rule_fixtures(self) -> None:
        for name, expected in EXPECTED_INVALID_RULES.items():
            doc = yaml.safe_load((DEPLOYMENT / "invalid" / name).read_text(encoding="utf-8"))
            self.assertEqual(rule_codes(doc), [expected], name)


if __name__ == "__main__":
    unittest.main()
