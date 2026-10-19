#!/usr/bin/env python3
"""Tests for validate.py's pin guard: every pinned field::M.m is a revision keys change at."""

from __future__ import annotations

import tempfile
import tomllib
import unittest
from pathlib import Path

from validate import PINS_DIR, VOCAB_DIR, _validate_pins_introduced

DEMO_VOCAB = """\
name = "Demo"
field = "demo"
description = "Demo vocabulary."
key = "id"

[[keys]]
id = "A"
name = "A"
version = "1.0"

[[keys]]
id = "B"
name = "B"
version = "1.1"
removed = "2.0"
"""


class PinsIntroducedTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.vocab_dir = Path(tmp.name)
        (self.vocab_dir / "demo.vocab.toml").write_text(DEMO_VOCAB, encoding="utf-8")
        self.pin_path = Path("schemas/pins/demo.toml")

    def _errors(self, contract: str) -> list[str]:
        doc = {"demo::1.0": {"demo.field": contract}}
        return _validate_pins_introduced(self.pin_path, doc, self.vocab_dir)

    def test_pin_at_an_introduced_minor_passes(self) -> None:
        self.assertEqual(self._errors("demo::1.0"), [])
        self.assertEqual(self._errors("demo::1.1"), [])

    def test_pin_at_a_removal_only_major_passes(self) -> None:
        # RFC 0003: removing B opens demo::2.0 with no key introduced at it.
        self.assertEqual(self._errors("demo::2.0"), [])

    def test_pin_at_a_minor_no_key_introduces_fails(self) -> None:
        # opentide#568: att&ck::1.1 was pinned while every key was at 1.0.
        errors = self._errors("demo::1.2")
        self.assertEqual(len(errors), 1)
        self.assertIn("no demo key is introduced or removed at 1.2", errors[0])
        self.assertIn("key revisions: 1.0, 1.1, 2.0", errors[0])

    def test_attack_removal_major_is_pinnable(self) -> None:
        # 27 att&ck keys carry removed = "2.0" and none is introduced at 2.0.
        doc = {"demo::1.0": {"techniques": "att&ck::2.0"}}
        self.assertEqual(_validate_pins_introduced(self.pin_path, doc, VOCAB_DIR), [])

    def test_pin_past_the_last_removal_fails(self) -> None:
        errors = self._errors("demo::2.1")
        self.assertEqual(len(errors), 1)
        self.assertIn("no demo key is introduced or removed at 2.1", errors[0])

    def test_pin_to_a_missing_vocabulary_fails(self) -> None:
        errors = self._errors("nope::1.0")
        self.assertEqual(len(errors), 1)
        self.assertIn("vocabularies/nope.vocab.toml is missing", errors[0])

    def test_extends_and_non_table_sections_are_skipped(self) -> None:
        doc = {"extends": "base", "demo::1.0": {"extends": "base", "demo.field": "demo::1.1"}}
        self.assertEqual(_validate_pins_introduced(self.pin_path, doc, self.vocab_dir), [])

    def test_repository_pins_are_all_introduced(self) -> None:
        cache: dict[str, set[str] | None] = {}
        for path in sorted(PINS_DIR.glob("*.toml")):
            doc = tomllib.loads(path.read_text(encoding="utf-8"))
            with self.subTest(pin_file=path.name):
                self.assertEqual(_validate_pins_introduced(path, doc, VOCAB_DIR, cache), [])


if __name__ == "__main__":
    unittest.main()
