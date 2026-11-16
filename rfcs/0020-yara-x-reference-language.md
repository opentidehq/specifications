# RFC 0020: YARA-X 1.x is the reference YARA language

- **RFC:** 0020
- **Title:** YARA-X 1.x is the reference YARA language, with a per-platform portability setting
- **Author:** opentide maintainers
- **Status:** accepted
- **Created:** 2026-11-16
- **Accepted:** 2026-11-16. The language decision is the maintainer's on [opentidehq/specifications#93](https://github.com/opentidehq/specifications/issues/93) (2026-11-15) and [opentidehq/opentide#1225](https://github.com/opentidehq/opentide/issues/1225); the module set is the maintainer's decision on opentide#1225 (2026-11-16). The normative text is [specs/languages/yara-1.0.md](../specs/languages/yara-1.0.md) 1.6, [specs/platforms/harfanglab-1.0.md](../specs/platforms/harfanglab-1.0.md) 1.5, [specs/platforms/bitdefender-1.0.md](../specs/platforms/bitdefender-1.0.md) 1.5, and [specs/validation.md](../specs/validation.md) 1.15.
- **Amends:** [RFC 0015](0015-yara-language.md) §3 (dialect and diagnostics), §4 (profiles), and the module list
- **Implementation:** [opentidehq/opentide#1225](https://github.com/opentidehq/opentide/issues/1225) (epic [#1219](https://github.com/opentidehq/opentide/issues/1219)): [#1405](https://github.com/opentidehq/opentide/pull/1405) (YARA-X is the language, `yara_x_incompatible` retired, `yara_x_only_syntax`) and [#1438](https://github.com/opentidehq/opentide/pull/1438) (modules from YARA-X's default set)

## Summary

[yara-1.0](../specs/languages/yara-1.0.md) defined the YARA language as what libyara 4.5 compiles, with YARA-X 1.x as a second opinion whose refusals were the warning `yara_x_incompatible`. This RFC makes **YARA-X 1.x the reference language**:

- what YARA-X refuses is an error, under the code of what is wrong;
- syntax only YARA-X has is part of the language, and each platform profile says whether its engine takes it (`yara_x_syntax: allowed | refused`); while it is `refused`, that syntax is the error `yara_x_only_syntax`;
- `yara_x_incompatible` is retired;
- the modules are YARA-X's default module set, less `vt`.

`YaraSignature`, the platform blocks, and every schema id are unchanged.

## Motivation

- **libyara is in maintenance; YARA-X is where VirusTotal works.** New YARA syntax and module work land in YARA-X only.
- **Two languages in one checker cost more than they bring.** The analysis engine parsed with `yara-x-parser` and then emulated libyara's quirks on top, with a second grammar for libyara-only forms. The quirks it emulated (an unknown regexp escape, `@a[-1]`, a repeated rule modifier) are bugs or near-bugs that YARA-X refuses on purpose ([Differences with YARA](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/)).
- **A warning nobody acts on.** `yara_x_incompatible` flagged text that would break the day a platform moves to YARA-X, without failing the rule. Making those errors now costs a small, mechanical fix per rule.
- **Portability is a per-platform question.** Neither HarfangLab nor Bitdefender names its engine version. What matters for each is whether it takes YARA-X-only syntax, which one setting per profile answers until a live deploy confirms it.

## Detailed design

### 1. Affected specs

| Path | Change |
|------|--------|
| `specs/languages/yara-1.0.md` | 1.5 → **1.6**. Reference language YARA-X 1.x; YARA-X-only syntax; module set; `yara_x_only_syntax`; `yara_x_incompatible` retired; profiles carry `yara_x_syntax` instead of `dialect`. |
| `specs/platforms/harfanglab-1.0.md` | 1.4 → **1.5**. YARA profile: `yara_x_syntax: refused`. `schema_id` unchanged. |
| `specs/platforms/bitdefender-1.0.md` | 1.4 → **1.5**. YARA profile: `yara_x_syntax: refused`. `schema_id` unchanged. |
| `specs/validation.md` | 1.14 → **1.15**. The YARA warning list; `yara_unknown_module` in the fixture checker. |
| `SPECS.md`, `CHANGELOG.md`, `rfcs/README.md`, `llms.txt` | Index rows |
| `fixtures/invalid/rule-yara-unknown-module.yaml` | **New.** `import "magic"` is `yara_unknown_module`. |

### 2. Why a minor revision in place, not `yara-1.1.md`

[Versioning](../specs/versioning.md) asks for a new spec file when a **schema identifier** changes, so that objects that declare the old one keep validating against it. The YARA language has no schema identifier: no object names a language revision, and a `yara` block's shape (`YaraSignature`, `platform::harfanglab::1.0`, `platform::bitdefender::1.0`) is unchanged. A second language file would have nothing to select it, and every `signature` would still be checked against one language. This follows the precedent of RFC 0015 itself, which made a HarfangLab block with both `sigma` and `yara` fail in place (harfanglab-1.0 1.2).

The change is breaking for content (signatures libyara compiled can now fail), so it carries this RFC, as GOVERNANCE requires.

### 3. The language

- **Reference:** YARA as YARA-X 1.x compiles it, YARA-X 1.23.0 the release checked against. libyara source is no longer the normative source of a rule; it remains the source of the slow-pattern heuristic the engine keeps.
- **What libyara accepted and YARA-X refuses is an error**, under the code of what is wrong:

  | Construct | Code |
  |-----------|------|
  | An unknown regexp escape (`/\Release/`), a `{` outside a repetition | `yara_regexp` |
  | `base64` or `base64wide` on a string under 3 bytes | `yara_string_modifier` |
  | A negative string index (`@a[-1]`) | `yara_number_out_of_range` |
  | `[0-0]`, a jump bound past 2^32 − 1 | `yara_hex_string` |
  | A repeated rule modifier (`global global`) | `yara_parse_error` |
  | A rule wildcard in `of` (`any of (base*)`); the message says to list the rules | `yara_parse_error` |
  | A rule named like an imported module | `yara_rule_identifier_conflict` |
  | `entrypoint` | `yara_undefined_identifier`, with the warning `yara_entrypoint_deprecated` |
  | A module member YARA-X types as boolean used as a number (an ordering, `!=`, arithmetic) | `yara_type` |

- **What YARA-X compiles and libyara refused is no longer an error:** an identifier over 128 characters, a jump bound from 2^31 to 2^32 − 1, a loop variable that an enclosing loop binds, `0% of them`, a constant division by zero, floats in a loop's enumeration, an unbounded or over-200 jump inside a hex alternative.
- **YARA-X-only syntax is part of the language:** `with`, digit separators, float meta values, `"""` strings, booleans in `of` tuples, hex and octal jump bounds, `.len()`, a percentage with `at` or `in`, regexp modifiers other than `i`, `s`, `is`, `(?` groups and an empty first alternative in a regexp, the 64-bit and float readers, and different `base64` and `base64wide` alphabets in one string.
- **Matching differences are informative.** `xor` with `fullword` checks word boundaries on the XORed bytes, and `base64` matches without libyara's false positives. They do not affect validity.

### 4. Profiles

The `dialect` row is replaced by `yara_x_syntax: allowed | refused`. While it is `refused`, YARA-X-only syntax is `yara_x_only_syntax` (error), naming the construct and the platform. Both profiles start at `refused`: neither vendor documents its engine, and Bitdefender's agent ships libyara ([RFC 0016](0016-bitdefender-gravityzone-platform.md)). A profile flips to `allowed` in a revision of this spec and its platform spec once a live deploy confirms the platform takes the syntax.

The check is syntactic. A profile does not emulate libyara: a signature YARA-X compiles that libyara refuses for a value or a limit (an identifier over 128 characters, an unsigned literal above `i64::MAX`, `0% of them`) passes under both profiles.

A text checked with no platform profile (a `.yar` file in an editor) takes YARA-X-only syntax.

### 5. Modules

The modules are **YARA-X's documented default module set, less `vt`**: `console`, `crx`, `cuckoo`, `dex`, `dotnet`, `elf`, `hash`, `lnk`, `macho`, `math`, `pe`, `string`, `time`, `zip` (VirusTotal/yara-x 1.23.0, `lib/Cargo.toml` `default-modules`). Importing any other module is `yara_unknown_module`:

- `magic` is not a YARA-X default. YARA-X builds it only with its `magic-module` feature and libmagic, because it can be very slow and its output varies across libmagic versions ([YARA-X: magic](https://virustotal.github.io/yara-x/docs/modules/magic/)).
- `vt` is a YARA-X default that this spec excludes: it describes VirusTotal's own scan metadata, which only VirusTotal's scanning fills.
- `msi`, `olecf`, and `vba` are experimental in YARA-X and not built by default.

Members and their types are YARA-X's. A member YARA-X types as boolean is checked as YARA-X checks it: `== 1` is the warning `yara_suspicious_expression` (YARA-X's `bool_int_comparison`), and an ordering, `!=`, or arithmetic is `yara_type`.

`crx` and `zip` are outside both profiles' confirmed sets (`pe`, `elf`, `math`, `hash`, `time`, unchanged), so they get the existing `yara_module_unconfirmed` warning.

### 6. Codes

- **New error:** `yara_x_only_syntax`.
- **Retired:** `yara_x_incompatible`. An implementation MUST NOT report it. It MAY keep explaining it, and the code is never reused.
- Every other code is kept; the conditions of `yara_parse_error`, `yara_undefined_string`, `yara_undefined_identifier`, `yara_rule_identifier_conflict`, `yara_unknown_module`, `yara_type`, `yara_regexp`, `yara_hex_string`, `yara_string_modifier`, `yara_number_out_of_range`, `yara_entrypoint_deprecated`, and `yara_suspicious_expression` follow YARA-X.

## Drawbacks

- **Rules that compiled can now fail validation.** The fixes are small (escape a `{`, list the rules instead of a wildcard, replace `entrypoint` with `pe.entry_point`), and opentide's changelog lists them.
- **The one feature loss is rule wildcards in `of`**: a rule that used `any of (family_*)` must list the rules.
- **A libyara platform may refuse what validation passes.** The profiles check syntax, not libyara's limits, so a 129-character identifier or `0% of them` passes validation and fails at a libyara tenant. Bitdefender's agent ships libyara. This is accepted: emulating libyara is the dual-language checker this RFC removes.
- **`import "magic"` and `import "vt"` fail.** A rule that imported `magic` (which libyara ships) drops the import and its conditions.

## Alternatives

- **Keep libyara 4.5 as the contract.** Rejected: it ties opentide to a maintenance-mode engine and keeps a second grammar in the checker.
- **A `dialect` per profile (`libyara4` | `yara_x`), as RFC 0015 left open.** Rejected: a full libyara dialect means emulating libyara's limits and quirks. One portability setting over a short list of syntax answers the question that matters for each platform.
- **A new file, `yara-1.1.md`.** Rejected; see §2.
- **YARA-X's whole default module set, `vt` included.** Rejected: `vt`'s fields are filled only by VirusTotal's scanning, so a rule that uses it never matches on an EDR.
- **Keep `magic`.** Rejected: YARA-X does not build it by default, and its verdicts vary with the libmagic version.

## Unresolved questions

- When a live deploy on HarfangLab or Bitdefender confirms YARA-X-only syntax, the profile flips to `allowed`; which constructs the live check must cover is opentide's publishing checklist, not this spec.
- Whether the profiles' confirmed module sets grow (for example to `dotnet` or `lnk`) once a vendor confirms them.

## References

- [opentidehq/specifications#93](https://github.com/opentidehq/specifications/issues/93); [opentidehq/opentide#1225](https://github.com/opentidehq/opentide/issues/1225), [#1219](https://github.com/opentidehq/opentide/issues/1219), [#1405](https://github.com/opentidehq/opentide/pull/1405), [#1438](https://github.com/opentidehq/opentide/pull/1438)
- [RFC 0015](0015-yara-language.md); [RFC 0016](0016-bitdefender-gravityzone-platform.md)
- [YARA-X](https://github.com/VirusTotal/yara-x): [Differences with YARA](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/), [modules](https://virustotal.github.io/yara-x/docs/modules/), [magic](https://virustotal.github.io/yara-x/docs/modules/magic/)
- opentide `docs/engine/YARA.md` (`integration/unified-core`): each code's source and test
