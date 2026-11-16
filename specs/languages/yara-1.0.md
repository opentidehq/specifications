---
spec: language-yara
version: "1.6"
schema_id: null
status: normative
supersedes: null
---

# YARA language

## Summary

YARA is a detection language that several platforms deploy: HarfangLab ([harfanglab-1.0](../platforms/harfanglab-1.0.md)) and Bitdefender GravityZone ([bitdefender-1.0](../platforms/bitdefender-1.0.md)). This spec defines YARA once for every platform. A platform's `yara` block embeds a [`YaraSignature`](#yarasignature): a whole YARA text, written out in the block and deployed verbatim. The block is checked against the [language](#language), the [diagnostics](#diagnostics), and the platform's [profile](#platform-profiles).

The contract is YARA as YARA-X 1.x compiles it. What YARA-X refuses is an error. Syntax only YARA-X has is part of the language, and each platform profile says whether its engine takes it: while a profile's `yara_x_syntax` is `refused`, that syntax is the error `yara_x_only_syntax`. The analysis engine reports every code below in `opentide validate` and in editors. Design and research are in [RFC 0015](../../rfcs/0015-yara-language.md); the move from libyara 4.5 to YARA-X is [RFC 0020](../../rfcs/0020-yara-x-reference-language.md).

## Requirements

- A platform block that deploys YARA as a whole text MUST embed a `YaraSignature`, under the key `signature`.
- `signature` MUST be a non-blank string written out in the block. A YAML alias at `signature` MUST fail static validation with `yara_signature_alias`.
- Deploy MUST send `signature` verbatim. It MAY normalise line endings to `\n` and add one trailing newline. It MUST NOT add, remove, reorder, or rewrite rules, meta, strings, or imports.
- `signature` MUST contain at least one rule that is neither `private` nor `global` (`yara_empty_signature`).
- `signature` MUST NOT contain an `include` directive (`yara_include`). No platform resolves includes: each API takes one text with no file system behind it.
- Static validation MUST report what YARA-X 1.x refuses to compile as an [error](#errors), and MUST report every [warning](#warnings) without failing the rule.
- Static validation MUST apply the profile of the platform whose block holds the signature. A signature in two platform blocks is checked once under each profile.
- Under a profile whose `yara_x_syntax` is `refused`, static validation MUST report [YARA-X-only syntax](#yara-x-only-syntax) as `yara_x_only_syntax`. Under `allowed`, and for a text checked with no profile, it MUST NOT.
- A profile MUST NOT emulate libyara: what YARA-X compiles and libyara refuses for a value or a limit MUST NOT be an error under any profile.
- Static validation MUST NOT report the retired code `yara_x_incompatible`.
- YARA is checked offline: by `opentide validate`, and by `opentide validate query` without `--live` (a rule's signature, or a `.yar` or `.yara` file under `--platform`'s profile). No platform offers a YARA dry run, so `validate query --live` MUST report `supported: false` for a YARA platform and MUST NOT claim a tenant check.

## Definition

### YaraSignature

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `signature` | string | yes | The YARA signature, as a `.yar` file holds it: `import` statements, then one or more YARA rules. It may include `private` and `global` rules, rule tags, meta, and comments. |

A platform spec adds its own keys beside `signature` (for example Bitdefender's `on_access`). One opentide rule MAY carry a `yara` block for several platforms; each block writes its own `signature`.

### Language

The language is **YARA as YARA-X 1.x compiles it**. YARA-X 1.23.0 is the release this revision is checked against. libyara 4.5's source is not a normative source of the language. The language has:

- rules, `import`, `private`, `global`, rule tags, and meta (string, integer, boolean);
- text, hex, and regular-expression strings, with the modifiers `nocase`, `wide`, `ascii`, `fullword`, `private`, `xor`, `base64`, and `base64wide`;
- the condition language:
  - `and`, `or`, `not`, `defined`;
  - arithmetic and bitwise operators;
  - `contains`, `icontains`, `startswith`, `istartswith`, `endswith`, `iendswith`, `iequals`, `matches`;
  - `#`, `@`, `!`;
  - `at`, `in`, `filesize`, and the integer readers (`int8` … `uint32be`);
  - `of`, `for … of`, `for … in`;
  - [module](#modules) fields and functions;
- the [YARA-X-only syntax](#yara-x-only-syntax).

A rule without a `strings:` section is valid. An `import` applies to the rules after it: a module used in a rule before its `import` is `yara_module_not_imported`. Identifiers have no length limit.

#### Stricter than libyara

What libyara 4.5 compiled and YARA-X refuses is an error, under the code of what is wrong:

| Construct | Code |
|-----------|------|
| An unknown escape in a regexp (`/\Release/`), a `{` outside a repetition (`/abc{/`) | `yara_regexp` |
| `base64` or `base64wide` on a string under 3 bytes | `yara_string_modifier` |
| A string index below 1 (`@a[-1]`) | `yara_number_out_of_range` |
| A `[0-0]` jump, a jump bound past 2^32 − 1 | `yara_hex_string` |
| A repeated rule modifier (`global global`, `private private`) | `yara_parse_error` |
| A rule wildcard in `of` (`any of (base*)`). The message says to list the rules. | `yara_parse_error` |
| A rule named like an imported module (`import "pe"` … `rule pe`) | `yara_rule_identifier_conflict` |
| `entrypoint` | `yara_undefined_identifier`, with the warning `yara_entrypoint_deprecated` |
| A module member YARA-X types as boolean used as a number (an ordering, `!=`, arithmetic) | `yara_type` |
| `import "magic"` | `yara_unknown_module` |

What YARA-X compiles and libyara refused is valid: an identifier over 128 characters, a jump bound from 2^31 to 2^32 − 1, a loop variable an enclosing loop also binds, `0% of them`, a constant division by zero, floats in a loop's enumeration, and an unbounded or over-200 jump inside a hex alternative (`( 02 [1-300] 03 | 04 )`).

#### YARA-X-only syntax

These constructs are part of the language. libyara refuses them, so a profile whose `yara_x_syntax` is `refused` reports each one as `yara_x_only_syntax`, naming the construct and the platform:

- `with` declarations;
- digit separators in numbers (`1_000`);
- float meta values;
- `"""` strings;
- boolean expressions in `of` tuples;
- hex and octal jump bounds (`[0x10-0x20]`);
- `.len()`;
- a percentage with `at` or `in` (`50% of them in (0..100)`);
- regexp modifiers other than `i`, `s`, and `is`; `(?` groups and an empty first alternative in a regexp;
- the 64-bit and float readers (`int64`, `uint64`, `float32`, `float64`, and their `be` forms);
- different alphabets for `base64` and `base64wide` in one string.

#### Matching differences

YARA-X matches some strings differently from libyara: `xor` with `fullword` checks word boundaries on the XORed bytes, and `base64` matching has no false positives. This is informative. Static validation does not scan, and these differences do not affect validity.

### Modules

The modules are **YARA-X's documented default module set, less `vt`**: `console`, `crx`, `cuckoo`, `dex`, `dotnet`, `elf`, `hash`, `lnk`, `macho`, `math`, `pe`, `string`, `time`, and `zip` (VirusTotal/yara-x 1.23.0, `lib/Cargo.toml` `default-modules`). Their fields, functions, overloads, and types are YARA-X's. Importing any other module is the error `yara_unknown_module`:

- `magic` is not a YARA-X default: YARA-X builds it only with its `magic-module` feature and libmagic, because it can be very slow and its output varies across libmagic versions ([YARA-X: magic](https://virustotal.github.io/yara-x/docs/modules/magic/)).
- `vt` is a YARA-X default that this spec excludes: it describes VirusTotal's own scan metadata, which only VirusTotal's scanning fills.
- `msi`, `olecf`, and `vba` are experimental in YARA-X and not built by default.

For these modules and YARA-X's experimental ones, the `yara_unknown_module` message says why.

A module member YARA-X types as boolean (a field, or a function's return, such as `pe.is_dll()`, `lnk.is_lnk`, or `dex.contains_class(…)`) is a boolean. Compared with `==` to an integer (`lnk.is_lnk == 1`) it is the warning `yara_suspicious_expression`, as YARA-X warns (`bool_int_comparison`). An ordering, `!=`, or arithmetic on it is the error `yara_type`, as YARA-X refuses it. A `with` name bound to one is a boolean too.

Each profile names the modules confirmed on its agents. Importing a known module outside that set is the warning `yara_module_unconfirmed`.

### Diagnostics

#### Errors

| Code | Condition |
|------|-----------|
| `yara_parse_error` | Syntax error, as YARA-X reports it: among them a repeated rule modifier, a rule wildcard in `of`, an escape in a `base64` alphabet, and an empty text string |
| `yara_include` | An `include` directive |
| `yara_signature_alias` | `signature` is a YAML alias instead of its own text |
| `yara_empty_signature` | No YARA rule, or only `private` or `global` rules |
| `yara_duplicate_rule` | Two YARA rules with one name in a `signature` |
| `yara_duplicate_string` | Two strings with one identifier in a rule (the anonymous `$` excepted) |
| `yara_duplicate_tag` | A rule tag repeated on one rule |
| `yara_undefined_string` | A `$id`, `#id`, `@id`, `!id`, or `$prefix*` in a condition that matches no string of the rule; `$` outside `for … of`; `them` in a rule with no strings |
| `yara_unreferenced_string` | A string never used in the condition, when the condition does not use `them`. A string whose identifier starts with `_` (`$_x`) is exempt |
| `yara_undefined_identifier` | A bare identifier that is neither a rule defined earlier in the `signature`, a loop or `with` variable, nor a module; a call to something that is not a function; `entrypoint` |
| `yara_rule_identifier_conflict` | A rule named like a YARA-X reserved word or built-in (`with` and the 64-bit and float readers among them), or like an imported module |
| `yara_unknown_module` | `import` of a module outside the language's [modules](#modules) (`magic` and `vt` among them) |
| `yara_module_not_imported` | A module field or function used without an `import` of the module before the rule |
| `yara_unknown_module_member` | A field or function YARA-X's module does not have, or arguments no overload takes |
| `yara_type` | An operator or function applied to the wrong type (`filesize contains "a"`); a module member YARA-X types as boolean where a number is needed (an ordering, `!=`, arithmetic, an offset, an index, a range bound) |
| `yara_regexp` | An invalid regular expression, as YARA-X reads it: an unknown escape, a `{` outside a repetition, a look-around group, a string's regexp that can match the empty string, nesting past 250 levels |
| `yara_hex_string` | An invalid hex string: odd nibbles, a `[0-0]` jump, a jump `[a-b]` with a > b, a bound past 2^32 − 1, unbalanced alternatives |
| `yara_string_modifier` | A modifier repeated, on the wrong kind of string, or combined as YARA-X refuses (`xor` or `base64` with `nocase`, `base64` with `fullword` or `xor`); an `xor` range or `base64` alphabet YARA-X refuses; `base64` or `base64wide` on a string under 3 bytes |
| `yara_number_out_of_range` | An integer literal over 64 bits; a percentage above 100; a constant expression that overflows 64 bits; a string index below 1 |
| `yara_x_only_syntax` | [YARA-X-only syntax](#yara-x-only-syntax) under a profile whose `yara_x_syntax` is `refused`. The message names the construct and the platform. |

#### Warnings

| Code | Condition |
|------|-----------|
| `yara_slow_pattern` | A string with no atom good enough to scan fast: a short or all-wildcard atom, a regexp with no fixed atom, a hex jump too wide to scan fast (libyara 4.5's slow-scanning heuristic, kept as a hint) |
| `yara_entrypoint_deprecated` | `entrypoint`, beside the error `yara_undefined_identifier`: YARA-X has no `entrypoint` (use `pe.entry_point` or `elf.entry_point`) |
| `yara_suspicious_expression` | An invariant or unsatisfiable condition, a non-boolean condition, or an integer compared with a boolean. A condition is non-boolean where YARA-X 1.x reports `non_bool_expr`: an integer, float, or string expression. A module member YARA-X types as boolean is boolean; `== 1` on one is YARA-X's `bool_int_comparison`. |
| `yara_module_unconfirmed` | A known module outside the profile's confirmed set |
| `yara_meta_missing` | A meta key the profile recommends is missing on a non-private rule |

#### Retired codes

| Code | Retired in | Now |
|------|------------|-----|
| `yara_x_incompatible` | 1.6 | Was the warning for what libyara compiles and YARA-X refuses. Each such construct is now an error under the code of what is wrong ([Stricter than libyara](#stricter-than-libyara)). |

A retired code is never reported and never reused. An implementation MAY keep explaining it.

Codes are stable. opentide's `docs/engine/YARA.md` maps each one to its source (YARA-X, or the libyara behaviour YARA-X keeps) and the test that proves it.

### Platform profiles

| | `bitdefender` | `harfanglab` |
|---|---|---|
| `yara_x_syntax` | `refused` | `refused` |
| Characters | ASCII only | UTF-8 |
| Size | at most 30,000 characters | no documented limit |
| YARA rules per `signature` | one or more | one or more |
| Confirmed modules | `pe`, `elf`, `math`, `hash`, `time` | `pe`, `elf`, `math`, `hash`, `time` |
| Recommended meta | none | `context` on every non-private rule |
| Profile codes | `bitdefender_yara_ascii`, `bitdefender_yara_size` (errors) | `harfanglab_yara_context` (warning) |

`yara_x_syntax` is `allowed` or `refused`. Neither vendor documents its YARA engine, and Bitdefender's agent ships libyara by its open-source notices ([RFC 0015](../../rfcs/0015-yara-language.md#bitdefender-yara)), so both profiles start at `refused`. A profile moves to `allowed` in a revision of this spec and of its platform spec, once a live deploy confirms the platform takes YARA-X-only syntax.

The check is syntactic. A profile does not emulate libyara: a signature YARA-X compiles that libyara refuses for a value or a limit (an identifier over 128 characters, an unsigned literal above `i64::MAX`, `0% of them`) passes under both profiles, and may still fail at a libyara tenant.

A platform spec states its profile codes. The confirmed module sets are a maintainer decision (2026-11-10): `crx`, `zip`, and every other module outside them get `yara_module_unconfirmed`.

## Relationships

- [harfanglab-1.0](../platforms/harfanglab-1.0.md): `configurations.harfanglab.yara.signature`, and the decomposed form checked as the rule deploy assembles it
- [bitdefender-1.0](../platforms/bitdefender-1.0.md): `configurations.bitdefender.yara.signature`
- [platforms](../platforms/index.md): capability matrix and static-validation bar
- [validation.md](../validation.md): errors, warnings, and offline checks
- [RFC 0015](../../rfcs/0015-yara-language.md): design and research
- [RFC 0020](../../rfcs/0020-yara-x-reference-language.md): YARA-X 1.x as the reference language, `yara_x_syntax`, and the module set
- [RFC 0014](../../rfcs/0014-sysdig-falco-platform.md): the engine pattern this follows

## Defaults & overrides

| Setting | Default |
|---------|---------|
| Language | YARA-X 1.x |
| `yara_x_syntax` | `refused`, per profile; a text checked with no profile takes YARA-X-only syntax |
| Confirmed modules | `pe`, `elf`, `math`, `hash`, `time`, per profile |

There are no overrides. A workspace cannot widen a profile.

## Examples

A HarfangLab block with two YARA rules, one of them a private helper:

```yaml
configurations:
  harfanglab:
    enabled: true
    schema: platform::harfanglab::1.0
    status: STAGING
    yara:
      signature: |
        import "pe"

        private rule MZ_Header {
          condition:
            uint16(0) == 0x5A4D
        }

        rule Loader_Stage1 : loader {
          meta:
            description = "Stage-1 loader with an encrypted config blob"
            context = "file,memory"
          strings:
            $cfg = { 43 46 47 21 [4-16] 00 01 }
            $mutex = "Global\\qx-7731" ascii wide
          condition:
            MZ_Header and pe.number_of_sections > 3 and all of them
        }
```

A rule that uses `with` (YARA-X-only syntax) is valid in a `.yar` file checked with no profile. In a HarfangLab or Bitdefender block it is `yara_x_only_syntax`, because both profiles' `yara_x_syntax` is `refused`:

```yara
import "pe"

rule Loader_Sections {
  meta:
    context = "file"
  condition:
    with n = pe.number_of_sections : ( n > 3 and n < 10 )
}
```

These are errors under every profile, where libyara 4.5 compiled them:

| Text | Code |
|------|------|
| `$a = /\Release/` (`\R` is not an escape YARA-X knows) | `yara_regexp` |
| `any of (Loader_*)` | `yara_parse_error`: list the rules |
| `entrypoint == 0x1000` | `yara_undefined_identifier`; use `pe.entry_point` |
| `import "magic"` | `yara_unknown_module` |

Fixtures: [fixtures/platforms/harfanglab-yara-signature.yaml](../../fixtures/platforms/harfanglab-yara-signature.yaml); invalid: [rule-yara-signature-alias.yaml](../../fixtures/invalid/rule-yara-signature-alias.yaml), [rule-harfanglab-yara-include.yaml](../../fixtures/invalid/rule-harfanglab-yara-include.yaml), [rule-yara-unknown-module.yaml](../../fixtures/invalid/rule-yara-unknown-module.yaml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-11-10 | Initial language spec ([RFC 0015](../../rfcs/0015-yara-language.md)): `YaraSignature`, the libyara 4.5 dialect with YARA-X warnings, diagnostics codes, and the `bitdefender` and `harfanglab` profiles. Answers the YARA questions of [specifications#68](https://github.com/opentidehq/specifications/issues/68). |
| 1.1 | 2026-11-10 | Clarifications from the first implementation review, checked against libyara 4.5.4 and YARA-X 1.23: identifiers are at most 128 characters (`yara_parse_error`); an `import` must come before the rule that uses the module; a rule named like an imported module is `yara_x_incompatible` (libyara compiles it), so `yara_rule_identifier_conflict` covers keywords only; a `yara_x_incompatible` message says what YARA-X refuses rather than quoting it; `yara_slow_pattern` names libyara's own warnings only. No code is added or removed. |
| 1.2 | 2026-11-10 | Clarifications from the second implementation review, checked against libyara 4.5.4 and YARA-X 1.23: the 128-character limit applies to rule names, rule tags, and meta keys, not to string identifiers; a non-boolean condition for `yara_suspicious_expression` is what YARA-X reports as `non_bool_expr`, so module members YARA-X types as boolean do not warn. No code is added or removed. |
| 1.3 | 2026-11-10 | Clarification from the third implementation review, checked against libyara 4.5.4 and YARA-X 1.23: the 128-character limit covers every identifier except string identifiers, including `for` and `with` variables, not only rule names, rule tags, and meta keys. No code is added or removed. |
| 1.4 | 2026-11-10 | `opentide validate query` checks YARA offline (signatures, and `.yar`/`.yara` files under the platform's profile); `--live` stays `supported: false`. Matches [validation 1.9](../validation.md#query-validation). No code is added or removed. |
| 1.5 | 2026-11-10 | `yara_rule_identifier_conflict` also covers a rule whose name matches a rule wildcard an earlier condition uses, which libyara 4.5.4 refuses ("matches previously used wildcard rule set"). No code is added or removed. |
| 1.6 | 2026-11-16 | YARA-X 1.x is the reference language ([RFC 0020](../../rfcs/0020-yara-x-reference-language.md), [specifications#93](https://github.com/opentidehq/specifications/issues/93)), replacing libyara 4.5. What libyara compiled and YARA-X refuses is an error under the code of what is wrong; what YARA-X compiles and libyara refused for a value or a limit is valid, and identifiers have no length limit. YARA-X-only syntax is part of the language; each profile's `yara_x_syntax` (`refused` for both) replaces its `dialect`, and new error `yara_x_only_syntax` reports that syntax under a refusing profile. `yara_x_incompatible` is retired. The modules are YARA-X's default set less `vt` (`crx` and `zip` added, `magic` removed), typed as YARA-X types them; a module boolean compared `== 1` warns, and ordered, `!=`, or in arithmetic is `yara_type`. |
