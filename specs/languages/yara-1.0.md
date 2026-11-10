---
spec: language-yara
version: "1.4"
schema_id: null
status: normative
supersedes: null
---

# YARA language

## Summary

YARA is a detection language that several platforms deploy: HarfangLab ([harfanglab-1.0](../platforms/harfanglab-1.0.md)) and Bitdefender GravityZone. This spec defines YARA once for every platform. A platform's `yara` block embeds a [`YaraSignature`](#yarasignature): a whole YARA text, written out in the block and deployed verbatim. The block is checked against the [dialect](#dialect), the [diagnostics](#diagnostics), and the platform's [profile](#platform-profiles).

The contract is YARA as libyara 4.5 compiles it. YARA-X 1.x is a second opinion: what only YARA-X refuses is a warning. The analysis engine (language-server) reports every code below in `opentide validate` and in editors. Design and research are in [RFC 0015](../../rfcs/0015-yara-language.md).

## Requirements

- A platform block that deploys YARA as a whole text MUST embed a `YaraSignature`, under the key `signature`.
- `signature` MUST be a non-blank string written out in the block. A YAML alias at `signature` MUST fail static validation with `yara_signature_alias`.
- Deploy MUST send `signature` verbatim. It MAY normalise line endings to `\n` and add one trailing newline. It MUST NOT add, remove, reorder, or rewrite rules, meta, strings, or imports.
- `signature` MUST contain at least one rule that is neither `private` nor `global` (`yara_empty_signature`).
- `signature` MUST NOT contain an `include` directive (`yara_include`). No platform resolves includes: each API takes one text with no file system behind it.
- Static validation MUST report every [error](#errors) as a failure, and MUST report every [warning](#warnings) without failing the rule.
- Static validation MUST apply the profile of the platform whose block holds the signature. A signature in two platform blocks is checked once under each profile.
- YARA is checked offline: by `opentide validate`, and by `opentide validate query` without `--live` (a rule's signature, or a `.yar` or `.yara` file under `--platform`'s profile). No platform offers a YARA dry run, so `validate query --live` MUST report `supported: false` for a YARA platform and MUST NOT claim a tenant check.

## Definition

### YaraSignature

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `signature` | string | yes | The YARA signature, as a `.yar` file holds it: `import` statements, then one or more YARA rules. It may include `private` and `global` rules, rule tags, meta, and comments. |

A platform spec adds its own keys beside `signature` (for example Bitdefender's `on_access`). One opentide rule MAY carry a `yara` block for several platforms; each block writes its own `signature`.

### Dialect

The language is **YARA as libyara 4.5 compiles it**:

- rules, `import`, `private`, `global`, rule tags, and meta (string, integer, boolean);
- text, hex, and regular-expression strings, with the modifiers `nocase`, `wide`, `ascii`, `fullword`, `private`, `xor`, `base64`, and `base64wide`;
- the full condition language:
  - `and`, `or`, `not`;
  - arithmetic and bitwise operators;
  - `contains`, `icontains`, `startswith`, `istartswith`, `endswith`, `iendswith`, `iequals`, `matches`;
  - `#`, `@`, `!`;
  - `at`, `in`, `filesize`, `entrypoint`, and the `int*`/`uint*` readers;
  - `of`, `for … of`, `for … in`;
  - module fields and functions.

A rule without a `strings:` section is valid. Two libyara limits are part of the dialect:

- Every identifier except a string identifier is at most 128 characters: rule names, rule tags, meta keys, `for` and `with` variables, and any other bare identifier. A longer one is `yara_parse_error`, as libyara refuses it as a syntax error. String identifiers (`$name`, and `#name`, `@name`, `!name`) have no such limit in libyara 4.5 or YARA-X.
- An `import` applies to the rules after it. A module used in a rule before its `import` is `yara_module_not_imported`.

| Engine verdict | Report |
|----------------|--------|
| libyara 4.5 refuses to compile it | error |
| libyara compiles it and YARA-X 1.x refuses it (a stray `{` or an unknown escape such as `\R` in a regexp, `@a[-1]`, `base64` on fewer than 3 characters, `entrypoint`, a repeated `global` or `private`, a rule named like an imported module) | warning `yara_x_incompatible` |
| Syntax only YARA-X accepts (`.len()`, hex and octal jump bounds, booleans inside `of` tuples) | error. The message names the YARA-X feature. |
| A libyara compile warning | warning |

Each profile names its `dialect`. Every profile today is `libyara4`. A later revision may move one platform to `yara_x` without changing this language.

### Modules

The engine knows 13 modules, with their fields, functions, overloads, and types: `pe`, `elf`, `math`, `hash`, `time`, `dotnet`, `macho`, `magic`, `cuckoo`, `console`, `string`, `lnk`, and `dex`. Each profile names the modules confirmed on its agents. Importing a known module outside that set is the warning `yara_module_unconfirmed`. Importing a module the engine does not know is the error `yara_unknown_module`.

### Diagnostics

#### Errors

| Code | Condition |
|------|-----------|
| `yara_parse_error` | Syntax error, including an identifier other than a string identifier longer than 128 characters |
| `yara_include` | An `include` directive |
| `yara_signature_alias` | `signature` is a YAML alias instead of its own text |
| `yara_empty_signature` | No YARA rule, or only `private` or `global` rules |
| `yara_duplicate_rule` | Two YARA rules with one name in a `signature` |
| `yara_duplicate_string` | Two strings with one identifier in a rule (the anonymous `$` excepted) |
| `yara_duplicate_tag` | A rule tag repeated on one rule |
| `yara_undefined_string` | A `$id`, `#id`, `@id`, `!id`, or `$prefix*` in a condition that matches no string of the rule |
| `yara_unreferenced_string` | A string never used in the condition, when the condition does not use `them` (libyara refuses it) |
| `yara_undefined_identifier` | A bare identifier that is neither a rule defined earlier in the `signature` nor a module |
| `yara_rule_identifier_conflict` | A rule named like a YARA keyword |
| `yara_unknown_module` | `import` of a module libyara does not ship |
| `yara_module_not_imported` | A module field or function used without an `import` of the module before the rule |
| `yara_unknown_module_member` | A field or function the module does not have, or the wrong arguments |
| `yara_type` | An operator or function applied to the wrong type (`filesize contains "a"`) |
| `yara_regexp` | An invalid regular expression |
| `yara_hex_string` | An invalid hex string: odd nibbles, a bad jump `[a-b]`, unbalanced alternatives |
| `yara_string_modifier` | A modifier combination libyara refuses (`base64` with `nocase`, `xor` on a hex string), or an `xor`/`base64` argument out of range |
| `yara_number_out_of_range` | An integer literal, size suffix, jump bound, or string index out of libyara's range |

#### Warnings

| Code | Condition |
|------|-----------|
| `yara_x_incompatible` | libyara compiles it and YARA-X 1.x does not. The message says what YARA-X refuses. |
| `yara_slow_pattern` | libyara's slow-scanning warnings: a short or all-wildcard atom, a regexp with no fixed atom, a hex jump too wide to scan fast |
| `yara_entrypoint_deprecated` | `entrypoint`, deprecated in libyara (use `pe.entry_point` or `elf.entry_point`) and refused by YARA-X |
| `yara_suspicious_expression` | An invariant or unsatisfiable condition, a non-boolean condition, or an integer compared with a boolean. A condition is non-boolean where YARA-X 1.x reports `non_bool_expr`: an integer, float, or string expression. A module member YARA-X types as boolean (`pe.is_dll()`, `pe.is_32bit()`, `pe.exports(…)`) is boolean, although libyara returns it as an integer. |
| `yara_module_unconfirmed` | A known module outside the profile's confirmed set |
| `yara_meta_missing` | A meta key the profile recommends is missing on a non-private rule |

Codes are stable. The language server's `docs/YARA.md` maps each one to the libyara source and the test that proves it, as `docs/FALCO.md` does for Falco.

### Platform profiles

| | `bitdefender` | `harfanglab` |
|---|---|---|
| Dialect | `libyara4` | `libyara4` |
| Characters | ASCII only | UTF-8 |
| Size | at most 30,000 characters | no documented limit |
| YARA rules per `signature` | one or more | one or more |
| Confirmed modules | `pe`, `elf`, `math`, `hash`, `time` | `pe`, `elf`, `math`, `hash`, `time` |
| Recommended meta | none | `context` on every non-private rule |
| Profile codes | `bitdefender_yara_ascii`, `bitdefender_yara_size` (errors) | `harfanglab_yara_context` (warning) |

A platform spec states its profile codes. Neither vendor publishes its engine version or module list. The confirmed module sets are a maintainer decision (2026-11-10), and the Bitdefender engine is libyara by its agent's open-source notices ([RFC 0015](../../rfcs/0015-yara-language.md#bitdefender-yara)).

## Relationships

- [harfanglab-1.0](../platforms/harfanglab-1.0.md): `configurations.harfanglab.yara.signature`, and the decomposed form checked as the rule deploy assembles it
- [platforms](../platforms/index.md): capability matrix and static-validation bar
- [validation.md](../validation.md): errors, warnings, and offline checks
- [RFC 0015](../../rfcs/0015-yara-language.md): design and research
- [RFC 0014](../../rfcs/0014-sysdig-falco-platform.md): the engine pattern this follows

## Defaults & overrides

| Setting | Default |
|---------|---------|
| Dialect | `libyara4`, per profile |
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

Fixtures: [fixtures/platforms/harfanglab-yara-signature.yaml](../../fixtures/platforms/harfanglab-yara-signature.yaml); invalid: [rule-yara-signature-alias.yaml](../../fixtures/invalid/rule-yara-signature-alias.yaml), [rule-harfanglab-yara-include.yaml](../../fixtures/invalid/rule-harfanglab-yara-include.yaml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-11-10 | Initial language spec ([RFC 0015](../../rfcs/0015-yara-language.md)): `YaraSignature`, the libyara 4.5 dialect with YARA-X warnings, diagnostics codes, and the `bitdefender` and `harfanglab` profiles. Answers the YARA questions of [specifications#68](https://github.com/opentidehq/specifications/issues/68). |
| 1.1 | 2026-11-10 | Clarifications from the first implementation review, checked against libyara 4.5.4 and YARA-X 1.23: identifiers are at most 128 characters (`yara_parse_error`); an `import` must come before the rule that uses the module; a rule named like an imported module is `yara_x_incompatible` (libyara compiles it), so `yara_rule_identifier_conflict` covers keywords only; a `yara_x_incompatible` message says what YARA-X refuses rather than quoting it; `yara_slow_pattern` names libyara's own warnings only. No code is added or removed. |
| 1.2 | 2026-11-10 | Clarifications from the second implementation review, checked against libyara 4.5.4 and YARA-X 1.23: the 128-character limit applies to rule names, rule tags, and meta keys, not to string identifiers; a non-boolean condition for `yara_suspicious_expression` is what YARA-X reports as `non_bool_expr`, so module members YARA-X types as boolean do not warn. No code is added or removed. |
| 1.3 | 2026-11-10 | Clarification from the third implementation review, checked against libyara 4.5.4 and YARA-X 1.23: the 128-character limit covers every identifier except string identifiers, including `for` and `with` variables, not only rule names, rule tags, and meta keys. No code is added or removed. |
| 1.4 | 2026-11-10 | `opentide validate query` checks YARA offline (signatures, and `.yar`/`.yara` files under the platform's profile); `--live` stays `supported: false`. Matches [validation 1.9](../validation.md#query-validation). No code is added or removed. |
