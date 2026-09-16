---
spec: validation
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Validation

## Summary

OpenTide validates detection content through a structured pipeline: ID uniqueness, UUID format, Pydantic schema validation, vocabulary conformance, deprecated field warnings, and cross-object reference checks. Optional checks include CVE scanning and per-platform query validation.

## Requirements

- `opentide validate` MUST run default checks: `id-uniqueness`, `uuid-format`, `schema`.
- Schema validation MUST load each object via `metadata.schema` and validate against the registered Pydantic model.
- Vocabulary validation MUST walk metaschema `tide.vocab` annotations for each object type.
- UUID values MUST be UUID version 4.
- Object UUIDs MUST be unique across the workspace registry.
- Cross-object references MUST resolve to existing objects when checked.
- Threat `chaining` relationships MUST reference valid targets when checked.
- Query validation MUST only be offered for platforms in the query-validation allowlist (see [platforms.md](platforms.md)).
- Platforms without query validators MUST return `supported: false` — not fake success.

## Definition

### Check types (`ValidateCheck`)

| Check | Identifier | Default | Description |
|-------|------------|---------|-------------|
| ID uniqueness | `id-uniqueness` | yes | No duplicate `metadata.uuid` across YAML files |
| UUID format | `uuid-format` | yes | Every UUID must be valid UUIDv4 |
| Schema | `schema` | yes | Pydantic model validation + vocab + cross-ref |
| CVE | `cve` | no | CVE reference integrity (optional flag) |

### Schema check sub-steps

When `schema` is enabled, for each in-scope object the implementation MUST, in order:

1. **Load and model-validate** — resolve the object's `metadata.schema` and validate it against the registered model.
2. **Vocabulary** — check controlled-vocabulary fields against the indexed metaschema vocabulary annotations.
3. **Deprecation** — flag deprecated fields as warnings.
4. **References** — resolve `references` links to existing objects.
5. **Chaining** — resolve chaining relationships (threat vectors only).

Steps 4 and 5 resolve cross-object links; they run whenever the `schema` check runs against a full workspace scope where the referenced objects are present.

### Validation scope

| Mode | Behavior |
|------|----------|
| `full` | All objects in the workspace index |
| `narrow` | Filter by `--file`, `--uuid`, and/or `--type` |

When `--file`, `--uuid`, or `--type` filters match no objects, validation MUST emit a `scope_no_match` error rather than silently passing — a filter that selects nothing is treated as a mistake, not a success.

### Query validation

Command: `opentide validate query --platform <id>`

| Platform | Supported |
|----------|-----------|
| `sentinel` | yes |
| `defender_for_endpoint` | yes |
| `splunk` | yes |
| `sentinel_one` | yes |
| `carbon_black_cloud` | yes |
| `crowdstrike` | no |
| `harfanglab` | no |

Requires platform credentials and enabled configuration. Validates deployed or planned rule queries against the live platform API.

### Specifications-repo fixture checker

This repository’s CI (`scripts/object_fixtures.py`) is **not** `opentide validate`. It proves object-spec field types against fixtures without a Pydantic runtime. Codes below are checker codes; they are distinct from the `ValidateCheck` identifiers (`uuid-format`, `schema`, …).

| Fixture | Checker code |
|---------|--------------|
| [fixtures/invalid/threat-impact-as-string.yaml](../fixtures/invalid/threat-impact-as-string.yaml) | `field_not_list` |
| [fixtures/invalid/threat-leverage-semicolon.yaml](../fixtures/invalid/threat-leverage-semicolon.yaml) | `packed_vocab_string` |
| [fixtures/invalid/threat-impact-semicolon.yaml](../fixtures/invalid/threat-impact-semicolon.yaml) | `packed_vocab_string` |
| [fixtures/invalid/threat-leverage-semicolon-list-item.yaml](../fixtures/invalid/threat-leverage-semicolon-list-item.yaml) | `packed_vocab_string` |
| [fixtures/invalid/threat-impact-empty.yaml](../fixtures/invalid/threat-impact-empty.yaml) | `empty_vocab_list` |
| [fixtures/invalid/threat-leverage-empty.yaml](../fixtures/invalid/threat-leverage-empty.yaml) | `empty_vocab_list` |
| [fixtures/invalid/threat-leverage-high.yaml](../fixtures/invalid/threat-leverage-high.yaml) | `unknown_vocab_value` |
| [fixtures/invalid/threat-actors-string-list.yaml](../fixtures/invalid/threat-actors-string-list.yaml) | `actors_not_objects` |
| [fixtures/invalid/threat-actors-not-list.yaml](../fixtures/invalid/threat-actors-not-list.yaml) | `actors_not_objects` |
| [fixtures/invalid/threat-actor-missing-name.yaml](../fixtures/invalid/threat-actor-missing-name.yaml) | `actor_missing_name` |
| [fixtures/invalid/threat-actor-unscoped.yaml](../fixtures/invalid/threat-actor-unscoped.yaml) | `actor_unscoped` |
| [fixtures/invalid/threat-actor-wrong-stage.yaml](../fixtures/invalid/threat-actor-wrong-stage.yaml) | `actor_unknown` |
| [fixtures/invalid/threat-missing-body.yaml](../fixtures/invalid/threat-missing-body.yaml) | `missing_threat_body` |
| [fixtures/invalid/rule-bad-uuid.yaml](../fixtures/invalid/rule-bad-uuid.yaml) | `invalid_uuid` |
| [fixtures/invalid/rule-unknown-schema.yaml](../fixtures/invalid/rule-unknown-schema.yaml) | `unknown_schema` |
| [fixtures/invalid/rule-missing-metadata.yaml](../fixtures/invalid/rule-missing-metadata.yaml) | `missing_metadata` |
| [fixtures/invalid/objective-no-signals.yaml](../fixtures/invalid/objective-no-signals.yaml) | `empty_signals` |

A packed semicolon string that happens to start with a valid token MUST still fail `packed_vocab_string`. Accepting only the first token is lossy and non-compliant.

### Issue severities

| Severity | Examples |
|----------|----------|
| `error` | Schema failure, duplicate UUID, invalid UUID, broken cross-ref |
| `warning` | Deprecated field usage |

### Environment signals

| Variable | Set when |
|----------|----------|
| `VALIDATION_ERROR_RAISED` | One or more errors |
| `VALIDATION_WARNING_RAISED` | One or more warnings |

### Parallel execution

Validation MAY parallelize per-object work and ID scans; worker count is resolved from object count and optional `--workers` flag.

## Relationships

- [metadata.md](metadata.md) — UUID and schema requirements
- [versioning.md](versioning.md) — schema routing at validation time
- [vocabularies/format.md](vocabularies/format.md) — vocabulary conformance
- [metaschema-keywords.md](metaschema-keywords.md) — `tide.vocab`, `tide.meta.deprecation`
- [platforms.md](platforms.md) — query validation allowlist
- Object specs — field requirements validated by Pydantic

## Defaults & overrides

Validation uses merged configuration for vocabulary and status enums. No separate validation config file. Scope defaults to full workspace.

## Examples

| Fixture | Expected result |
|---------|-----------------|
| [fixtures/valid/rule-1.0.yaml](../fixtures/valid/rule-1.0.yaml) | Passes `uuid-format` + `schema` (`opentide validate`) |
| [fixtures/valid/threat-1.0.yaml](../fixtures/valid/threat-1.0.yaml) | Passes `threat::1.0` lists (`impact`, `leverage`) and `list[ThreatActor]` |
| [fixtures/invalid/rule-bad-uuid.yaml](../fixtures/invalid/rule-bad-uuid.yaml) | Fails `uuid-format` (`opentide validate`); checker code `invalid_uuid` |
| [fixtures/invalid/rule-unknown-schema.yaml](../fixtures/invalid/rule-unknown-schema.yaml) | Fails `schema` (`opentide validate`); checker code `unknown_schema` |
| [fixtures/cross-object/rule-references-objective.yaml](../fixtures/cross-object/rule-references-objective.yaml) | Passes when sibling objective fixture present |

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-16 | Document specifications-repo fixture checker codes for `threat::1.0` list/`ThreatActor` encoding ([#11](https://github.com/OpenTideHQ/specifications/issues/11), [#12](https://github.com/OpenTideHQ/specifications/issues/12)). |
| 1.0 | 2026-06-25 | Initial spec from opentide `validation/session.py` |
