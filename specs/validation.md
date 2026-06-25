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

When `schema` is enabled, for each in-scope object:

1. **Pydantic load** — `load_object_for_validation()` using declared `metadata.schema`
2. **Vocabulary** — `validate_object_vocab_from_metaschema()` against indexed metaschemas
3. **Deprecation** — `validate_deprecated_fields_from_metaschema()` (warnings)
4. **References** — `check_references_for_object()` resolves `references` links
5. **Chaining** — `check_chaining_for_object()` for threat vectors only

### Validation scope

| Mode | Behavior |
|------|----------|
| `full` | All objects in the workspace index |
| `narrow` | Filter by `--file`, `--uuid`, and/or `--type` |

Empty narrow scope with filters MUST emit a `scope_no_match` error.

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
| [fixtures/valid/rule-1.0.yaml](../fixtures/valid/rule-1.0.yaml) | Passes schema + UUID checks |
| [fixtures/invalid/rule-bad-uuid.yaml](../fixtures/invalid/rule-bad-uuid.yaml) | Fails `uuid-format` |
| [fixtures/invalid/rule-unknown-schema.yaml](../fixtures/invalid/rule-unknown-schema.yaml) | Fails `schema` |
| [fixtures/cross-object/rule-references-objective.yaml](../fixtures/cross-object/rule-references-objective.yaml) | Passes when sibling objective fixture present |

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial spec from opentide `validation/session.py` |
