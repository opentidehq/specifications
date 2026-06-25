---
spec: versioning
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Versioning

## Summary

OpenTide separates **structural schema revisions** from **object instance versions**. Schema revisions select the validation model and generated JSON Schema artifact; instance versions track business content evolution in git.

## Requirements

- Every Tide object MUST declare `metadata.schema` as a registered schema identifier (`{family}::{major}.{minor}`).
- Every Tide object MUST declare `metadata.version` as a business version (semver string or integer).
- Consumers MUST NOT use `metadata.version` to select a JSON Schema file.
- Multiple schema revisions for the same family MAY coexist in a workspace (e.g. `rule::1.0` and `rule::1.1`).
- Breaking structural changes MUST introduce a new schema identifier and a new spec file version in this repository.
- Git history is the authoritative record of instance content changes; no `revisions.json` indexer is required.

## Definition

### Schema identifier

| Component | Format | Example |
|-----------|--------|---------|
| Family | lowercase object type | `rule`, `threat`, `objective` |
| Revision | `{major}.{minor}` | `1.0` |
| Full identifier | `{family}::{major}.{minor}` | `rule::1.0` |

### Artifact naming

| Artifact | Path pattern | Example |
|----------|--------------|---------|
| JSON Schema | `.opentide/schemas/{family}.{major}.{minor}.schema.json` | `rule.1.0.schema.json` |
| YAML template | `.opentide/templates/{family}.{major}.{minor}.template.yaml` | `rule.1.0.template.yaml` |
| IDE router | `.opentide/schemas/opentide.schema.json` | routes `objects/**/*.yaml` by `metadata.schema` |

### Runtime routing

1. **Registry** — maps `rule::1.0` → validation model (single source of truth in opentide).
2. **Load** — reads `metadata.schema`, resolves model, optionally migrates via `SchemaVersionChain`, validates with Pydantic.
3. **Validate** — `opentide validate` checks every object against its declared schema identifier.
4. **Index** — scans `.opentide/schemas/*.schema.json` into `framework_schemas` and `json_schemas` keyed by identifier.

Each per-version JSON Schema pins `metadata.schema` as a `const` for IDE discrimination.

## Relationships

- [metadata.md](metadata.md) — defines `metadata.schema` and `metadata.version` fields
- [workspace.md](workspace.md) — paths for schemas, templates, and object directories
- Object specs under `objects/` — one spec per active schema revision

## Defaults & overrides

Path defaults are configured in bundled `paths.toml`; clients MAY override via [configuration.md](configuration.md). Schema artifacts under `.opentide/schemas/` MUST NOT be hand-edited.

## Examples

- Valid rule declaring `schema: rule::1.0`: [fixtures/valid/rule-1.0.yaml](../fixtures/valid/rule-1.0.yaml)
- Invalid unknown schema: [fixtures/invalid/rule-unknown-schema.yaml](../fixtures/invalid/rule-unknown-schema.yaml)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial spec bootstrapped from opentide `SCHEMA_REVISION.md` |
