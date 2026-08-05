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

An implementation MUST route objects to validation by their declared identifier:

1. **Resolve** — read `metadata.schema` and select the validation model registered for that identifier.
2. **Migrate (optional)** — an object MAY be migrated from an older revision to a newer one before validation.
3. **Validate** — check the object against the model for its declared identifier.
4. **Index** — expose the generated `.opentide/schemas/*.schema.json` artifacts keyed by identifier.

Each per-revision JSON Schema MUST pin `metadata.schema` as a `const` so editors and the router can discriminate objects by revision.

### Multi-version coexistence

Schema revisions are additive; two revisions of a family MAY be active in one workspace at once. When a new revision such as `rule::1.1` ships:

1. A new validation model is registered for `rule::1.1` alongside the existing `rule::1.0`.
2. A migration path from `rule::1.0` to `rule::1.1` MAY be provided by the implementation.
3. `opentide generate schemas` emits **both** artifacts, and the IDE router adds a branch per identifier.
4. Objects opt in individually by setting `metadata.schema`; objects still declaring `rule::1.0` continue to validate against `1.0` until migrated.

A schema upgrade therefore MUST NOT require a repository-wide migration in a single step.

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
