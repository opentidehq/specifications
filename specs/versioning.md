---
spec: versioning
version: "1.1"
schema_id: null
status: normative
supersedes: null
---

# Versioning

## Summary

`metadata.schema` says which shape an object has. `metadata.version` says how that object's content has changed. They are not interchangeable.

A workspace may contain more than one shape of the same object at once (`rule::1.0` next to `rule::2.0`, `threat::1.0` next to a later threat revision). Validation, deployment, and every other feature MUST follow the shape the file declares. Supporting a revision means the whole product can read it, not only the schema check.

## Requirements

- Every Tide object MUST declare `metadata.schema` as a registered schema identifier (`{family}::{major}.{minor}`).
- Every Tide object MUST declare `metadata.version` as a business version (semver string or integer).
- Consumers MUST NOT use `metadata.version` to choose a schema.
- More than one revision of the same family MAY coexist in one workspace.
- A breaking structural change MUST introduce a new schema identifier and a new spec file. The previous revision stays valid for files that still declare it.
- Git is the history of instance content. No `revisions.json` indexer is required.
- An implementation MUST register a model for every schema identifier it claims to support. A class or pin table that is not registered is not a supported revision.
- Validation, deployment, documentation, export, query validation, promotion, sharing, and editor validation MUST use the model selected by `metadata.schema`. They MUST NOT assume a single shape per object family.
- A missing or unknown `metadata.schema` MUST be an error. The implementation MUST NOT substitute the newest revision of the family.
- Loading an object MUST check it as declared. Changing `metadata.schema` MUST be an explicit migration. Validate, deploy, and the other features MUST NOT rewrite it as a side effect.
- A migration, when the implementation provides one, MUST move forward only. It MUST set `metadata.schema` to the target revision and MUST NOT change `metadata.version`.
- Each registered revision MUST have its own JSON Schema and its own template. A filename that includes a revision (`rule.1.0.schema.json`) MUST contain that revision only.
- When a family has more than one registered revision, editor validation MUST choose the schema from `metadata.schema`. Mapping a whole object folder to one schema file is not enough.
- Authors adopt a new revision one object at a time. Shipping a revision MUST NOT require every file in the repository to change in one step.

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
| IDE router | `.opentide/schemas/opentide.schema.json` | routes objects by `metadata.schema` |

Each per-revision JSON Schema MUST pin `metadata.schema` as a `const`.

### How a feature reads an object

1. **Resolve** — read `metadata.schema` and take the registered model for that identifier.
2. **Check** — validate the object against that model.
3. **Use** — read fields where that revision puts them. A `rule::1.0` deploy reads `configurations.<platform>`. A later rule revision reads the platform block where its spec puts it. Description, status, and links follow the same rule.

Migration is not part of that read. It is a separate action that rewrites one object onto a newer revision and then stops. The next read follows the identifier the migration wrote.

### Coexistence

When a new revision ships, the previous one stays registered beside it. Generation emits an artifact for each. Objects opt in by setting `metadata.schema`. A file that still declares the old identifier keeps working, for deployment as well as validation, until someone migrates that file.

## Relationships

- [metadata.md](metadata.md) — `metadata.schema` and `metadata.version`
- [validation.md](validation.md) — the schema check is one consumer of this contract
- [deployment.md](deployment.md) — deployment is another; it uses the declared revision's fields
- [workspace.md](workspace.md) — where schemas and templates are written
- Object specs under `objects/` — one spec per revision

## Defaults & overrides

Path defaults live in bundled `paths.toml`. Clients MAY override paths via [configuration.md](configuration.md). They MUST NOT point two revisions at one schema file. Files under `.opentide/schemas/` MUST NOT be hand-edited.

## Examples

- A rule on `rule::1.0`: [fixtures/valid/rule-1.0.yaml](../fixtures/valid/rule-1.0.yaml)
- An unknown identifier: [fixtures/invalid/rule-unknown-schema.yaml](../fixtures/invalid/rule-unknown-schema.yaml)

A workspace that holds both of those rules, once a second rule revision exists, validates each against its own identifier and deploys each from the platform block that revision defines.

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.1 | 2026-09-30 | Every feature follows `metadata.schema`, not only validation. Missing schema is an error. Migration is explicit and does not change `metadata.version`. |
| 1.0 | 2026-06-25 | Initial spec bootstrapped from opentide `SCHEMA_REVISION.md` |
