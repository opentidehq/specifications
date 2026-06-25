---
spec: vocabulary-format
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Vocabulary format

## Summary

OpenTide vocabularies are TOML files (`.vocab.toml`) defining allowed enum values for object and configuration fields. Canonical copies live in `vocabularies/`; opentide bundles them at build time.

## Requirements

- Every vocabulary file MUST validate against [schemas/vocabulary.schema.json](../../schemas/vocabulary.schema.json).
- Every vocabulary file MUST declare `name` and `field` at the top level.
- Entry keys MUST be declared in `[[keys]]` tables unless using `stages` for scoped vocabularies.
- Clients MUST NOT override vocabulary files in `.opentide/configurations/`; extensions use `schema.toml` `[[vocabulary.*]]` entries only.
- The `field` value MUST match the YAML/JSON field path the vocabulary constrains (e.g. `tlp`, `att&ck`, `detection.methodology`).
- Sync direction MUST be **specifications → opentide** (canonical data originates here).

## Definition

### Top-level properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `name` | string | yes | Human-readable vocabulary name |
| `field` | string | yes | Field path this vocabulary applies to |
| `description` | string | no | Vocabulary description |
| `icon` | string | no | Display icon for UI/schema generation |
| `key` | `"name"` \| `"id"` | no | Whether entries are keyed by `name` or `id` (default: name-based) |
| `model` | boolean | no | When true, vocabulary models a nested object type |
| `keys` | array of KeyEntry | no | Enum entries |
| `stages` | array | no | Scoped stage identifiers for multi-stage vocabularies |

### `[[keys]]` entry

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `id` | string | no | Stable identifier (e.g. `TLP:AMBER`) |
| `name` | string | yes* | Display/slug value used in YAML |
| `description` | string | no | Entry description (markdown in schema) |
| `icon` | string | no | Entry icon |
| `misp` | string | no | MISP taxonomy mapping |
| `tide.vocab.stages` | string \| list | no | Stage scope for this entry |

\* Required when `key = "name"` (default).

### Staged vocabularies

Entries MAY be scoped to lifecycle stages via `tide.vocab.stages`. Metaschema fields use `tide.vocab.scoped` and `tide.vocab.stages` keywords to filter allowed values at generation and validation time.

### Example file

```toml
name = "Traffic Light Protocol"
field = "tlp"
description = "TLP classification for information sharing."
key = "name"

[[keys]]
id = "TLP:CLEAR"
name = "clear"
description = "Recipients can spread this to the world."
```

## Relationships

- [catalog.md](catalog.md) — index of bundled vocabularies
- [metaschema-keywords.md](../metaschema-keywords.md) — `tide.vocab` keyword resolution
- [configuration.md](../configuration.md) — `schema.toml` vocabulary extensions
- [validation.md](../validation.md) — vocabulary conformance checks

## Defaults & overrides

| Mechanism | Allowed? |
|-----------|----------|
| Edit `vocabularies/*.vocab.toml` here (via RFC) | Yes |
| Client copy of `.vocab.toml` in configurations | **No** |
| `schema.toml` `[[vocabulary.*]]` extension | Yes |

### opentide sync interface

| Location | Role |
|----------|------|
| `specifications/vocabularies/` | Canonical source (this repo) |
| `opentide/src/opentide/data/vocabulary/` | Runtime bundle (copied at build) |
| `schemas/vocabulary.schema.json` | Validation schema for TOML files |

The sync script is an opentide build concern; this spec defines the data contract only.

## Examples

- Canonical TLP vocabulary: [vocabularies/tlp.vocab.toml](../../vocabularies/tlp.vocab.toml)
- JSON Schema: [schemas/vocabulary.schema.json](../../schemas/vocabulary.schema.json)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial spec from opentide `vocabulary.schema.json` |
