---
spec: metaschema-keywords
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Metaschema keywords

## Summary

OpenTide extends JSON Schema generation with `tide.*` keywords in its metaschema. At generation time the implementation walks the metaschema depth-first and resolves each keyword into standard JSON Schema constructs; the `tide.*` keywords are then stripped from the emitted client-facing schemas.

<Callout type="info">
This spec is an **implementer contract** — it defines how JSON Schema is generated from the metaschema. Detection authors do not write `tide.*` keywords; they benefit from the generated schemas transparently. Read this only if you build tooling that generates or consumes OpenTide schemas.
</Callout>

## Requirements

- Implementations MUST resolve all `tide.*` keywords before emitting JSON Schema artifacts.
- Vocabulary keywords MUST resolve against canonical `vocabularies/` data.
- Configuration keywords MUST resolve against merged TOML configuration at generation time.
- Emitted JSON Schema MUST NOT contain unresolved `tide.*` keys.
- Object schemas MUST pin `metadata.schema` as a `const` for IDE router discrimination.

## Definition

### `tide.meta.*`

| Keyword | Value | Effect |
|---------|-------|--------|
| `tide.meta.definition` | `true` or model name | Inline a definition model schema (e.g. `metadata`, `references`) |
| `tide.meta.deprecation` | string message | Mark field deprecated in generated schema title/description |

### `tide.vocab.*`

| Keyword | Value | Effect |
|---------|-------|--------|
| `tide.vocab` | string, bool, or list | Resolve vocabulary contract(s) to `enum` + `markdownEnumDescriptions` |
| `tide.vocab.scoped` | boolean | Enable stage-scoped vocabulary filtering |
| `tide.vocab.stages` | string \| list | Filter vocabulary entries to matching stages |
| `tide.vocab.hints.no-wrap` | boolean | Disable enum value wrapping in descriptions |

#### `tide.vocab` resolution

| `tide.vocab` value | Behavior |
|--------------------|----------|
| `"severity"` (legacy unversioned) | Implementations SHOULD warn; resolve via schema pin for the field path |
| `"severity::1.0"` | Explicit vocabulary contract pin |
| `true` | Infer field name from property path → lookup schema pin |
| `["att&ck::1.0", "custom"]` | Union of contracts (existing list semantics + versions) |

When `tide.vocab` is `true`, the leaf field name is used as the vocabulary field identifier for pin lookup.

#### Schema pin resolution

Each object schema revision (`metadata.schema`, e.g. `threat::1.0`) maintains a vocabulary pin table in `schemas/pins/{threat,objective,rule}.toml`. Keys are dot-paths to vocab-constrained fields; values are versioned contract identifiers (`field::M.m`).

During JSON Schema generation and validation for schema `S`:

1. If `tide.vocab` is an explicit `field::M.m` string (or list of such), use it directly.
2. If `tide.vocab` is a bare field name or `true`, look up the pin for path `P` under section `[S]` in the family pin file.
3. Resolve the contract via per-key lifecycle rules in [vocabularies/format.md](vocabularies/format.md) (cumulative minor filter + `removed`).

Implementations MUST NOT resolve pins against the latest unversioned vocabulary when a schema revision is known. If a pinned contract is unavailable, generation and strict validation MUST fail with an explicit error.

### `tide.config.*`

| Keyword | Value | Effect |
|---------|-------|--------|
| `tide.config.visibility.logsources` | truthy | Inject logsources enum from visibility config |
| `tide.config.visibility.detectors` | truthy | Inject detectors enum from visibility config |
| `tide.config.parameter-list` | string path | Fetch enum values from configuration parameter list |
| `tide.config.systems::enabled` | truthy | Inject enabled platform identifiers |
| `tide.config.system.tenants` | platform id | Inject tenant list for a platform |
| `tide.config.statuses` | truthy | Inject deployment status names and descriptions |

### `tide.template.*`

| Keyword | Value | Effect |
|---------|-------|--------|
| `tide.template.force-required` | list[string] | Fields always required in YAML templates |
| `tide.template.hide` | boolean | Omit field from generated template |
| `tide.template.spacer` | boolean | Add blank line before field in template |
| `tide.template.multiline` | boolean | Use multiline YAML style |
| `tide.template.required` | boolean | Override required state in template |
| `tide.template.no-space` | boolean | Compact spacing in template |
| `tide.template.config.default` | config path | Default value from merged configuration |
| `tide.template.config.default.enabled` | boolean | Gate default value injection |
| `tide.template.config.required` | config path | Conditionally require field from config |

### `tide.mdr.parameter`

| Keyword | Value | Effect |
|---------|-------|--------|
| `tide.mdr.parameter` | string | Maps schema field to platform deployment parameter name (Splunk, etc.) |

### `tide.placeholders`

| Keyword | Value | Effect |
|---------|-------|--------|
| `tide.placeholders` | map[string, string] | Template placeholder substitutions (e.g. `SCHEMA_VERSION`) |

### `tide.object.*`

| Keyword | Value | Effect |
|---------|-------|--------|
| `tide.object.parent` | UUID | Parent object reference for indexing |

### `recomposition`

| Keyword | Value | Effect |
|---------|-------|--------|
| `recomposition` | identifier | Expand platform rule block from registered platform schema |

### Resolution order

1. `tide.meta.definition` — expand nested models first
2. `recomposition` — platform-specific property injection
3. `tide.config.*` — configuration-driven enums
4. `tide.vocab` — vocabulary enums
5. Recurse into nested objects
6. Strip remaining `tide.*` keys for output schema

## Relationships

- [vocabularies/format.md](vocabularies/format.md) — vocabulary file format and per-key lifecycle
- [schemas/pins/](../schemas/pins/) — per-schema vocabulary pin manifests
- [RFC 0003](../rfcs/0003-per-key-vocabulary-versioning.md) — per-key versioning design
- [configuration.md](configuration.md) — config sources for `tide.config.*`
- [deployment.md](deployment.md) — statuses for `tide.config.statuses`
- [platforms.md](platforms.md) — `recomposition` and platform schemas
- [validation.md](validation.md) — metaschema-driven vocabulary and deprecation walks

## Defaults & overrides

Configuration keywords reflect merged TOML at `opentide generate schemas` time. Client overrides affect generated enums. See [configuration.md](configuration.md).

## Examples

Rule metaschema binds `detection_model` to objective vocabulary:

```python
"detection_model": {"tide.vocab": "objective"}
```

Threat schema `threat::1.0` pins `threat.killchain` to `killchain::1.0` via [schemas/pins/threat.toml](../schemas/pins/threat.toml). A later `threat::2.1` revision may pin `killchain::1.1` while other pins remain at `::1.0`.

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.1 | 2026-06-26 | Versioned `tide.vocab` and schema pin resolution ([RFC 0003](../rfcs/0003-per-key-vocabulary-versioning.md)) |
| 1.0 | 2026-06-25 | Initial spec from opentide `generation/schema_pipeline.py` and `pydantic_metaschema.py` |
