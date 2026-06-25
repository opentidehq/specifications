---
spec: metaschema-keywords
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Metaschema keywords

## Summary

OpenTide extends JSON Schema generation with `tide.*` keywords in Pydantic metaschema. At generation time, `gen_json_schema()` walks the metaschema depth-first and resolves each keyword into standard JSON Schema constructs. Keywords are stripped from emitted client-facing schemas via `strip_framework_keywords()`.

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
| `tide.vocab` | string, bool, or list | Resolve vocabulary file(s) to `enum` + `markdownEnumDescriptions` |
| `tide.vocab.scoped` | boolean | Enable stage-scoped vocabulary filtering |
| `tide.vocab.stages` | string \| list | Filter vocabulary entries to matching stages |
| `tide.vocab.hints.no-wrap` | boolean | Disable enum value wrapping in descriptions |

When `tide.vocab` is `true`, the field name is used as the vocabulary identifier.

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

- [vocabularies/format.md](vocabularies/format.md) — vocabulary file format
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

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial spec from opentide `generation/schema_pipeline.py` and `pydantic_metaschema.py` |
