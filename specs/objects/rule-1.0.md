---
spec: rule
version: "1.0"
schema_id: rule::1.0
status: normative
supersedes: null
---

# Detection rule (MDR)

## Summary

A detection rule (MDR — Managed Detection Rule) is the deployable unit of detection content: metadata, severity, ATT&CK techniques, platform-specific query configurations, optional response playbook, and lifecycle status. Schema identifier: `rule::1.0`.

This document is the **exemplar spec** — all object specs follow the same section order and level of detail.

## Requirements

- The document MUST declare `metadata.schema: rule::1.0`.
- `name`, `metadata`, and `description` MUST be present.
- `status` MUST be a valid deployment status from [deployment.md](../deployment.md) (default: `STAGING`).
- `severity` MUST be a valid rule severity vocabulary value (default: `Informational`).
- `techniques` MUST be a list of ATT&CK technique IDs (MAY be empty).
- `platforms` or `configurations` MUST contain at least one enabled platform block for deployable rules.
- `detection_model` when present MUST reference a valid objective UUID.
- Platform blocks MUST validate against the platform schema identifier declared in each block's `schema` field.
- `references` MAY be omitted.
- Registry-backed methods (`deploy`, `validate`, `document`) require a bound opentide registry at runtime — not part of static YAML validation.

## Definition

### Top level (DetectionRule)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Rule display name |
| `metadata` | ObjectMetadata | yes | — | See [metadata.md](../metadata.md) |
| `description` | string | yes | — | Rule narrative (multiline YAML encouraged) |
| `status` | string | no | `STAGING` | Deployment lifecycle status |
| `severity` | string | no | `Informational` | Rule severity vocabulary |
| `techniques` | list[string] | no | `[]` | MITRE ATT&CK technique IDs |
| `platforms` | map[string, object] | no | `{}` | Legacy flat platform dict (prefer `configurations`) |
| `configurations` | RuleConfigurations | no | null | Typed per-platform configuration blocks |
| `references` | ObjectReferences | no | null | External and internal references |
| `detection_model` | string | no | null | Objective UUID this rule implements |
| `response` | RuleResponse | no | null | Alert and response configuration |

### `response` (RuleResponse)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `alert_severity` | string | no | `Informational` | Alert severity vocabulary |
| `playbook` | string | no | null | Playbook identifier or URL |
| `responders` | string | no | null | Responder team vocabulary |
| `procedure` | ResponseProcedure | no | null | Analysis and containment procedure |

### `procedure` (ResponseProcedure)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `analysis` | string | yes | Analysis steps narrative |
| `searches` | list[ResponseSearch] | no | Supplemental hunt searches |
| `containment` | string | no | Containment guidance |

### `searches[]` (ResponseSearch)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `purpose` | string | yes | Why this search is run |
| `system` | string | yes | Target platform or system |
| `query` | string | yes | Query text |

### Platform block (PlatformConfigBase)

Shared fields on every platform configuration:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | boolean | no | `false` | Whether this platform block is active |
| `name` | string | no | `""` | Platform-specific rule name |
| `schema` | string | no | null | Platform schema ID, e.g. `platform::sentinel::1.0` |
| `status` | string | no | null | Platform-specific deployment status |
| `flags` | list[string] | no | null | Platform flags |
| `tenants` | list[string] | no | null | Target tenant identifiers |
| `contributors` | list[string] | no | null | Platform contributors |

### `configurations` (RuleConfigurations)

Typed optional blocks keyed by platform identifier:

| Key | Model | Schema ID |
|-----|-------|-----------|
| `sentinel` | SentinelConfig | `platform::sentinel::1.0` |
| `defender_for_endpoint` | DefenderConfig | `platform::defender_for_endpoint::1.0` |
| `splunk` | SplunkConfig | `platform::splunk::1.0` |
| `sentinel_one` | SentinelOneConfig | `platform::sentinel_one::1.0` |
| `crowdstrike` | CrowdstrikeConfig | `platform::crowdstrike::1.0` |
| `harfanglab` | HarfangLabConfig | `platform::harfanglab::1.0` |
| `carbon_black_cloud` | CarbonBlackConfig | `platform::carbon_black_cloud::1.0` |

See [platforms.md](../platforms.md) for per-platform required fields and capabilities.

## Relationships

- [metadata.md](../metadata.md) — identity and schema routing
- [objective-1.0.md](objective-1.0.md) — linked via `detection_model`
- [deployment.md](../deployment.md) — `status` lifecycle and promotion
- [platforms.md](../platforms.md) — platform blocks and deploy/validate capabilities
- [validation.md](../validation.md) — schema, vocabulary, and query validation
- Vocabularies: `severity`, `alert_severity`, `att&ck`, `responders`, deployment statuses

## Defaults & overrides

| Setting | Source | Override |
|---------|--------|----------|
| Default `status` | `STAGING` | Per-rule YAML |
| Status enum | `deployment.toml` | `.opentide/configurations/deployment.toml` |
| Platform defaults | bundled `platforms/*.toml` | `.opentide/configurations/platforms/` |
| Template description default | `schema.toml` | `.opentide/configurations/schema.toml` |

Vocabulary files are canonical in `vocabularies/` — not overridable. See [configuration.md](../configuration.md).

## Examples

### Valid fixtures

| Fixture | Demonstrates |
|---------|--------------|
| [fixtures/valid/rule-1.0.yaml](../../fixtures/valid/rule-1.0.yaml) | Minimal valid rule with Sentinel configuration |
| [fixtures/cross-object/rule-references-objective.yaml](../../fixtures/cross-object/rule-references-objective.yaml) | `detection_model` → objective UUID |

### Invalid fixtures

| Fixture | Violation |
|---------|-----------|
| [fixtures/invalid/rule-missing-metadata.yaml](../../fixtures/invalid/rule-missing-metadata.yaml) | Missing required `metadata` |
| [fixtures/invalid/rule-unknown-schema.yaml](../../fixtures/invalid/rule-unknown-schema.yaml) | Unregistered `metadata.schema` |
| [fixtures/invalid/rule-bad-uuid.yaml](../../fixtures/invalid/rule-bad-uuid.yaml) | Non-UUIDv4 `metadata.uuid` |

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial exemplar spec from opentide `models/rule.py` |
