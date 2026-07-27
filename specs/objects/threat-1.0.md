---
spec: threat
version: "1.0"
schema_id: threat::1.0
status: normative
supersedes: null
---

# Threat vector (TVM)

## Summary

A threat vector describes an adversary capability or scenario: severity, impact, ATT&CK mapping, and optional chaining relationships. Schema identifier: `threat::1.0`.

## Requirements

- The document MUST declare `metadata.schema: threat::1.0`.
- `name` and `criticality` MUST be present at the top level.
- `threat` body MUST be present with all required subfields.
- `threat.att&ck` MUST be a non-empty list of ATT&CK technique references (YAML key `att&ck`; aliased as `att_ck` in Pydantic).
- `references` MAY be omitted.
- `threat.terrain` MUST be a non-empty explanatory string describing where and how the threat operates.
- `threat.surface` MUST be a non-empty list of `surface::1.0` vocabulary values.
- `threat.chaining` entries MUST reference valid chaining relation vocabulary values when present.

## Definition

### Top level (ThreatVector)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Threat vector display name |
| `criticality` | string | yes | — | Criticality vocabulary value |
| `metadata` | ObjectMetadata | yes | — | See [metadata.md](../metadata.md) |
| `threat` | ThreatBody | yes | — | Threat assessment body |
| `references` | ObjectReferences | no | null | External and internal references |

### `threat` (ThreatBody)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `description` | string | yes | — | Narrative description |
| `severity` | string | yes | — | Threat severity vocabulary |
| `impact` | string | yes | — | Impact vocabulary |
| `leverage` | string | yes | — | Leverage vocabulary |
| `viability` | string | yes | — | Viability vocabulary |
| `terrain` | string | yes | — | Explanatory narrative about where/how the threat operates |
| `surface` | list[string] | yes | — | Threat surface vocabulary values (`surface::1.0`) |
| `att&ck` | list[string] | yes | — | MITRE ATT&CK technique IDs |
| `actors` | list[string] | no | null | Threat actor vocabulary values |
| `killchain` | string \| list[string] | no | null | Kill chain stage(s) |
| `chaining` | list[ChainingEntry] | no | null | Vector chaining relationships |

### `chaining` entry

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| (relation keys) | string | per entry | Chaining relation from `chaining_relations` vocabulary |

## Relationships

- [metadata.md](../metadata.md) — shared metadata block
- [objective-1.0.md](objective-1.0.md) — objectives MAY reference threat UUIDs in `objective.threats`
- [rule-1.0.md](rule-1.0.md) — rules link to objectives via `detection_model`
- Vocabularies: `criticality`, `severity`, `impact`, `leverage`, `viability`, `surface`, `att&ck`, `actors`, `killchain`, `chaining_relations`

## Defaults & overrides

No object-level configuration overrides. Vocabulary values are canonical in `vocabularies/`. See [configuration.md](../configuration.md).

## Examples

- Valid: [fixtures/valid/threat-1.0.yaml](../../fixtures/valid/threat-1.0.yaml)
- Invalid (missing threat body): [fixtures/invalid/threat-missing-body.yaml](../../fixtures/invalid/threat-missing-body.yaml)
- Cross-reference: [fixtures/cross-object/objective-references-threat.yaml](../../fixtures/cross-object/objective-references-threat.yaml)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial spec from opentide `models/threat.py` |
