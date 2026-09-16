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
- `threat.impact` MUST be a non-empty `list[string]` of `impact::1.0` vocabulary names.
- `threat.leverage` MUST be a non-empty `list[string]` of `leverage::1.0` vocabulary names.
- `threat.impact` and `threat.leverage` MUST be YAML lists of tokens. A scalar string is invalid. Implementations MUST NOT accept semicolon-concatenated strings (for example `Elevation of privilege; Repudiation`) as an encoding of multiple values, neither as the field value nor as a list item.
- `threat.actors` when present MUST be a `list[ThreatActor]`. A list of bare strings is invalid. There is no string-list alternate form and no coercion from strings to objects.
- Each `ThreatActor.name` MUST be a scoped `actors::1.0` value (`<stage>::<id>`, for example `att&ck::G0007` or `misp::<uuid>`). Unscoped ids are invalid.
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
| `impact` | list[string] | yes | — | Impact vocabulary names (`impact::1.0`); non-empty |
| `leverage` | list[string] | yes | — | Leverage vocabulary names (`leverage::1.0`); non-empty |
| `viability` | string | yes | — | Viability vocabulary |
| `terrain` | string | yes | — | Explanatory narrative about where/how the threat operates |
| `surface` | list[string] | yes | — | Threat surface vocabulary values (`surface::1.0`) |
| `att&ck` | list[string] | yes | — | MITRE ATT&CK technique IDs |
| `actors` | list[ThreatActor] | no | null | Threat actors; each entry is a `ThreatActor` object |
| `killchain` | string \| list[string] | no | null | Kill chain stage(s) |
| `chaining` | list[ChainingEntry] | no | null | Vector chaining relationships |

`terrain` and `surface` are complementary: `terrain` is free-form prose for humans; `surface` is the controlled vocabulary used for filtering and coverage. Do not put vocabulary tokens in `terrain`.

`impact` and `leverage` are multi-valued. Catalogue content that packed several tokens into one semicolon-separated string is **non-compliant**; migrate each token to its own list item. Do not collapse a packed string to its first token.

### `actors[]` (ThreatActor)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Scoped `actors::1.0` value: `att&ck::<id>` or `misp::<id>` |
| `sighting` | string | no | null | Optional sighting note or date |
| `references` | list[string] | no | null | Optional actor reference URLs |

The vocabulary pin for this field is `threat.actors.name` → `actors::1.0` (see [schemas/pins/threat.toml](../../schemas/pins/threat.toml)). Do not pin `threat.actors` as a list of bare strings.

Invalid (no coercion):

```yaml
threat:
  actors:
    - att&ck::G0007   # invalid: string, not ThreatActor
```

Valid:

```yaml
threat:
  actors:
    - name: att&ck::G0007
    - name: misp::5b4ee3ea-eee3-4c8e-8323-85ae32658754
      sighting: "2024-11-02"
      references:
        - https://attack.mitre.org/groups/G0007
```

### `chaining` entry

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| (relation keys) | string | per entry | Chaining relation from `chaining_relations` vocabulary |

## Relationships

- [metadata.md](../metadata.md) — shared metadata block
- [objective-1.0.md](objective-1.0.md) — objectives MAY reference threat UUIDs in `objective.threats`
- [rule-1.0.md](rule-1.0.md) — rules link to objectives via `detection_model`
- [schemas/pins/threat.toml](../../schemas/pins/threat.toml) — vocabulary pins for `threat::1.0` (`threat.actors.name`, `threat.impact`, `threat.leverage`, …)
- Vocabularies: `criticality`, `severity`, `impact`, `leverage`, `viability`, `surface`, `att&ck`, `actors`, `killchain`, `chaining_relations`

## Defaults & overrides

No object-level configuration overrides. Vocabulary values are canonical in `vocabularies/`. See [configuration.md](../configuration.md).

## Examples

```yaml
name: Simulated Actor
criticality: High
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  schema: threat::1.0
  version: 1
  created: "2026-01-01"
  modified: "2026-01-02"
  tlp: clear
threat:
  description: Simulated threat actor exercising credential access
  severity: Significant incident
  impact:
    - Data Breach
    - Identity Theft
  leverage:
    - Elevation of privilege
    - Repudiation
  viability: Likely
  terrain: Endpoint workstations and user devices.
  surface:
    - Windows::Desktop
  att&ck:
    - T1059
  actors:
    - name: att&ck::G0007
    - name: misp::5b4ee3ea-eee3-4c8e-8323-85ae32658754
      sighting: "2024-11-02"
      references:
        - https://attack.mitre.org/groups/G0007
```

- Valid: [fixtures/valid/threat-1.0.yaml](../../fixtures/valid/threat-1.0.yaml)
- Invalid (missing threat body): [fixtures/invalid/threat-missing-body.yaml](../../fixtures/invalid/threat-missing-body.yaml)
- Invalid (`impact` as scalar string): [fixtures/invalid/threat-impact-as-string.yaml](../../fixtures/invalid/threat-impact-as-string.yaml)
- Invalid (semicolon-packed `leverage` string): [fixtures/invalid/threat-leverage-semicolon.yaml](../../fixtures/invalid/threat-leverage-semicolon.yaml)
- Invalid (semicolon-packed list item): [fixtures/invalid/threat-leverage-semicolon-list-item.yaml](../../fixtures/invalid/threat-leverage-semicolon-list-item.yaml)
- Invalid (empty `impact` list): [fixtures/invalid/threat-impact-empty.yaml](../../fixtures/invalid/threat-impact-empty.yaml)
- Invalid (`actors` as string list): [fixtures/invalid/threat-actors-string-list.yaml](../../fixtures/invalid/threat-actors-string-list.yaml)
- Invalid (`ThreatActor` missing `name`): [fixtures/invalid/threat-actor-missing-name.yaml](../../fixtures/invalid/threat-actor-missing-name.yaml)
- Invalid (unscoped actor id): [fixtures/invalid/threat-actor-unscoped.yaml](../../fixtures/invalid/threat-actor-unscoped.yaml)
- Cross-reference: [fixtures/cross-object/objective-references-threat.yaml](../../fixtures/cross-object/objective-references-threat.yaml)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-16 | Correct `impact` and `leverage` to non-empty `list[string]`; forbid semicolon packing ([#12](https://github.com/OpenTideHQ/specifications/issues/12)). Correct `actors` to `list[ThreatActor]` with scoped `name`; pin path is `threat.actors.name` ([#11](https://github.com/OpenTideHQ/specifications/issues/11)). Write-up correction of 1.0 — `schema_id` stays `threat::1.0`. |
| 1.0 | 2026-06-25 | Initial spec from opentide `models/threat.py` |
