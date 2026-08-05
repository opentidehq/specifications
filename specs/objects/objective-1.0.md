---
spec: objective
version: "1.0"
schema_id: objective::1.0
status: normative
supersedes: null
---

# Detection objective (DOM)

## Summary

A detection objective defines what to detect: prioritized signals, composition strategy, and links to threat vectors. Schema identifier: `objective::1.0`.

## Requirements

- The document MUST declare `metadata.schema: objective::1.0`.
- `name` and top-level `composition` MUST be present.
- `objective` body MUST include at least one `signals` entry.
- Each signal MUST have `name`, `uuid`, `description`, `severity`, `methodology`, `entities`, and `data`.
- `objective.composition` MUST mirror the top-level `composition` strategy and description.
- `objective.threats` entries MUST reference valid threat UUIDs when cross-validation is enabled.
- `references` MAY be omitted.

## Definition

### Top level (DetectionObjective)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Objective display name |
| `metadata` | ObjectMetadata | yes | — | See [metadata.md](../metadata.md) |
| `composition` | ObjectiveComposition | yes | — | Top-level composition block |
| `objective` | ObjectiveBody | yes | — | Detection objective body |
| `references` | ObjectReferences | no | null | External and internal references |

### `composition` / `objective.composition` (ObjectiveComposition)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `strategy` | string | yes | Detection composition strategy vocabulary |
| `description` | string | yes | How signals compose |

<Callout type="info">
**Why composition appears twice.** The strategy is declared at the top level (`composition`) so it is visible without descending into the objective body, and mirrored inside `objective.composition` where the signals it governs live. The two blocks MUST carry the same `strategy` and `description`; the validator enforces this. Author both with identical values.
</Callout>

### `objective` (ObjectiveBody)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `priority` | string | yes | — | Priority level |
| `type` | string | yes | — | Detection type vocabulary |
| `description` | string | yes | — | Objective narrative |
| `signals` | list[DetectionSignal] | yes | — | Detection signals (min 1) |
| `composition` | ObjectiveComposition | yes | — | Nested composition (same semantics as top-level) |
| `investment` | string | no | null | Investment level |
| `threats` | list[string] | no | null | Threat vector UUIDs |
| `attack` | list[string] | no | null | ATT&CK technique IDs |

### `signals[]` (DetectionSignal)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Signal name |
| `uuid` | string | yes | — | Signal UUID |
| `description` | string | yes | — | Signal description |
| `severity` | string | yes | — | Severity vocabulary |
| `data` | SignalData | yes | — | Data availability and requirements |
| `methodology` | string | yes | — | Detection methodology vocabulary |
| `entities` | list[string] | yes | — | Signal entity vocabulary values |
| `effort` | integer | no | null | Recovery effort (NIST 800-61) |
| `detectors` | list[ExternalDetector] | no | null | External detector references |
| `examples` | list[DetectionExample] | no | null | Example queries |
| `parent` | string | no | null | Parent signal UUID |

### `data` (SignalData)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `availability` | string | yes | Data availability level |
| `requirements` | string | yes | Data source requirements |
| `logsources` | list[string] | no | MITRE data source references |

### `detectors[]` (ExternalDetector)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Detector name |
| `technology` | string | yes | Technology identifier |
| `description` | string | yes | Detector description |
| `link` | string | no | Reference URL |

### `examples[]` (DetectionExample)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | yes | Example description |
| `link` | string | yes | Example URL |
| `language` | string | no | Query language |
| `query` | string | no | Example query text |

## Relationships

- [metadata.md](../metadata.md) — shared metadata
- [threat-1.0.md](threat-1.0.md) — referenced by `objective.threats`
- [rule-1.0.md](rule-1.0.md) — rules reference objectives via `detection_model` (objective UUID)
- Vocabularies: `detection.composition`, `detection.types`, `detection.methodology`, `signal.entities`, `severity`, `datasources`, `efforts`

## Defaults & overrides

No object-level configuration overrides. See [configuration.md](../configuration.md).

## Examples

```yaml
name: Credential Access Objective
metadata:
  uuid: 00000000-0000-4000-8002-000000000001
  schema: objective::1.0
  version: 1
  tlp: clear
composition:                          # top-level: mirrors objective.composition
  strategy: synergetic
  description: Compose signals for credential access detection
objective:
  priority: High
  type: Threat
  description: Detect credential access techniques
  composition:                        # same strategy + description as above
    strategy: synergetic
    description: Compose signals for credential access detection
  threats:
    - 00000000-0000-4000-8001-000000000001   # → threat UUID
  signals:
    - name: Suspicious logon signal
      uuid: 00000000-0000-4000-8099-000000000001
      description: Suspicious authentication activity
      severity: Medium
      methodology: analytics
      entities: [host]
      data:
        availability: Complete
        requirements: Security event logs
```

- Valid: [fixtures/valid/objective-1.0.yaml](../../fixtures/valid/objective-1.0.yaml)
- Invalid (no signals): [fixtures/invalid/objective-no-signals.yaml](../../fixtures/invalid/objective-no-signals.yaml)
- Cross-reference: [fixtures/cross-object/rule-references-objective.yaml](../../fixtures/cross-object/rule-references-objective.yaml)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial spec from opentide `models/objective.py` |
