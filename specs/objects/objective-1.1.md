---
spec: objective
version: "1.1"
schema_id: objective::1.1
status: normative
supersedes: null
---

# Detection objective (DOM)

## Summary

A detection objective defines what to detect: prioritized signals, composition strategy, and links to threat vectors. Schema identifier: `objective::1.1`.

`objective::1.1` is the same objective as [`objective::1.0`](objective-1.0.md), plus one signal shape: a binding that reuses a signal defined on another objective already in the repository. `objective::1.0` stays normative for definition-only objectives. It is not deprecated. A binding is valid only on this schema.

## Requirements

- The document MUST declare `metadata.schema: objective::1.1`.
- `name` and top-level `composition` MUST be present.
- `objective` body MUST include at least one `signals` entry.
- Each signal entry MUST be exactly one of: a definition, or a binding.
- A definition MUST have `name`, `uuid`, `description`, `severity`, `methodology`, `entities`, and `data`.
- A binding MUST be `reuse` set to the UUIDv4 of a signal definition in the workspace signal library, and MUST NOT include any definition field (`name`, `uuid`, `description`, `severity`, `methodology`, `entities`, `data`, `effort`, `detectors`, `examples`, `parent`).
- A binding on a document whose `metadata.schema` is `objective::1.0` is invalid (`binding_requires_1_1`).
- `objective.composition` MUST mirror the top-level `composition` strategy and description.
- `objective.threats` entries MUST reference valid threat UUIDs when cross-validation is enabled.
- `references` MAY be omitted.
- The signal library is every signal **definition** in the workspace object index (committed objective YAML, or an inflight shard that wins). A binding whose `reuse` value is absent from that library is `unresolved_signal`.
- Each definition UUID MUST have exactly one owning objective: the objective whose `signals[]` contains that definition. Two definitions with the same UUID are `duplicate_signal_uuid`. The index MUST NOT keep last-writer-wins.
- A binding whose owner is the same objective is `self_signal`. The same UUID twice in one objective's effective signal list is `duplicate_signal`.
- `effective_signals(objective)` is the ordered list of definition UUIDs on that objective, with each `reuse` value resolved to its definition UUID.
- TLP rank, least restrictive first, is `clear` < `green` < `amber` < `amber+strict` < `red`. A binding is valid when the consumer's `metadata.tlp` is the same rank as the owner's or stricter. A less restrictive consumer is `signal_tlp`.
- The index record for a definition MUST keep authored `parent` (a parent signal UUID, or absent) and MUST record the owning objective UUID separately as `owner`. Ingest MUST NOT write the objective UUID into `parent`. Relation walks use `owner` for the objective → signal hop.
- `parent`, when set on a definition, MUST be a UUIDv4 in the signal library and SHOULD name a signal in the same objective's effective set. It does not bind a signal and it does not change coverage.
- A rule's `detection_model` is **direct** coverage of one objective (`objective::1.0` or `objective::1.1`). Let S be `effective_signals` of that objective. The rule also **indirectly** covers every other objective that includes at least one signal in S. Reason `owns` when that objective owns the signal. Reason `shares` when it includes the signal and does not own it. Indirect coverage is partial: the shared signals only, not the other objective's full composition. Reports MUST label it partial and MUST list the via-signal UUIDs and the reason.
- The coverage walk stops at S. A signal bound by an intermediate objective is covered only when that signal is itself in S.
- `techniques` resolved for a rule come from the direct objective and that objective's threats. Indirect threats appear in coverage output. Their technique ids are not copied onto the rule.
- A resolved binding counts toward the minimum of one signal. An unresolved binding does not, and is still an error.

## Definition

### Top level (DetectionObjective)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Objective display name |
| `metadata` | ObjectMetadata | yes | — | See [metadata.md](../metadata.md). `metadata.schema` is `objective::1.1`. |
| `composition` | ObjectiveComposition | yes | — | Top-level composition block |
| `objective` | ObjectiveBody | yes | — | Detection objective body |
| `references` | ObjectReferences | no | null | External and internal references |

### `composition` / `objective.composition` (ObjectiveComposition)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `strategy` | string | yes | Detection composition strategy vocabulary |
| `description` | string | yes | How signals compose |

<Callout type="info">
**Why composition appears twice.** The strategy is declared at the top level (`composition`) so it is visible without descending into the objective body, and mirrored inside `objective.composition` where the signals it governs live. The two blocks MUST carry the same `strategy` and `description`. Author both with identical values.
</Callout>

### `objective` (ObjectiveBody)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `priority` | string | yes | — | Priority level |
| `type` | string | yes | — | Detection type vocabulary |
| `description` | string | yes | — | Objective narrative |
| `signals` | list[Definition \| Binding] | yes | — | Detection signals (min 1) |
| `composition` | ObjectiveComposition | yes | — | Nested composition (same semantics as top-level) |
| `investment` | string | no | null | Investment level |
| `threats` | list[string] | no | null | Threat vector UUIDs |
| `attack` | list[string] | no | null | ATT&CK technique IDs |

List order is composition order. Definitions and bindings may interleave. The composition strategy applies to the full effective list. The owning objective's composition does not change.

### `signals[]` definition (DetectionSignal)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Signal name |
| `uuid` | string | yes | — | Signal UUID. Library key. |
| `description` | string | yes | — | Signal description |
| `severity` | string | yes | — | Severity vocabulary |
| `data` | SignalData | yes | — | Data availability and requirements |
| `methodology` | string | yes | — | Detection methodology vocabulary |
| `entities` | list[string] | yes | — | Signal entity vocabulary values |
| `effort` | integer | no | null | Recovery effort (NIST 800-61) |
| `detectors` | list[ExternalDetector] | no | null | External detector references |
| `examples` | list[DetectionExample] | no | null | Example queries |
| `parent` | string | no | null | Parent signal UUID |

### `signals[]` binding (SignalBinding)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `reuse` | string (UUIDv4) | yes | — | Signal UUID of a definition in the workspace library |

A binding has no local name, description, severity, or data. Those values are read from the definition. The binding does not allocate a UUID and does not insert a second library row.

Completion of `reuse` uses the `signal` model vocabulary ([metaschema-keywords.md](../metaschema-keywords.md)): entry id is the definition UUID, display name is `{owning objective name}::{signal name}`, and `tide.object.parent` is the owning objective UUID. The `objective::1.0` schema does not offer this key. Signal UUIDs are not entries in the `objective` vocabulary used by `detection_model`.

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

- [objective-1.0.md](objective-1.0.md) — definition-only objectives. A 1.0 definition is a valid 1.1 definition. Moving a definition-only objective to 1.1 rewrites `metadata.schema` only.
- [metadata.md](../metadata.md) — shared metadata. `metadata.version` is the instance content version and does not select this schema.
- [threat-1.0.md](threat-1.0.md) — referenced by `objective.threats`. Indirect coverage surfaces those threats as partial, via the shared signals.
- [rule-1.0.md](rule-1.0.md) — `detection_model` is the direct objective. Indirect objectives are derived from `reuse`.
- [validation.md](../validation.md) — binding codes
- [sharing/misp-1.0.md](../sharing/misp-1.0.md) — `opentide-relation` includes the owner UUID of each bound signal
- Vocabularies: `detection.composition`, `detection.types`, `detection.methodology`, `signal.entities`, `severity`, `datasources`, `efforts`, `tlp`. The `signal` completion set is a model vocabulary, not a file under `vocabularies/`.

## Defaults & overrides

No object-level configuration overrides. See [configuration.md](../configuration.md).

Vocabulary pins for this schema match `objective::1.0`. See [schemas/pins/objective.toml](../../schemas/pins/objective.toml).

## Examples

A definition-only `objective::1.1` document is the `objective::1.0` shape with the schema id changed. See [fixtures/valid/objective-1.1.yaml](../../fixtures/valid/objective-1.1.yaml).

A binding, after the owner is in the repository. The owner may stay on `objective::1.0`. Completion inserts the signal UUID. The label beside it is `Credential Access Objective::Suspicious logon signal`.

```yaml
name: Lateral Movement Objective
metadata:
  uuid: 00000000-0000-4000-8002-000000000002
  schema: objective::1.1
  version: 1
  tlp: amber
composition:
  strategy: synergetic
  description: Compose movement signals with the shared logon signal
objective:
  priority: High
  type: Threat
  description: Detect lateral movement that reuses credential-access evidence
  composition:
    strategy: synergetic
    description: Compose movement signals with the shared logon signal
  threats:
    - 00000000-0000-4000-8001-000000000003
  signals:
    - reuse: 00000000-0000-4000-8099-000000000001   # definition on another objective
    - name: Remote service logon
      uuid: 00000000-0000-4000-8099-000000000002
      description: A new service logon on a second host
      severity: High
      methodology: analytics
      entities: [host]
      data:
        availability: Complete
        requirements: Security event logs
```

A rule with `detection_model` pointing at this objective covers it directly, and covers the owner of `…8099…0001` indirectly with reason `owns`. A rule whose `detection_model` is that owner covers this objective indirectly with reason `shares`, via that signal only.

- Valid binding: [fixtures/cross-object/objective-reuses-signal.yaml](../../fixtures/cross-object/objective-reuses-signal.yaml)
- Valid definition-only 1.1: [fixtures/valid/objective-1.1.yaml](../../fixtures/valid/objective-1.1.yaml)
- Invalid (`reuse` plus `name`): [fixtures/invalid/objective-signal-entry-mixed.yaml](../../fixtures/invalid/objective-signal-entry-mixed.yaml)
- Invalid (`reuse` is not a UUIDv4): [fixtures/invalid/objective-signal-bad-uuid.yaml](../../fixtures/invalid/objective-signal-bad-uuid.yaml)
- Invalid (binding on 1.0): [fixtures/invalid/objective-1.0-signal-binding.yaml](../../fixtures/invalid/objective-1.0-signal-binding.yaml)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.1 | 2026-09-29 | Signal binding `reuse` ([RFC 0007](../../rfcs/0007-signal-reuse.md)). `objective::1.0` remains normative for definitions only. |
