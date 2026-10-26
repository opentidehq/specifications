---
spec: rule
version: "1.1"
schema_id: rule::1.1
status: normative
supersedes: null
---

# Detection rule (MDR)

## Summary

A detection rule (MDR — Managed Detection Rule) is the deployable unit of detection content: metadata, severity, ATT&CK techniques, platform-specific query configurations, optional response playbook, and lifecycle status. Schema identifier: `rule::1.1`.

This revision adds optional `metadata.reviewed`. [rule-1.0.md](rule-1.0.md) (`rule::1.0`) stays normative. A rule opts in by setting `metadata.schema`. Platform blocks and every other field match `rule::1.0`.

## Requirements

- The document MUST declare `metadata.schema: rule::1.1`.
- `name`, `metadata`, and `description` MUST be present.
- `metadata.reviewed` MAY be omitted. Omitted means no recorded review.
- When `metadata.reviewed` is present, it MUST be an ISO 8601 date (`YYYY-MM-DD`) or datetime string, coerced to string on load, using the same forms as `metadata.created` and `metadata.modified`. A date-only value denotes 00:00:00Z on that date.
- Implementations MUST NOT write `metadata.reviewed` during validate, deploy, share, or template generation. Authors set it when a person reviews the rule.
- Consumers MUST NOT treat `metadata.created` or `metadata.modified` as a review time. Updating `reviewed` does not require a change to `metadata.version` or `metadata.modified`.
- `status` MUST be a valid deployment status from [deployment.md](../deployment.md) (default: `STAGING`).
- `severity` MUST be a value of the `alert_severity` vocabulary (pin `alert_severity::1.0`: `Informational`, `Low`, `Medium`, `High`, `Critical`; default: `Informational`). It is the rule's own severity, distinct from a threat's `severity`, which uses the `severity` (Threat Severity) incident scale.
- `techniques` MUST be a list of ATT&CK technique ids from vocabulary `att&ck` (pin `att&ck::1.2`). The list MAY be empty.
- `platforms` or `configurations` MUST contain at least one enabled platform block for deployable rules.
- `detection_model` when present MUST reference either a valid objective UUID or the UUID of a signal defined under an objective (`objective::1.0` or `objective::1.1`). A rule implements a whole objective or one of its signals; both are referenceable by design. A signal reference implements that signal, and the rule's objective is the signal's owning objective. Indirect coverage of other objectives is derived from signal bindings on `objective::1.1` ([objective-1.1.md](objective-1.1.md), draft). A rule has a single `detection_model`.
- Platform blocks MUST validate against the platform schema identifier declared in each block's `schema` field.
- `references` MAY be omitted.
- Registry-backed methods (`deploy`, `validate`, `document`) require a bound opentide registry at runtime — not part of static YAML validation.

<Callout type="info">
**"Deployable rule" defined.** A rule is *deployable* when it contains at least one platform block (under `configurations` or legacy `platforms`) with `enabled: true`. A rule with no enabled platform block is still **valid** — for example a rule in `DESIGN` status being drafted — it simply will not deploy. Static validation never requires a platform block; only deployment does.
</Callout>

<Callout type="info">
**`configurations` vs `platforms`.** `configurations` is the typed, preferred form: each key (`sentinel`, `splunk`, …) maps to a validated platform model. `platforms` is a legacy flat dict kept for backward compatibility. New rules SHOULD use `configurations`; existing rules using the legacy `platforms` dict SHOULD be migrated to typed `configurations` blocks. Do not declare the same platform in both blocks.
</Callout>

## Definition

### Top level (DetectionRule)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Rule display name |
| `metadata` | ObjectMetadata | yes | — | See [metadata.md](../metadata.md). This revision accepts optional `metadata.reviewed`. |
| `description` | string | yes | — | Rule narrative (multiline YAML encouraged) |
| `status` | string | no | `STAGING` | Deployment lifecycle status |
| `severity` | string | no | `Informational` | `alert_severity::1.0` |
| `techniques` | list[string] | no | `[]` | MITRE ATT&CK technique ids (`att&ck::1.2`) |
| `platforms` | map[string, object] | no | `{}` | Legacy flat platform dict (prefer `configurations`) |
| `configurations` | RuleConfigurations | no | null | Typed per-platform configuration blocks |
| `references` | ObjectReferences | no | null | External and internal references |
| `detection_model` | string | no | null | UUID of the objective, or of a signal defined under an objective, that this rule implements (`objective::1.0` or `objective::1.1`) |
| `response` | RuleResponse | no | null | Alert and response configuration |

### Review staleness

Evaluated at instant `T`, for a positive duration `W` supplied by the consumer, a detection rule is **unreviewed** when any of the following holds:

1. `metadata.schema` is `rule::1.0` (that revision has no review field).
2. `metadata.schema` is `rule::1.1` and `metadata.reviewed` is absent.
3. `metadata.schema` is `rule::1.1` and the `reviewed` instant is strictly earlier than `T − W`.

A `reviewed` instant equal to `T − W` or later is not unreviewed. `W` is not a field on the rule. The predicate is a read and MUST NOT modify the rule.

### `response` (RuleResponse)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `alert_severity` | string | no | `Informational` | Alert severity vocabulary |
| `playbook` | string | no | null | Playbook identifier or URL |
| `responders` | string | no | `[deployment] default_responders` | Alert handling team. Free text, NOT a vocabulary: the team is per-organisation configuration (opentide#507) |
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
| `language` | string | no | Query language, for a `system` with more than one. Omitted with `system: elastic`: unknown. |

`language` names the query language when `system` alone does not. With `system: elastic` it MUST be one of the names [elastic-1.0](../platforms/elastic-1.0.md) uses: `kuery` (KQL), `lucene`, `eql`, or `esql` (ES\|QL). `language` MUST NOT be set with any other `system`, because the system alone names the language: `sentinel` and `defender_for_endpoint` are KQL, `splunk` is SPL, and no other system has a language in this revision. With `system: elastic`, an omitted `language` (or an empty one, YAML `null`) means the language is unknown and the query is not analysed, as before the field existed.

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

| Key | Model | Schema ID | Spec |
|-----|-------|-----------|------|
| `sentinel` | SentinelConfig | `platform::sentinel::1.0` | [sentinel-1.0.md](../platforms/sentinel-1.0.md) |
| `defender_for_endpoint` | DefenderConfig | `platform::defender_for_endpoint::1.0` | [defender-for-endpoint-1.0.md](../platforms/defender-for-endpoint-1.0.md) |
| `splunk` | SplunkConfig | `platform::splunk::1.0` | [splunk-1.0.md](../platforms/splunk-1.0.md) |
| `sentinel_one` | SentinelOneConfig | `platform::sentinel_one::1.0` | [sentinel-one-1.0.md](../platforms/sentinel-one-1.0.md) |
| `crowdstrike` | CrowdstrikeConfig | `platform::crowdstrike::1.0` | [crowdstrike-1.0.md](../platforms/crowdstrike-1.0.md) |
| `harfanglab` | HarfangLabConfig | `platform::harfanglab::1.0` | [harfanglab-1.0.md](../platforms/harfanglab-1.0.md) |
| `carbon_black_cloud` | CarbonBlackConfig | `platform::carbon_black_cloud::1.0` | [carbon-black-cloud-1.0.md](../platforms/carbon-black-cloud-1.0.md) |
| `elastic` | ElasticConfig | `platform::elastic::1.0` | [elastic-1.0.md](../platforms/elastic-1.0.md) |

Shared block fields and the capability matrix are in [platforms/index.md](../platforms/index.md). Each link above is the field contract for that block.

## Relationships

- [metadata.md](../metadata.md) — identity, schema routing, and `metadata.reviewed`
- [rule-1.0.md](rule-1.0.md) — previous MDR revision; still valid; no `metadata.reviewed`
- [objective-1.0.md](objective-1.0.md) — linked via `detection_model` (the objective, or one of its signals)
- [objective-1.1.md](objective-1.1.md) — same link; `reuse` bindings add indirect coverage (draft)
- [deployment.md](../deployment.md) — `status` lifecycle and promotion
- [platforms/index.md](../platforms/index.md) — platform blocks and deploy/validate capabilities
- [validation.md](../validation.md) — schema, vocabulary, and query validation
- Vocabularies: `severity`, `alert_severity`, `att&ck`, deployment statuses

## Defaults & overrides

| Setting | Source | Override |
|---------|--------|----------|
| Default `status` | `STAGING` | Per-rule YAML |
| Status enum | `deployment.toml` | `.opentide/configurations/deployment.toml` |
| Platform defaults | bundled `platforms/*.toml` | `.opentide/configurations/platforms/` |
| Template description default | `schema.toml` | `.opentide/configurations/schema.toml` |

Vocabulary files are canonical in `vocabularies/` — not overridable. See [configuration.md](../configuration.md).

## Examples

```yaml
name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000101
  schema: rule::1.1
  version: 1
  created: "2026-01-01"
  modified: "2026-01-02"
  reviewed: "2026-09-01"                 # optional; omit when nobody has reviewed the rule
  tlp: clear
description: Detects credential access via suspicious process creation
status: STAGING
severity: High
techniques: [T1059]
detection_model: 00000000-0000-4000-8002-000000000001   # → objective UUID, or a signal UUID under one
response:
  alert_severity: High
configurations:
  sentinel:
    enabled: true
    name: Sentinel KQL Rule
    status: STAGING
    query: |
      SecurityEvent
      | where EventID == 4688
      | take 1
    scheduling:
      frequency: PT1H
      lookback: PT2H
    alert:
      title: Sentinel KQL Rule
      suppression: false
```

### Valid fixtures

| Fixture | Demonstrates |
|---------|--------------|
| [fixtures/valid/rule-1.1.yaml](../../fixtures/valid/rule-1.1.yaml) | `rule::1.1` with `metadata.reviewed` set |
| [fixtures/valid/rule-1.1-unreviewed.yaml](../../fixtures/valid/rule-1.1-unreviewed.yaml) | `rule::1.1` with `metadata.reviewed` omitted |
| [fixtures/valid/rule-1.1-search-language.yaml](../../fixtures/valid/rule-1.1-search-language.yaml) | Elastic ES\|QL and KQL hunts with `searches[].language`, and a Splunk hunt without it (`rule::1.1`; the field is the same on `rule::1.0`) |
| [fixtures/valid/rule-1.0.yaml](../../fixtures/valid/rule-1.0.yaml) | Previous revision, still valid |
| [fixtures/cross-object/rule-references-objective.yaml](../../fixtures/cross-object/rule-references-objective.yaml) | `detection_model` → objective UUID |
| [fixtures/cross-object/rule-references-signal.yaml](../../fixtures/cross-object/rule-references-signal.yaml) | `detection_model` → signal UUID |

### Invalid fixtures

| Fixture | Violation |
|---------|-----------|
| [fixtures/invalid/rule-reviewed-bad-date.yaml](../../fixtures/invalid/rule-reviewed-bad-date.yaml) | `metadata.reviewed` is not an ISO 8601 date or datetime |
| [fixtures/invalid/rule-1.0-reviewed.yaml](../../fixtures/invalid/rule-1.0-reviewed.yaml) | `metadata.reviewed` on `rule::1.0` |
| [fixtures/invalid/rule-missing-metadata.yaml](../../fixtures/invalid/rule-missing-metadata.yaml) | Missing required `metadata` |
| [fixtures/invalid/rule-unknown-schema.yaml](../../fixtures/invalid/rule-unknown-schema.yaml) | Unregistered `metadata.schema` |
| [fixtures/invalid/rule-bad-uuid.yaml](../../fixtures/invalid/rule-bad-uuid.yaml) | Non-UUIDv4 `metadata.uuid` |
| [fixtures/invalid/rule-search-language.yaml](../../fixtures/invalid/rule-search-language.yaml) | `searches[].language` outside the Elastic names, and set on a `sentinel` search (`rule::1.0`) |

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.1 | 2026-10-23 | Optional `response.procedure.searches[].language`: `kuery`, `lucene`, `eql`, or `esql` with `system: elastic`, and not set with any other system. Omitted means unknown, as before ([specifications#58](https://github.com/opentidehq/specifications/issues/58)). Additive: every existing rule stays valid, and `schema_id` stays `rule::1.1`. |
| 1.1 | 2026-10-19 | `techniques` is pinned to `att&ck::1.2` (ATT&CK 20.0). Additive: every `att&ck::1.1` technique still validates ([opentide#568](https://github.com/opentidehq/opentide/issues/568)). `schema_id` stays `rule::1.1`. |
| 1.1 | 2026-10-19 | `configurations.elastic` (`ElasticConfig`, `platform::elastic::1.0`, [elastic-1.0.md](../platforms/elastic-1.0.md)) is added ([RFC 0007](../../rfcs/0007-elastic-security-platform.md)). Additive: every existing rule stays valid, and `schema_id` stays `rule::1.1`. |
| 1.1 | 2026-10-19 | `detection_model` references an objective UUID or the UUID of any signal defined under an objective. Both are referenceable by design and implementations always accepted signal UUIDs; the earlier objective-only wording was wrong. |
| 1.1 | 2026-10-19 | `detection_model` may name `objective::1.0` or `objective::1.1`. Indirect coverage is derived ([RFC 0011](../../rfcs/0011-signal-reuse.md)). |
| 1.1 | 2026-10-07 | `techniques` is pinned to `att&ck::1.1`. `schema_id` stays `rule::1.1`. |
| 1.1 | 2026-09-30 | Optional `metadata.reviewed` ([RFC 0008](../../rfcs/0008-rule-reviewed-date.md)). `rule::1.0` remains normative. |
