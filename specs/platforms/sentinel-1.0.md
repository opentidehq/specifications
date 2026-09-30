---
spec: platform-sentinel
version: "1.0"
schema_id: platform::sentinel::1.0
status: normative
supersedes: null
---

# Microsoft Sentinel (`platform::sentinel::1.0`)

## Summary

`configurations.sentinel` is a Microsoft Sentinel scheduled analytics rule, or a near-real-time (NRT) rule when `scheduling.nrt` is true. The detection text is KQL. Query validation is supported. The analytics rule id sent to Sentinel is the rule's `metadata.uuid`.

Shared fields (`enabled`, `name`, `schema`, `status`, `flags`, `tenants`, `contributors`) are defined in [platforms](index.md#shared-platform-block).

## Requirements

- Static validation MUST require `query`, `scheduling`, and `alert`.
- `query` MUST be non-blank KQL.
- `scheduling` MAY omit `frequency`, `lookback`, and `nrt` and still validate.
- `alert` MAY be an empty object and still validate. `suppression` defaults to `false`. `create_incident` defaults to `true`.
- `grouping`, `entities`, `exclusions`, `template`, and `trigger` MAY be omitted and still validate.
- Deploy of a non-NRT rule MUST fail when `scheduling.frequency` or `scheduling.lookback` is missing.
- Deploy MUST fail when `grouping` is missing, and MUST fail when `grouping.alert` is missing.
- Deploy MUST fail when `alert.suppression` is boolean `true`. The value MUST be `false` or a duration string.
- When `grouping.alert.enabled` is true, deploy MUST fail when `grouping.alert.grouping_lookback` is missing.
- `scheduling.nrt: true` MUST deploy an NRT rule and MUST NOT require `frequency`, `lookback`, or `trigger`.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | KQL. Multiline. Compiled with matching `exclusions` before deploy. |
| `scheduling` | [SentinelScheduling](#scheduling-sentinelscheduling) | yes | — | Run cadence, or NRT. |
| `alert` | [SentinelAlert](#alert-sentinelalert) | yes | — | Alert and incident presentation. |
| `grouping` | [SentinelGrouping](#grouping-sentinelgrouping) | no | null | Event grouping and incident grouping. Required at deploy. |
| `entities` | list[[SentinelEntityMapping](#entities-sentinelentitymapping)] | no | null | Entity mappings from result columns. |
| `exclusions` | list[[SentinelExclusion](#exclusions-sentinelexclusion)] | no | null | Per-tenant KQL fragments appended to `query`. |
| `template` | [SentinelTemplate](#template-sentineltemplate) | no | null | Analytics-rule template this rule was built from. |
| `trigger` | [SentinelTrigger](#trigger-sentineltrigger) | no | null | Result threshold. Ignored when `scheduling.nrt` is true. |

### `scheduling` (SentinelScheduling)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `nrt` | boolean | no | null | `true` deploys `kind: NRT` and skips frequency, lookback, and trigger. |
| `frequency` | string | no | null | ISO 8601 duration. How often a scheduled rule runs (`PT1H`). Required at deploy unless `nrt` is true. |
| `lookback` | string | no | null | ISO 8601 duration. Query window (`PT2H`). Required at deploy unless `nrt` is true. |

Durations are converted to Sentinel `queryFrequency` and `queryPeriod`.

### `alert` (SentinelAlert)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `title` | string | no | null | Alert display-name format. Empty leaves the Sentinel default. The rule `name` is still the analytics-rule display name. |
| `description` | string | no | null | Alert description format. |
| `severity` | string | no | null | Sentinel severity. When omitted, deploy uses `response.alert_severity`. `Critical` is sent as `High`. |
| `suppression` | string \| boolean | no | `false` | `false` disables suppression and sends a one-hour duration. A duration string enables suppression for that long. Boolean `true` fails deploy. |
| `create_incident` | boolean | no | `true` | Whether a firing alert opens an incident. |
| `tactics` | list[string] | no | null | Sentinel tactic names. Replaced when the rule's ATT&CK techniques resolve to tactics. |
| `techniques` | list[string] | no | null | Technique ids. Replaced by the rule's resolved techniques when those exist. |
| `custom_details` | list[CustomDetail] | no | null | Extra alert properties. |
| `dynamic_properties` | list[DynamicProperty] | no | null | Column-driven alert properties. |

`custom_details[]`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key` | string | yes | Alert property name. |
| `column` | string | yes | Result column. |

`dynamic_properties[]`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `property` | string | yes | Sentinel alert property. `Tactics` and `Severity` are sent as the tactics and severity column overrides. Any other value is an alert dynamic property. |
| `column` | string | yes | Result column. |

### `grouping` (SentinelGrouping)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `event` | string | yes | — | Sentinel `aggregationKind`. `SingleAlert` groups events into one alert. `AlertPerResult` emits one alert per row. |
| `alert` | [SentinelAlertGrouping](#groupingalert-sentinelalertgrouping) | no | null | Incident grouping. Required at deploy. |

### `grouping.alert` (SentinelAlertGrouping)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | boolean | yes | — | Group alerts into one incident. |
| `reopen_closed_incidents` | boolean | no | null | Reopen a matching closed incident. Deploy sends `false` when omitted. |
| `grouping_lookback` | string | no | null | ISO 8601 duration. Required at deploy when `enabled` is true. When `enabled` is false and this is omitted, deploy sends `PT1H`. |
| `matching` | string | no | null | Sentinel matching method. Deploy sends `AllEntities` when omitted. |
| `group_by_entities` | list[string] | no | null | Entity types used when matching is selective. |
| `group_by_alert_details` | list[string] | no | null | Alert-detail fields used when matching is selective. |
| `group_by_custom_details` | list[string] | no | null | Custom-detail keys used when matching is selective. |

### `entities[]` (SentinelEntityMapping)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `entity` | string | yes | Sentinel entity type (`Account`, `Host`, `IP`, `URL`, …). |
| `mappings` | list[Mapping] | yes | Column bindings for that entity. |

`mappings[]`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identifier` | string | yes | Entity identifier (`Name`, `Address`, …). |
| `column` | string | yes | Result column. |

### `exclusions[]` (SentinelExclusion)

Applied at deploy for the target tenant. An exclusion with no `tenant`, or with `tenant` equal to the target, is included. Others are skipped.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | no | `""` | KQL fragment appended after the base query. |
| `reason` | string | yes | — | Why the exclusion exists. Not sent to Sentinel. |
| `tenant` | string | no | null | Limit the exclusion to one tenant name. |
| `let` | map[string, scalar] | no | null | KQL `let` bindings prepended to the query. Values may be string, number, or boolean. Other types are skipped. The last definition of a name wins. |

### `template` (SentinelTemplate)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `uuid` | string | yes | Sentinel alert-rule template name. |
| `version` | string | yes | Template version. |

### `trigger` (SentinelTrigger)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `operator` | string | yes | Sentinel trigger operator. |
| `threshold` | int | yes | Sentinel trigger threshold. |

Sent only for scheduled rules. Omitted on NRT rules.

### Deploy

| Block status strategy | Sentinel result |
|-----------------------|-----------------|
| `DISABLEMENT` | Rule updated with `enabled: false` |
| `DELETION` | Analytics rule deleted by `metadata.uuid` |
| any other | Rule created or updated with `enabled: true` |

The rule display name is the Tide rule `name`. The description is the Tide rule `description`. Severity prefers `alert.severity`, then `response.alert_severity`.

## Relationships

- [platforms](index.md) — shared fields, capability row, external ids
- [rule-1.0.md](../objects/rule-1.0.md) — parent object
- [deployment.md](../deployment.md) — `status`
- [validation.md](../validation.md) — KQL query validation

## Defaults & overrides

| Field | Default |
|-------|---------|
| `alert.suppression` | `false` |
| `alert.create_incident` | `true` |
| `grouping.alert.reopen_closed_incidents` | `false` at deploy when omitted |
| `grouping.alert.matching` | `AllEntities` at deploy when omitted |
| `grouping.alert.grouping_lookback` | `PT1H` at deploy when grouping is disabled and the field is omitted |
| Alert severity | `response.alert_severity`, then the block value if set |
| `Critical` severity | sent as `High` |

## Examples

```yaml
configurations:
  sentinel:
    enabled: true
    schema: platform::sentinel::1.0
    status: STAGING
    query: |
      SecurityEvent
      | where EventID == 4688
      | take 1
    scheduling:
      frequency: PT1H
      lookback: PT2H
    alert:
      title: Suspicious process creation
      severity: High
      suppression: false
      create_incident: true
    grouping:
      event: SingleAlert
      alert:
        enabled: false
    entities:
      - entity: Account
        mappings:
          - identifier: Name
            column: Account
```

NRT omits the schedule window:

```yaml
scheduling:
  nrt: true
```

Fixture: [fixtures/platforms/sentinel.yaml](../../fixtures/platforms/sentinel.yaml). The rule-object fixture [fixtures/valid/rule-1.0.yaml](../../fixtures/valid/rule-1.0.yaml) carries the same scheduled shape.

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-30 | Initial field contract from the Sentinel configuration model and deployer. |
