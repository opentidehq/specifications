---
spec: platform-sentinel
version: "1.2"
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
- The Sentinel loader treats a missing `scheduling` or `alert` as an empty object, and it drops keys it does not map. Static validation still requires both objects and rejects unknown keys.
- `grouping`, `entities`, `exclusions`, `template`, and `trigger` MAY be omitted and still validate.
- Deploy of a non-NRT rule MUST fail when `scheduling.frequency` or `scheduling.lookback` is missing.
- Deploy MUST fail when `grouping` is missing, and MUST fail when `grouping.alert` is missing.
- Deploy MUST fail when `alert.suppression` is boolean `true`. The value MUST be `false` or a duration string.
- Every duration (`scheduling.frequency`, `scheduling.lookback`, `alert.suppression`, `grouping.alert.grouping_lookback`) MUST be ISO 8601 or shorthand ([Durations](#durations)). Deploy MUST fail on a duration in neither form. Static validation accepts any string.
- When `grouping.alert.enabled` is true, deploy MUST fail when `grouping.alert.grouping_lookback` is missing.
- `scheduling.nrt: true` MUST deploy an NRT rule and MUST NOT require `frequency`, `lookback`, or `trigger`.
- Each `alert.techniques` entry MUST be an [ATT&CK v18](#attck-techniques) technique or sub-technique id. Static validation MUST reject any other value, including an id that a later ATT&CK release added. The `att&ck` vocabulary does not constrain this field.
- Deploy MUST send parent technique ids in the Sentinel `techniques` property and sub-technique ids in `subTechniques`. It MUST NOT send a sub-technique id in `techniques`.
- Deploy MUST NOT send a sub-technique outside [ATT&CK v18](#attck-techniques) in `subTechniques`. A rule's resolved techniques follow the `att&ck` vocabulary, so one can be newer; its parent is still sent in `techniques`, and an implementation SHOULD warn that the sub-technique was left out.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | KQL. Multiline. Compiled with matching `exclusions` before deploy. |
| `scheduling` | [SentinelScheduling](#scheduling-sentinelscheduling) | yes | — | Run cadence, or NRT. |
| `alert` | [SentinelAlert](#alert-sentinelalert) | yes | — | Alert and incident presentation. |
| `grouping` | [SentinelGrouping](#grouping-sentinelgrouping) | optional | null | Event grouping and incident grouping. Required at deploy. |
| `entities` | list[[SentinelEntityMapping](#entities-sentinelentitymapping)] | optional | null | Entity mappings from result columns. |
| `exclusions` | list[[SentinelExclusion](#exclusions-sentinelexclusion)] | optional | null | Per-tenant KQL fragments appended to `query`. |
| `template` | [SentinelTemplate](#template-sentineltemplate) | optional | null | Analytics-rule template this rule was built from. |
| `trigger` | [SentinelTrigger](#trigger-sentineltrigger) | optional | null | Result threshold. Ignored when `scheduling.nrt` is true. |

### `scheduling` (SentinelScheduling)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `nrt` | boolean | optional | null | `true` deploys `kind: NRT` and skips frequency, lookback, and trigger. |
| `frequency` | string | optional | null | [Duration](#durations): ISO 8601, or shorthand converted to ISO 8601. How often a scheduled rule runs (`PT1H`). Required at deploy unless `nrt` is true. |
| `lookback` | string | optional | null | [Duration](#durations): ISO 8601, or shorthand converted to ISO 8601. Query window (`PT2H`). Required at deploy unless `nrt` is true. |

Deploy sends `frequency` as Sentinel `queryFrequency` and `lookback` as `queryPeriod`.

### `alert` (SentinelAlert)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `title` | string | optional | null | Alert display-name format. Empty leaves the Sentinel default. The rule `name` is still the analytics-rule display name. |
| `description` | string | optional | null | Alert description format. |
| `severity` | string | optional | null | Sentinel severity. When omitted, deploy uses `response.alert_severity`. `Critical` is sent as `High`. |
| `suppression` | string \| boolean | optional | `false` | `false` disables suppression and sends a one-hour duration. A [duration](#durations), ISO 8601 or shorthand, enables suppression for that long. Boolean `true` fails deploy. |
| `create_incident` | boolean | optional | `true` | Whether a firing alert opens an incident. |
| `tactics` | list[string] | optional | null | Sentinel tactic names (the ARM `AttackTactic` enum). Replaced when the rule's ATT&CK techniques resolve to tactics: each `att&ck` stage maps to the tactic of the same name. Stealth, Defense Impairment, and the ICS Evasion tactic map to `DefenseEvasion`. A stage with no Sentinel tactic is dropped. |
| `techniques` | list[string] | optional | null | [ATT&CK v18](#attck-techniques) technique and sub-technique ids, the ATT&CK version Sentinel is aligned to. A sub-technique is sent in `subTechniques` and its parent in `techniques`. Replaced by the rule's resolved techniques when those exist. |
| `custom_details` | list[CustomDetail] | optional | null | Extra alert properties. |
| `dynamic_properties` | list[DynamicProperty] | optional | null | Column-driven alert properties. |

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
| `alert` | [SentinelAlertGrouping](#groupingalert-sentinelalertgrouping) | optional | null | Incident grouping. Required at deploy. |

### `grouping.alert` (SentinelAlertGrouping)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | boolean | yes | — | Group alerts into one incident. |
| `reopen_closed_incidents` | boolean | optional | null | Reopen a matching closed incident. Deploy sends `false` when omitted. |
| `grouping_lookback` | string | optional | null | [Duration](#durations): ISO 8601, or shorthand converted to ISO 8601. Required at deploy when `enabled` is true. When `enabled` is false and this is omitted, deploy sends `PT1H`. |
| `matching` | string | optional | null | Sentinel matching method. Deploy sends `AllEntities` when omitted. |
| `group_by_entities` | list[string] | optional | null | Entity types used when matching is selective. |
| `group_by_alert_details` | list[string] | optional | null | Alert-detail fields used when matching is selective. |
| `group_by_custom_details` | list[string] | optional | null | Custom-detail keys used when matching is selective. |

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
| `query` | string | yes | — | KQL fragment appended after the base query. The key is required. An empty string is accepted (this field is not the non-blank rule `query`). |
| `reason` | string | yes | — | Why the exclusion exists. Not sent to Sentinel. |
| `tenant` | string | optional | null | Limit the exclusion to one tenant name. |
| `let` | map[string, scalar] | optional | null | KQL `let` bindings prepended to the query. Values may be string, number, or boolean. Other types are skipped. The last definition of a name wins. |

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

### ATT&CK techniques

Microsoft Sentinel is aligned to the MITRE ATT&CK framework, version 18 (Microsoft, "Understand security coverage by the MITRE ATT&CK framework"). The ids `alert.techniques` accepts are therefore Sentinel's own, not the `att&ck` vocabulary's, which follows the current ATT&CK release: every technique and sub-technique of the ATT&CK 18.1 Enterprise, Mobile, and ICS matrices that is neither revoked nor deprecated, as MITRE publishes them in its STIX data ([mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data), `{enterprise,mobile,ics}-attack-18.1.json`). ATT&CK 18.0 has the same ids. An implementation MAY bundle the list; it MUST NOT read it from the `att&ck` vocabulary.

An id that a later ATT&CK release added is not accepted, even when it replaced a v18 id: `T1685` (ATT&CK v19) replaced `T1562`, `T1562.001`, and `T1562.006`, which are the ids to write here. An implementation SHOULD name the replaced v18 ids when it rejects such an id, following revocations through every hop. An id ATT&CK retired before v18 (`T1086`, PowerShell) is not accepted either; an implementation SHOULD name the v18 id that replaced it (`T1059.001`), when there is one.

Deploy splits the ids it sends. The Sentinel `techniques` property takes `T####` ids only, so a sub-technique is sent in `subTechniques` and its parent in `techniques`:

| Ids | `techniques` | `subTechniques` |
|-----|--------------|-----------------|
| `T1556.009` | `T1556` | `T1556.009` |
| `T1556`, `T1556.009`, `T1078.004` | `T1556`, `T1078` | `T1556.009`, `T1078.004` |
| `T1059` | `T1059` | omitted |

The ids deploy sends are the rule's resolved techniques (its objective's, from the `att&ck` vocabulary) when any resolve, and `alert.techniques` otherwise. Resolved techniques also replace `alert.tactics`. A resolved sub-technique newer than v18 (`T1027.018`) is left out of `subTechniques`; its parent (`T1027`) is still sent in `techniques`.

### Durations

ISO 8601 is the documented form of every Sentinel duration (`PT1H`, `PT30M`, `P1D`, `P1DT2H`), and the form templates and examples use. Sentinel durations are whole weeks, days, hours, minutes, and seconds; years, months, and fractions are not supported.

Shorthand is also accepted: single-unit (`30m`, `1h`, `1d`) or compound (`1h10m`, `1d2h`, `2m30s`). It is the shorthand grammar of [Elastic Security](elastic-1.0.md#durations): whole numbers with the lower-case units `d`, `h`, `m`, and `s`, in that order, each at most once. A shorthand value is the same duration as its ISO 8601 form (`1h10m` is `PT1H10M`). Deploy converts every duration to ISO 8601 before it reaches Sentinel, so the API never receives shorthand.

| Written | Sent |
|---------|------|
| `PT1H` | `PT1H` |
| `1h` | `PT1H` |
| `1h10m` | `PT1H10M` |
| `1d2h` | `P1DT2H` |
| `2m30s` | `PT2M30S` |

The Sent column is the duration. An implementation MAY zero-pad the time fields (`PT01H00M00S`); Sentinel reads both spellings as the same duration.

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
- [elastic-1.0.md](elastic-1.0.md#durations) — the shared shorthand duration grammar
- [vocabularies/catalog.md](../vocabularies/catalog.md) — the `att&ck` vocabulary, which `alert.techniques` does not use

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
      techniques: [T1059.001]
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
| 1.1 | 2026-10-19 | `tactics`: ATT&CK v19 renamed Defense Evasion (TA0005) to Stealth and split out Defense Impairment (TA0112). Both, and the ICS Evasion tactic, deploy as `DefenseEvasion`, the only Sentinel tactic for them. A stage with no Sentinel tactic is dropped ([opentide#568](https://github.com/opentidehq/opentide/issues/568)). Schema id unchanged. |
| 1.1 | 2026-10-19 | [Durations](#durations): ISO 8601 stays the documented form; shorthand, single-unit or compound (`30m`, `1h10m`, `1d2h`, `2m30s`), with the grammar of [Elastic Security](elastic-1.0.md#durations), is accepted and converted to ISO 8601 at deploy ([opentide#564](https://github.com/opentidehq/opentide/pull/564) and the opentide 0.16.0 follow-up, which makes shorthand case-sensitive and adds seconds). Applies to `scheduling.frequency`, `scheduling.lookback`, `alert.suppression`, and `grouping.alert.grouping_lookback`. Schema id unchanged. |
| 1.2 | 2026-11-03 | `alert.techniques` takes [ATT&CK v18](#attck-techniques) technique and sub-technique ids only, the version Sentinel is aligned to: the active techniques and sub-techniques of the ATT&CK 18.1 Enterprise, Mobile, and ICS matrices. The list is Sentinel's, not the `att&ck` vocabulary's. Deploy sends sub-technique ids in `subTechniques` and their parents in `techniques` ([opentide#686](https://github.com/opentidehq/opentide/issues/686)). A non-structural narrowing: schema id unchanged. |
