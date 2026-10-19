---
spec: platform-crowdstrike
version: "1.1"
schema_id: platform::crowdstrike::1.0
status: normative
supersedes: null
---

# CrowdStrike Falcon (`platform::crowdstrike::1.0`)

## Summary

`configurations.crowdstrike` is a CrowdStrike Falcon correlation rule. The detection text is the correlation filter. There is no query validator: `opentide validate query --platform crowdstrike` reports unsupported. CrowdStrike assigns the remote rule id; OpenTide stores it per tenant in [deployment state](../deployment-state.md).

Shared fields are defined in [platforms](index.md#shared-platform-block). `contributors` on this block are joined into the update comment. When the list is empty, deploy uses `metadata.author`.

## Requirements

- Static validation MUST require `details`, `schedule`, and a non-blank `query`.
- `details.trigger` and `details.outcome` MUST be present for validation. They are unconstrained strings at validation time.
- `schedule.frequency` and `schedule.lookback` MUST be present for validation.
- Deploy MUST reject `outcome` unless, after lowercasing, it is `detection` or `incident`.
- Deploy MUST reject `trigger` unless, after lowercasing, it is `verbose` or `summary`.
- Deploy MUST reject `severity` unless it is `Informational`, `Low`, `Medium`, `High`, or `Critical`.
- The block MUST NOT contain `rule_id_bundle`, `rule_id`, or `rule_id::<tenant>`. Each fails `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)).
- `schedule.start` and `schedule.end` MAY be omitted. When set, they SHOULD be UTC timestamps `YYYY-MM-DDTHH:MM:SSZ`. An unquoted YAML timestamp MUST be rewritten to that form before it is sent.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `details` | [CrowdstrikeDetails](#details-crowdstrikedetails) | yes | — | Correlation outcome, trigger mode, and alert metadata. |
| `schedule` | [CrowdstrikeSchedule](#schedule-crowdstrikeschedule) | yes | — | How often the correlation search runs and how far it looks back. |
| `query` | string | yes | — | Correlation filter. Multiline. Sent as the rule `filter`. |

### `details` (CrowdstrikeDetails)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `trigger` | string | yes | `verbose` or `summary`, any case. Deploy lowercases the value. |
| `outcome` | string | yes | `detection` or `incident`, any case. Deploy lowercases the value. |
| `name` | string | optional | Falcon rule name. Deploy uses the Tide rule `name` when omitted. |
| `description` | string | optional | Falcon description. Deploy uses the Tide rule `description` when omitted. |
| `severity` | string | optional | `Informational`, `Low`, `Medium`, `High`, or `Critical`. Deploy uses `response.alert_severity` when omitted. |
| `tactic` | string | optional | Falcon tactic. Sent as given. |
| `technique` | string | optional | Falcon technique. Sent as given. |

Severity is sent as an integer:

| Tide severity | Falcon severity |
|---------------|-----------------|
| `Informational` | 10 |
| `Low` | 30 |
| `Medium` | 50 |
| `High` | 70 |
| `Critical` | 90 |

### `schedule` (CrowdstrikeSchedule)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `frequency` | string | yes | Run interval. Deploy sends it as `@every <frequency>` (`@every 1h`). |
| `lookback` | string | yes | How far back each run searches. Sent as the search lookback. |
| `start` | string | optional | Do not run before this UTC time. |
| `end` | string | optional | Stop running at this UTC time. |

### Deploy

The customer id is the tenant `customer_id` with the segment after the first hyphen removed, lowercased.

| Block status strategy | CrowdStrike result |
|-----------------------|--------------------|
| `DISABLEMENT` | Update the bound remote rule with Falcon status `inactive`; without a binding, report `external_id_missing` and make no HTTP call. |
| `DELETION` | Delete the bound remote rule and remove the binding after successful deletion; without a binding, report `external_id_missing`. |
| any other | Falcon status `active`. Update when a binding exists; otherwise create and durably record the returned id. |

The binding is the tenant's entry under `crowdstrike` in `.opentide/states/deployment/<uuid>.json`, the create-response id verbatim. A create is refused when the shard directory is gitignored or the run cannot persist state. The decision order and codes are in [deployment-state.md](../deployment-state.md#deploy-decisions).

The rule comment records the contributors and that OpenTide performed the update.

## Relationships

- [platforms](index.md) — shared fields, no query validation, external ids
- [deployment-state.md](../deployment-state.md) — where the Falcon rule id is stored
- [rule-1.0.md](../objects/rule-1.0.md) — parent object
- [validation.md](../validation.md) — `supported: false` for query validation

## Defaults & overrides

| Field | Default |
|-------|---------|
| Name and description | Tide rule `name` and `description` |
| Severity | `response.alert_severity` |
| Comment authors | `contributors`, else `metadata.author` |
| Schedule definition | `@every` plus `frequency` |

## Examples

```yaml
configurations:
  crowdstrike:
    enabled: true
    schema: platform::crowdstrike::1.0
    status: STAGING
    query: |
      event_simpleName=ProcessRollup2 FileName=cmd.exe
    details:
      trigger: summary
      outcome: detection
      severity: High
      tactic: Execution
      technique: T1059
    schedule:
      frequency: 1h
      lookback: 2h
      start: "2026-04-15T19:00:00Z"
```

Fixture: [fixtures/platforms/crowdstrike.yaml](../../fixtures/platforms/crowdstrike.yaml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-30 | Initial field contract from the CrowdStrike configuration model and deployer. |
| 1.1 | 2026-10-16 | `rule_id_bundle` and the `rule_id::<tenant>` alias are removed and fail `external_id_in_rule`. Deploy reads and writes the Falcon rule id in [deployment state](../deployment-state.md). `DISABLEMENT` updates the bound rule as `inactive` and every other deployed strategy sends `active`, matching [deployment.md](../deployment.md); the note recording the reversed mapping is removed. `DISABLEMENT` and `DELETION` without a binding report `external_id_missing` ([RFC 0010](../../rfcs/0010-deployment-external-ids.md)). Schema id unchanged. |
