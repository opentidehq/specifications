---
spec: platform-crowdstrike
version: "1.0"
schema_id: platform::crowdstrike::1.0
status: normative
supersedes: null
---

# CrowdStrike Falcon (`platform::crowdstrike::1.0`)

## Summary

`configurations.crowdstrike` is a CrowdStrike Falcon correlation rule. The detection text is the correlation filter. There is no query validator: `opentide validate query --platform crowdstrike` reports unsupported. CrowdStrike assigns the rule id; OpenTide stores it in `rule_id_bundle`.

Shared fields are defined in [platforms](index.md#shared-platform-block). `contributors` on this block are joined into the update comment. When the list is empty, deploy uses `metadata.author`.

## Requirements

- Static validation MUST require `details`, `schedule`, and a non-blank `query`.
- `details.trigger` and `details.outcome` MUST be present for validation. They are unconstrained strings at validation time.
- `schedule.frequency` and `schedule.lookback` MUST be present for validation.
- Deploy MUST reject `outcome` unless, after lowercasing, it is `detection` or `incident`.
- Deploy MUST reject `trigger` unless, after lowercasing, it is `verbose` or `summary`.
- Deploy MUST reject `severity` unless it is `Informational`, `Low`, `Medium`, `High`, or `Critical`.
- `schedule.start` and `schedule.end` MAY be omitted. When set, they SHOULD be UTC timestamps `YYYY-MM-DDTHH:MM:SSZ`. An unquoted YAML timestamp MUST be rewritten to that form before it is sent.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `details` | [CrowdstrikeDetails](#details-crowdstrikedetails) | yes | — | Correlation outcome, trigger mode, and alert metadata. |
| `schedule` | [CrowdstrikeSchedule](#schedule-crowdstrikeschedule) | yes | — | How often the correlation search runs and how far it looks back. |
| `query` | string | yes | — | Correlation filter. Multiline. Sent as the rule `filter`. |
| `rule_id_bundle` | map[string, string] | no | null | Falcon rule id per tenant name. See [External rule ids](index.md#external-rule-ids). |

### `details` (CrowdstrikeDetails)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `trigger` | string | yes | `verbose` or `summary`, any case. Deploy lowercases the value. |
| `outcome` | string | yes | `detection` or `incident`, any case. Deploy lowercases the value. |
| `name` | string | no | Falcon rule name. Deploy uses the Tide rule `name` when omitted. |
| `description` | string | no | Falcon description. Deploy uses the Tide rule `description` when omitted. |
| `severity` | string | no | `Informational`, `Low`, `Medium`, `High`, or `Critical`. Deploy uses `response.alert_severity` when omitted. |
| `tactic` | string | no | Falcon tactic. Sent as given. |
| `technique` | string | no | Falcon technique. Sent as given. |

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
| `start` | string | no | Do not run before this UTC time. |
| `end` | string | no | Stop running at this UTC time. |

### Deploy

The customer id is the tenant `customer_id` with the segment after the first hyphen removed, lowercased.

`DELETION` deletes the rule when `rule_id_bundle` has an entry for the tenant. A create or update writes the Falcon status from the block strategy. The current deployer sends `active` when the strategy is `DISABLEMENT` and `inactive` for every other strategy, which is the reverse of [deployment.md](../deployment.md). Static validation does not apply that mapping. Aligning the deployer with the shared strategy is an implementation fix; it does not change this block's fields.

The rule comment records the contributors and that OpenTide performed the update.

## Relationships

- [platforms](index.md) — shared fields, no query validation, external ids
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
