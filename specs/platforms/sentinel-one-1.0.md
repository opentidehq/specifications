---
spec: platform-sentinel-one
version: "1.1"
schema_id: platform::sentinel_one::1.0
status: normative
supersedes: null
---

# SentinelOne (`platform::sentinel_one::1.0`)

## Summary

`configurations.sentinel_one` is a SentinelOne STAR rule. The detection text is S1QL, either one query (`Single Event`) or an ordered set of queries (`Correlation`). Query validation is supported. SentinelOne assigns the remote rule id; opentide stores it per tenant in [deployment state](../deployment-state.md).

Shared fields are defined in [platforms](index.md#shared-platform-block).

## Requirements

- Static validation MUST require `condition`, and `condition.type` MUST be `Single Event` or `Correlation`.
- `condition.single_event` and `condition.correlation` MAY both be omitted and still validate. Deploy MUST fail unless the object that matches `type` is present.
- A correlation block MUST include `entity`, `match_in_order`, `time_window`, and at least the `sub_queries` list. Each sub-query MUST include `query` and `matches_required`.
- `response` and `details` MAY be omitted.
- `time_window`, when set, SHOULD use an `Nm` or `Nh` duration (`5m`, `1h`). Deploy converts those suffixes to minutes.
- `cool_off`, when set, SHOULD use the same `Nm` or `Nh` duration. The current deployer tests the value with `is str`, which is never true for a string instance, so a duration string is passed through unconverted. Aligning that comparison is an implementation fix; it does not change this field.
- The block MUST NOT contain `rule_id_bundle`, `rule_id`, or `rule_id::<tenant>`. Each fails `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)).

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `condition` | [SentinelOneCondition](#condition-sentinelonecondition) | yes | — | Single-event or correlation query. |
| `response` | [SentinelOneResponse](#response-sentineloneresponse) | optional | null | Threat verdict and network quarantine. Omitted means neither action is sent. |
| `details` | [SentinelOneDetails](#details-sentinelonedetails) | optional | null | Overrides for name, description, severity, and expiration. |

The rule is scoped to the tenant's `site_id` when that is set, otherwise to `account_id`.

### `condition` (SentinelOneCondition)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | yes | `Single Event` or `Correlation`. |
| `single_event` | object | optional | Required at deploy when `type` is `Single Event`. |
| `correlation` | object | optional | Required at deploy when `type` is `Correlation`. |
| `cool_off` | string | optional | Renotify window (`30m`, `1h`). Intended to become `renotifyMinutes`. The current deployer does not convert it; see Requirements. |

`single_event`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `query` | string | yes | S1QL. Multiline. Sent as `queryType: events`. |

`correlation`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `entity` | string | yes | Entity the sub-queries correlate on (`host`, `user`, …). |
| `match_in_order` | boolean | yes | Whether sub-queries must match in list order. |
| `time_window` | string | yes | Correlation window (`1h`, `30m`). |
| `sub_queries` | list[object] | yes | Each item has `query` (S1QL) and `matches_required` (int). |

A correlation rule is sent as `queryType: correlation`.

### `response` (SentinelOneResponse)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `treat_as_threat` | false \| `Malicious` \| `Suspicious` | yes | `false` is sent as `UNDEFINED`. |
| `network_quarantine` | boolean | yes | Quarantine the endpoint from the network. |

Both fields are required when `response` is present. Omitting `response` omits both actions.

### `details` (SentinelOneDetails)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | optional | STAR rule name. Deploy uses the Tide rule `name` when omitted. |
| `description` | string | optional | STAR description. Deploy uses the Tide rule `description` when omitted. |
| `severity` | string | optional | Sent as the STAR severity string. When omitted, deploy maps `response.alert_severity`: `Informational` and `Low` become `Low`; `Medium`, `High`, and `Critical` keep those names. |
| `expiration` | string | optional | When set, the rule is `Temporary` and this value is the expiration. When omitted, the rule is `Permanent`. |

A `details.severity` value is sent as written. It does not pass through the `response.alert_severity` map.

### Deploy

| Block status strategy | SentinelOne result |
|-----------------------|--------------------|
| `DISABLEMENT` | Update the bound remote rule with STAR status `Disabled`; without a binding, report `external_id_missing` and make no HTTP call. |
| `DELETION` | Delete the bound remote rule and remove the binding after successful deletion; without a binding, report `external_id_missing`. |
| any other | STAR status `Active`. Update when a binding exists; otherwise create and durably record the returned id. |

The binding is the tenant's entry under `sentinel_one` in `.opentide/states/deployment/<uuid>.json`, a canonical decimal string. A create is refused when the shard directory is gitignored or the run cannot persist state. The decision order and codes are in [deployment-state.md](../deployment-state.md#deploy-decisions).

## Relationships

- [platforms](index.md) — shared fields and external ids
- [deployment-state.md](../deployment-state.md) — where the STAR rule id is stored
- [rule-1.0.md](../objects/rule-1.0.md) — parent object
- [validation.md](../validation.md) — S1QL query validation

## Defaults & overrides

| Field | Default |
|-------|---------|
| Rule name and description | Tide rule `name` and `description` |
| Severity | mapped from `response.alert_severity` |
| Expiration | `Permanent` |
| `treat_as_threat: false` | sent as `UNDEFINED` |
| Scope | tenant `site_id`, else `account_id` |

## Examples

Single event:

```yaml
configurations:
  sentinel_one:
    enabled: true
    schema: platform::sentinel_one::1.0
    status: STAGING
    condition:
      type: Single Event
      single_event:
        query: |
          EventType = "Process Creation" AND TgtProcName Contains "cmd.exe"
      cool_off: 30m
    response:
      treat_as_threat: Suspicious
      network_quarantine: false
    details:
      severity: High
```

Correlation:

```yaml
condition:
  type: Correlation
  correlation:
    entity: host
    match_in_order: true
    time_window: 1h
    sub_queries:
      - query: EventType = "Process Creation"
        matches_required: 1
      - query: EventType = "File Modification"
        matches_required: 1
```

Fixture: [fixtures/platforms/sentinel-one.yaml](../../fixtures/platforms/sentinel-one.yaml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-30 | Initial field contract from the SentinelOne configuration model and deployer. |
| 1.1 | 2026-10-16 | `rule_id_bundle` and the `rule_id::<tenant>` alias are removed and fail `external_id_in_rule`. Deploy reads and writes the STAR rule id in [deployment state](../deployment-state.md); `DISABLEMENT` and `DELETION` without a binding report `external_id_missing` ([RFC 0010](../../rfcs/0010-deployment-external-ids.md)). Schema id unchanged. |
