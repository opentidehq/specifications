---
spec: platform-splunk
version: "1.0"
schema_id: platform::splunk::1.0
status: normative
supersedes: null
---

# Splunk (`platform::splunk::1.0`)

## Summary

`configurations.splunk` is a Splunk saved search. The detection text is SPL. Query validation is supported. Enterprise Security notable events, risk, and correlation search are optional blocks on top of the saved search.

The current block is the v3 layout. A `splunk::2.x` rule that still uses the flat keys is accepted and normalised onto this layout before validation. Both `opentide validate` and deploy use that normalisation.

Shared fields are defined in [platforms](index.md#shared-platform-block).

## Requirements

- Static validation MUST require a non-blank `query`, or a non-blank legacy `search` which is copied into `query`.
- `scheduling`, `trigger`, `actions`, and `correlation_search` MAY be omitted and still validate.
- Legacy flat keys (`search`, `cron_schedule`, `throttling`, `threshold`, `notable`, `risk`, `email`, and `scheduling.frequency` / `scheduling.lookback` / `scheduling.cron` / `scheduling.custom_time`) MUST be accepted and moved as defined in [Legacy splunk::2.x keys](#legacy-splunk2x-keys).
- A `query` or `scheduling.schedule` set on the v3 layout MUST win over `search` and `cron_schedule`.
- `search` and `cron_schedule` MUST be retained after normalisation so the object round-trips.
- Unknown keys that are not in the legacy set MUST fail validation.
- Deploy of a block whose `scheduling.schedule` is set, or whose `scheduling.type` is set to anything other than real time, MUST mark the saved search scheduled. A schedule with no `type` MUST still be scheduled.
- `scheduling.type: Real Time` (any case) MUST deploy a real-time search and MUST NOT require a cron schedule.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | SPL. Multiline. Legacy `search` fills this when `query` is empty. |
| `scheduling` | [SplunkScheduling](#scheduling-splunkscheduling) | no | null | Cron or frequency, and the search time range. |
| `trigger` | [SplunkTrigger](#trigger-splunktrigger) | no | null | Alert threshold, severity, and throttling. |
| `actions` | [SplunkActions](#actions-splunkactions) | no | null | Notable, risk, and email actions. |
| `correlation_search` | boolean | no | null | Force the Enterprise Security correlation-search action on or off. `null` follows the tenant. |
| `advanced` | map[string, any] | no | null | Extra `savedsearches.conf` keys, stringified at deploy. Hidden from templates. Generated schema marks the field deprecated in favour of the nested blocks. |
| `search` | string | no | null | Legacy v2 search string. Hidden from templates. Kept after it is copied to `query`. |
| `cron_schedule` | string | no | null | Legacy v2 cron. Hidden from templates. Kept after it is copied into `scheduling.schedule.cron`. |

### `scheduling` (SplunkScheduling)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | no | `Real Time` deploys `dispatch.earliest_time` and `dispatch.latest_time` as `rt`. Any other non-empty value, or a `schedule` with no `type`, deploys `is_scheduled = 1`. |
| `expires` | string | no | Splunk `alert.expires` (`2h`, `1d`). |
| `schedule` | [SplunkSchedule](#schedulingschedule-splunkschedule) | no | When the search runs. |
| `timerange` | [SplunkTimerange](#schedulingtimerange-splunktimerange) | no | Window the search covers. |

#### `scheduling.schedule` (SplunkSchedule)

Provide `cron`, or `frequency`. `frequency` is converted to cron using the tenant's `frequency_scheduling` mode (`random`, `current`, or `custom`).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `frequency` | string | no | `Nm`, `Nh`, or `Nd` (`5m`, `1h`, `1d`). Expected ranges are 1–59 minutes, 1–23 hours, 1–30 days. Values outside the range still convert, with a warning. |
| `cron` | string | no | Cron expression. Wins over `frequency` when both are set. |
| `custom_time` | string | no | Anchor for `frequency` when the tenant mode is `custom`. Format `HHhmm` (`09h15`). Required at deploy for that mode. |

#### `scheduling.timerange` (SplunkTimerange)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `lookback` | string | no | `Nm`, `Nh`, or `Nd`. Deploy converts it to a Splunk earliest time (`-90m@m`), including the tenant skew and offset. |
| `earliest` | string | no | Raw Splunk earliest time. Wins over `lookback`. |
| `latest` | string | no | Raw Splunk latest time. |

### `trigger` (SplunkTrigger)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `condition` | string | no | Splunk `counttype` (`number of events`, `number of hosts`, …). |
| `comparator` | string | no | Splunk `relation` (`greater than`, `less than`, …). |
| `threshold` | int | no | Splunk `quantity`. |
| `severity` | int | no | Splunk `alert.severity` (1–6). When omitted, deploy maps `response.alert_severity`. |
| `custom_condition` | string | no | Splunk `alert_condition` search. |
| `type` | string | no | `once` (any case) sets `alert.digest_mode` true. Any other value sets it false. |
| `throttling` | [SplunkThrottling](#triggerthrottling-splunkthrottling) | no | Suppression window. |

`response.alert_severity` maps to Splunk as:

| Tide severity | Splunk `alert.severity` |
|---------------|-------------------------|
| `Informational` | 2 |
| `Low` | 3 |
| `Medium` | 4 |
| `High` | 5 |
| `Critical` | 6 |

An unmapped value is sent as `3`.

#### `trigger.throttling` (SplunkThrottling)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fields` | list[string] | no | `alert.suppress.fields`, joined with commas. |
| `duration` | string | no | `alert.suppress.period`. When set, deploy also sets `alert.suppress` true. |
| `group_name` | string | no | `alert.suppress.group_name`. |

### `actions` (SplunkActions)

Notable and risk are sent only when the tenant has Enterprise Security enabled. Email is always eligible. A tenant modifier may still clear the allowed action list.

#### `actions.notable`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event.title` | string | no | `action.notable.param.rule_title`. |
| `event.description` | string | no | `action.notable.param.rule_description`. |
| `drilldown.name` | string | no | `action.notable.param.drilldown_name`. |
| `drilldown.search` | string | no | `action.notable.param.drilldown_search`. |
| `security_domain` | string | no | `action.notable.param.security_domain`, lowercased. |

#### `actions.risk`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `message` | string | no | `action.risk.param._risk_message`. |
| `risk_objects` | list[object] | no | Each item requires `field` (string), `type` (string), and `score` (int). |
| `threat_objects` | list[object] | no | Each item requires `field` (string) and `type` (string). |

Risk and threat objects are sent together as `action.risk.param._risk`.

#### `actions.email`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `to`, `cc`, `bcc` | string | no | Recipients. |
| `priority` | string | no | Mail priority. |
| `subject` | string | no | Subject line. Deploy key `action.email.subject`. |
| `message` | string | no | Body. Deploy key `action.email.message.alert`. |
| `content_type` | string | no | `action.email.content_type`. |
| `send_csv` | boolean | no | `action.email.sendcsv` as 1 or 0. |
| `send_pdf` | boolean | no | `action.email.sendpdf` as 1 or 0. |
| `inline_results` | boolean | no | `action.email.inline` as 1 or 0. |
| `include.results_link` | boolean | no | `action.email.include.results_link`. |
| `include.search_string` | boolean | no | `action.email.include.search`. |
| `include.trigger_condition` | boolean | no | `action.email.include.trigger`. |
| `include.trigger_time` | boolean | no | `action.email.include.trigger_time`. |

### `correlation_search`

| Value | Deploy |
|-------|--------|
| `true` / `false` | That value. |
| omitted | The tenant's `correlation_searches` flag, which defaults to true. |

When enabled, deploy sets `action.correlationsearch.enabled` and a label of `<rule name> - Rule`. Resolved ATT&CK techniques are written to `action.correlationsearch.annotations.mitre_attack`.

### Legacy `splunk::2.x` keys

Normalisation runs before field validation. It is idempotent.

| Legacy key | Moved to |
|------------|----------|
| `search` | `query`, only when `query` is missing or blank |
| `cron_schedule` | `scheduling.schedule.cron`, only when that schedule has neither `cron` nor `frequency` |
| `scheduling.frequency`, `scheduling.cron`, `scheduling.custom_time` | `scheduling.schedule.*` |
| `scheduling.lookback` | `scheduling.timerange.lookback` |
| `throttling` | `trigger.throttling` |
| `threshold` | `trigger.threshold` |
| top-level `notable` | `actions.notable` |
| top-level `risk` | `actions.risk` |
| top-level `email` | `actions.email` |

A flat key is not moved when the nested destination is already present. `search` and `cron_schedule` stay on the object.

### Deploy

The saved-search description is the Tide rule `description`. `response.responders` is sent as `alert.managedBy`.

| Block status strategy | Splunk result |
|-----------------------|---------------|
| `DISABLEMENT` | `disabled = true` |
| `DELETION` | Handled by the deployment plan's removal path for the saved search |
| any other | Saved search enabled |

Tenant modifiers in `splunk.toml` overlay `savedsearches.conf` keys after the block is compiled. Default modifiers fill gaps. Status, tenant, and flag modifiers overwrite.

## Relationships

- [platforms](index.md) — shared fields
- [rule-1.0.md](../objects/rule-1.0.md) — parent object
- [configuration.md](../configuration.md) — tenant `correlation_searches`, `frequency_scheduling`, `actions_enabled`
- [validation.md](../validation.md) — SPL query validation

## Defaults & overrides

| Field | Default |
|-------|---------|
| `correlation_search` | tenant `correlation_searches`, else true |
| `trigger.severity` | mapped from `response.alert_severity` |
| `frequency` cron minute and hour | tenant `frequency_scheduling` (`random` when unset on a tenant block) |
| `lookback` earliest | tenant skew (`allow_skew`) and `schedule_offset` |

## Examples

v3:

```yaml
configurations:
  splunk:
    enabled: true
    schema: platform::splunk::1.0
    status: STAGING
    query: |
      index=main sourcetype=WinEventLog EventCode=4688
      | head 1
    scheduling:
      schedule:
        frequency: 1h
      timerange:
        lookback: 2h
    trigger:
      condition: number of events
      comparator: greater than
      threshold: 0
      throttling:
        duration: 1h
        fields: [host]
    actions:
      notable:
        event:
          title: Suspicious process
        security_domain: threat
```

Legacy v2, still valid:

```yaml
configurations:
  splunk:
    schema: splunk::2.0
    search: index=main | head 1
    cron_schedule: "0 * * * *"
    threshold: 0
    throttling:
      fields: [host]
      duration: 1h
```

Fixtures: [fixtures/platforms/splunk.yaml](../../fixtures/platforms/splunk.yaml), [fixtures/platforms/splunk-legacy.yaml](../../fixtures/platforms/splunk-legacy.yaml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-30 | Initial field contract, including the splunk::2.x normalisation the engine already applies. |
