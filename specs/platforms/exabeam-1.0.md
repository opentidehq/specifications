---
spec: platform-exabeam
version: "1.0"
schema_id: platform::exabeam::1.0
status: draft
supersedes: null
---

# Exabeam New-Scale SIEM (`platform::exabeam::1.0`)

## Summary

`configurations.exabeam` is one **correlation rule** of Exabeam's New-Scale Security Operations Platform (the New-Scale SIEM, Threat Detection Management). Deploy creates, replaces, disables, and deletes it through the Correlation Rules API (`/correlation-rules/v2/rules`), as every opentide platform deploys through its vendor's API.

A correlation rule is one or more **sequences**. Each sequence is a filter in the [Exabeam Query Language](../languages/exabeam-1.0.md) (profile `rule`) and a condition. The condition is either *any match* or a *threshold* (a function over the matching events within a window). Two or more sequences correlate within a common window, optionally on common fields. The author writes the sequences and the response settings. Deploy derives the rule name, description, and severity from the opentide rule, so those are not retyped.

Exabeam assigns every rule a UUID at create time. That id is kept in [deployment state](../deployment-state.md).

Shared fields are defined in [platforms](index.md#shared-platform-block). Research, sources, and alternatives are in [RFC 0017](../../rfcs/0017-exabeam-platform.md). This spec is a **draft**: it follows Exabeam's published API reference, and the [RFC's unresolved questions](../../rfcs/0017-exabeam-platform.md#unresolved-questions) need a tenant to settle before it becomes normative.

## Requirements

Static validation (`opentide validate`) and registry load:

- `status` MUST be present, as on `elastic`, `sysdig`, and `bitdefender`.
- `sequences` MUST be a non-empty list. Every sequence MUST have a non-blank `query`.
- Every `query` MUST be checked against the [Exabeam Query Language](../languages/exabeam-1.0.md) under the `rule` profile. Its errors fail the rule, and its warnings are reported.
- A block MUST satisfy every [constraint](#constraints). A violation MUST be reported with its constraint code.
- Unknown keys MUST fail, at the block root and inside every object in the field tables.
- Legacy external-id keys (`rule_id`, `rule_id_bundle`, `rule_id::<tenant>`) MUST fail with `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)).
- Field names in `group_by`, `threshold.field`, and `suppression.group_by` name fields in the tenant's data. They MUST NOT be checked against a closed list. A field the CIM catalogue does not have is the warning `exabeam_unknown_field`.

Deploy:

- Exabeam is state-backed. Deploy MUST follow the [deploy decisions](../deployment-state.md#deploy-decisions) of deployment state, storing the rule id under `platforms.exabeam.<tenant>`. Deploy MUST NOT find a rule by listing (`GET /correlation-rules/v2/rules`), by `nameContains`, or by the `opentide:<uuid>` marker in the description.
- Every update MUST send the whole rule (`PUT`, which replaces the rule), whatever the console changed in between.
- Deploy MUST NOT use the import or export endpoints.
- Deploy MUST NOT create, change, or delete a context table.
- Deploy MUST NOT write to the rule file.

Query validation:

- `opentide validate` checks every sequence query offline. `opentide validate query --platform exabeam --live` checks each query's filter on a tenant through Search ([Query validation](#query-validation)). It MUST NOT report the condition, window, or grouping as checked: Exabeam has no API to preview a rule.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `sequences` | list[[ExabeamSequence](#sequences-exabeamsequence)] | yes | — | One or more sequences, in the order the author reads them |
| `correlation` | [ExabeamCorrelation](#correlation-exabeamcorrelation) | conditional | — | Required with two or more sequences; not allowed with one |
| `severity` | string | optional | [derived](#severity) | `none`, `low`, `medium`, `high`, or `critical` |
| `outcome` | string | optional | `alert` | `alert` (an alert in Threat Center), `case` (a case), or `none` |
| `email` | [ExabeamEmail](#email-exabeamemail) | optional | null | Also send an email when the rule triggers |
| `suppression` | [ExabeamSuppression](#suppression-exabeamsuppression) | optional | null | Suppress repeated triggers |
| `delay` | duration | optional | null | Evaluation delay, `7m` to `180m` (`3h`). Null means Exabeam's default delay of 7 minutes. |
| `schedule` | list[[ExabeamRecurrence](#schedule-exabeamrecurrence)] | optional | null | When the rule is active. Null means always. |
| `test_mode` | boolean | optional | tenant `test_mode` | Run the rule in test mode: it triggers, writes a `rule-trigger-test` event, and has no outcome |

The shared `name` is the Exabeam rule name. Empty means the opentide rule `name`.

### `sequences[]` (ExabeamSequence)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | A filter in the [Exabeam Query Language](../languages/exabeam-1.0.md), profile `rule`. Multiline in YAML. |
| `name` | string | optional | null | Sequence name, shown in the console |
| `threshold` | [ExabeamThreshold](#threshold-exabeamthreshold) | optional | null | The condition. Without it, the sequence triggers on any matching event. |
| `group_by` | list[string] | optional | null | One to three fields. A threshold counts per value; any match triggers once per value. |

### `threshold` (ExabeamThreshold)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `function` | string | yes | — | `count`, `unique_count`, `value`, `max`, `min`, `sum`, or `average` |
| `field` | string | conditional | null | The field the function reads. Required except for `count`. `count` without a field counts events. |
| `operator` | string | yes | — | `more_than`, `less_than`, `between`, `in`, `not_in`, or `changed` |
| `value` | number, list, or absent | conditional | — | See the table below |
| `within` | duration | yes | — | The window: whole `m`, `h`, or `d` |

| `function` | `operator` | `value` |
|------------|------------|---------|
| `count`, `unique_count`, `max`, `min`, `sum`, `average` | `more_than`, `less_than` | a number (`count` and `unique_count`: a non-negative integer) |
| the same | `between` | a list of two numbers, low then high |
| `value` | `in`, `not_in` | a non-empty list of strings or numbers |
| `value` | `changed` | absent |

An absence rule is a threshold with `less_than` (`count less_than 1 within 24h`).

### `correlation` (ExabeamCorrelation)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `within` | duration | yes | — | The window every sequence's condition must be met in: whole `m`, `h`, or `d` |
| `group_by` | list[string] | optional | `[]` | Up to three fields every sequence shares (the API's limit; the console allows more) |

The sequences are evaluated in any order. The API's create and update calls have no ordering setting ([RFC 0017](../../rfcs/0017-exabeam-platform.md#unresolved-questions)).

### `suppression` (ExabeamSuppression)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `for` | duration | yes | — | Suppress repeated triggers for this long: whole `m`, `h`, `d`, or `w` |
| `group_by` | list[string] | optional | null | One to three fields. Suppress per value instead of for the whole rule. |

### `email` (ExabeamEmail)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `recipients` | list[string] | yes | — | One or more email addresses |
| `subject` | string | optional | the Exabeam rule name | Email subject |
| `attach_csv` | boolean | optional | `false` | Attach the matching events as CSV |

### `schedule[]` (ExabeamRecurrence)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `every` | string | yes | — | `day`, `week`, `month`, or `days` (a range of weekdays) |
| `from` | string | yes | — | Start time, UTC, `HH:MMZ` (`08:00Z`) |
| `to` | string | yes | — | End time, UTC, `HH:MMZ` |
| `days` | list | conditional | — | `week`: one or more weekday names (`monday` … `sunday`). `month`: day numbers 1–31. Not allowed otherwise. |
| `last_day` | boolean | optional | `false` | `month` only: also the last day of the month. A `month` recurrence has `days`, `last_day: true`, or both. |
| `first` | string | conditional | — | `days` only: the first weekday of the range |
| `last` | string | conditional | — | `days` only: the last weekday of the range |

### Durations

A duration is a positive whole number and one unit, with no space: `m` (minutes), `h` (hours), `d` (days), and, for `suppression.for` only, `w` (weeks). Exabeam takes a number and a unit, so a duration is sent as written: `90m` is 90 minutes, not 1h30m. Compound durations (`1h30m`) and ISO 8601 are invalid. `delay` is sent in minutes, and MUST be 7 to 180 minutes (`7m` to `180m`, `1h` to `3h`).

| Written | Sent |
|---------|------|
| `30m` | `{time: 30, unit: "minutes"}` |
| `4h` | `{time: 4, unit: "hours"}` |
| `1d` | `{time: 1, unit: "days"}` |
| `2w` (suppression) | `{suppressTime: 2, suppressUnit: "weeks"}` |
| `15m` (delay) | `{delay: true, delayTimeInMinutes: 15}` |
| `2h` (delay) | `{delay: true, delayTimeInMinutes: 120}` |

### Constraints

Static validation MUST reject a block that breaks any of these, and report the code:

| Code | Constraint |
|------|------------|
| `exabeam_sequences` | `sequences` is a non-empty list, and every sequence has a non-blank `query` |
| `exabeam_correlation` | `correlation` is set when there are two or more sequences, and not set when there is one. Its `within` is a duration. |
| `exabeam_threshold_function` | `threshold.function` is one of the seven functions. `field` is a non-blank string, and is set unless the function is `count`. |
| `exabeam_threshold_operator` | `threshold.operator` is allowed with the function ([threshold](#threshold-exabeamthreshold)) |
| `exabeam_threshold_value` | `threshold.value` has the shape its operator takes, and `count` and `unique_count` compare with integers |
| `exabeam_group_by` | Every `group_by` (sequence, correlation, suppression) is a list of one to three distinct non-blank strings. `correlation.group_by` may be empty. |
| `exabeam_duration` | Every duration is a [duration](#durations) with a unit its field allows; `delay` is 7 to 180 minutes |
| `exabeam_severity` | `severity` is `none`, `low`, `medium`, `high`, or `critical` |
| `exabeam_outcome` | `outcome` is `alert`, `case`, or `none` |
| `exabeam_email` | `email.recipients` is a non-empty list of distinct addresses (`local@domain`); `subject` is non-blank when set |
| `exabeam_schedule` | Each recurrence has a known `every`, `from` and `to` matching `^([01]?[0-9]|2[0-3]):[0-5][0-9]Z$`, and exactly the day keys its `every` takes, with valid weekday names and day numbers |
| `exabeam_name_length` | The Exabeam rule name (shared `name`, else the rule `name`) is at most 128 characters |
| `exabeam_context_table_trigger` | A sequence whose query uses a context table (`IN "…"`) has no `threshold`. Exabeam requires "Trigger on first match" with a context table lookup. |

Every implementation reports each code at the path in this table:

| Code | Field path |
|------|------------|
| `exabeam_sequences` | `sequences`, or `sequences.<N>.query` |
| `exabeam_correlation` | `correlation` |
| `exabeam_threshold_function`, `exabeam_threshold_operator`, `exabeam_threshold_value` | `sequences.<N>.threshold` |
| `exabeam_group_by` | `sequences.<N>.group_by`, `correlation.group_by`, or `suppression.group_by` |
| `exabeam_duration` | `sequences.<N>.threshold.within`, `correlation.within`, `suppression.for`, or `delay` |
| `exabeam_severity`, `exabeam_outcome`, `exabeam_email` | `severity`, `outcome`, `email` |
| `exabeam_schedule` | `schedule.<N>`, or `schedule` when it is not a non-empty list |
| `exabeam_name_length` | `name` |
| `exabeam_context_table_trigger` | `sequences.<N>.threshold` |
| language codes ([exabeam-1.0](../languages/exabeam-1.0.md#diagnostics)) | `sequences.<N>.query` |

### Advisories

Validation reports these as warnings ([validation](../validation.md#platform-advisories)):

| Code | When |
|------|------|
| `exabeam_outcome_silent` | `outcome` is `none` and there is no `email`. The rule only writes a `rule-trigger` event. |
| `exabeam_correlation_window` | `correlation.within` is shorter than the longest `threshold.within`. Exabeam's guide asks for at least the longest sequence window. |
| `exabeam_name_duplicate` | Two enabled blocks in the workspace resolve to the same Exabeam rule name. Exabeam does not document whether names are unique, and its import refuses a rule whose name exists. |

### Name and description

| Exabeam field | Derivation |
|---------------|------------|
| `name` | Shared `name`, else the opentide rule `name` |
| `description` | The opentide `description` with whitespace collapsed to single spaces, then a blank line, then `ATT&CK: ` and the rule's ATT&CK technique ids joined by `, ` (the line is left out when there are none), then a line `opentide: <metadata.uuid>` |

Technique ids are the rule's `techniques`, then those inherited through `detection_model`, without duplicates: the same union [elastic-1.0](elastic-1.0.md#attck) uses. The create and update calls have no MITRE, use case, or tag field, so the description carries the mapping for analysts. Deploy never reads it back.

### Severity

`severity`, else from `response.alert_severity`:

| `alert_severity` | Exabeam `severity` |
|------------------|--------------------|
| `Critical` | `critical` |
| `High` | `high` |
| `Medium` | `medium` |
| `Low` | `low` |
| `Informational` | `none` |
| missing | `medium` |

### Compiled body

The body of `POST /correlation-rules/v2/rules` (create) and `PUT /correlation-rules/v2/rules/{id}` (update) is the same:

| Exabeam key | From |
|-------------|------|
| `name`, `description`, `severity` | [Name and description](#name-and-description), [Severity](#severity) |
| `enabled` | `false` under `DISABLEMENT`, else `true` |
| `testMode` | `test_mode`, else tenant `test_mode`, else `false` |
| `sequencesConfig.sequences[]` | Per sequence: `name` (when set), `query` (trimmed), and `condition` |
| `condition`, any match | `{triggerOnAnyMatch: true, groupByOption, groupBy}` |
| `condition`, threshold | `{triggerOnAnyMatch: false, groupByOption, groupBy, functionType, subject, field, operator, value, time, unit}`: `subject` is `field` when `field` is set, else `event`; `field` is left out for `event`; `value` is a string (below) |
| `groupByOption`, `groupBy` | `true` and the list when `group_by` is set; `false` and `[]` otherwise |
| `sequencesConfig.commonProperties` | Two or more sequences: `{groupBy, time, unit}` from `correlation`. One sequence: left out. |
| `sequencesConfig.outcomes` | `sendAlertTriage` (`outcome: alert`), `createCase` (`outcome: case`), and `sendEmail` (`email` set), each `true` or `false`; then `alertTriage: {name: <name>}` for `alert`, `case: {description: <name>}` for `case`, and `email: {recipients, subject, attachCsv}` with `email` (`subject` defaults to the Exabeam rule name) |
| `suppressConfig` | `{suppressOption: true, suppressTime, suppressUnit, granularSuppressOption, suppressGroupFields}` (the last two only with `group_by`), else `{suppressOption: false}` |
| `delayConfig` | `{delay: true, delayTimeInMinutes}`, else `{delay: false}` |
| `scheduleConfig` | `{recurrences: […]}` when `schedule` is set, else left out |

`value` is sent as a string, as the API takes it: a number in its shortest decimal form (`3`, `2.5`), a list joined by `,` with no spaces (`0.0.0.0,1.1.1.1`, and `low,high` for `between`), and `""` for `changed`.

A recurrence is sent as `{recurrenceType, startTime, endTime, …}`: `day` → `DAILY`; `week` → `WEEKLY` with `daysOfWeek` (upper case); `month` → `MONTHLY` with `daysInMonth` and `lastDayOfMonth`; `days` → `CUSTOM` with `dayFrom` and `dayTo` (upper case).

Keys are sent in the order of this table. The [goldens](#examples) are the exact bodies.

### Tenant setup

```toml
[platform]
enabled = true
identifier = "exabeam"
name = "Exabeam New-Scale SIEM"
subschema = "Exabeam New-Scale SIEM"
description = "Correlation rules for Exabeam New-Scale Security Operations Platform."
flags = []

[[tenants]]
name = "exabeam-eu"
strategies = ["RELEASE"]
[tenants.setup]
ssl = true
region = "eu"
client_id = "$EXABEAM_CLIENT_ID"
client_secret = "$EXABEAM_CLIENT_SECRET"
test_mode = false
```

| `tenants.setup` field | Type | Required | Default | Meaning |
|-----------------------|------|----------|---------|---------|
| `region` | string | yes | — | `us-west`, `us-east`, `ca`, `eu`, `sa`, `sg`, `ch`, `jp`, `au`, or `uk`. The API base URL is `https://api.<region>.exabeam.cloud`. It is not derived from the console URL (`use1` is `us-east`, `euw6` is `ch`). |
| `client_id` | string | yes | — | The API key. MUST be a `$ENV` reference. |
| `client_secret` | string | yes | — | The API key secret. MUST be a `$ENV` reference. |
| `api_url` | string | no | from `region` | An HTTPS base URL that replaces the region's, for a gateway Exabeam adds later |
| `test_mode` | bool | no | `false` | Default `test_mode` for blocks that do not set it. A staging tenant can run every rule in test mode. |
| `ssl` | bool | yes | — | Shared tenant setup (TLS verification) |

The API key needs the **Correlation Rules** permission at Read Write Delete. `--live` validation and `opentide query` also need **Search, Analyze and Export**. A tenant with an unknown setup key, a literal secret, or an unknown `region` fails configuration load.

### Deploy

Exabeam is **state-backed**, like Defender for Endpoint, SentinelOne, CrowdStrike, Sysdig, and Bitdefender:

- **Where.** `platforms.exabeam.<tenant>` in `.opentide/states/deployment/<uuid>.json`. The tenant key is the configured tenant `name`, whitespace-stripped.
- **Shape.** The `id` of the create response, a UUID, stored lower-case and canonical. It matches `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`.
- **No orphan creates.** Deploy MUST NOT create a rule unless the returned id can be kept (`deployment_state_ignored`, `deployment_state_unpersisted`), as on every state-backed platform.
- **Writes.** The binding is written as soon as the create returns, and removed after a successful `DELETE`, a `404` on delete, or the `DISABLEMENT`-on-missing path below.

**Authentication.** Deploy gets a token with `POST /auth/v1/token` (`{"client_id", "client_secret", "grant_type": "client_credentials"}`) and sends `Authorization: Bearer <token>`. It requests one token per tenant per run and reuses it. A `401` whose body says the token expired gets one new token and one retry. Exabeam allows 50 token requests per 5 minutes per source IP and asks clients to keep to a few tokens a day.

**Rate limit.** Exabeam allows 100 API requests per minute per source IP. The client MUST space its requests to at most 100 per rolling minute across every Exabeam tenant of the run. A `429` waits out `Retry-After` (60 seconds when absent) and retries the same request.

| Block status strategy | Binding | Exabeam calls |
|-----------------------|---------|---------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | `POST /correlation-rules/v2/rules` with the [compiled body](#compiled-body); `201` returns the rule, whose `id` is recorded |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present | `PUT /correlation-rules/v2/rules/{id}` with the whole compiled body |
| `DISABLEMENT` | present | `PUT` with the whole compiled body and `enabled: false` |
| `DELETION` | present | `DELETE /correlation-rules/v2/rules/{id}`, then the binding is removed |
| `DISABLEMENT`, `DELETION` | none | `external_id_missing` (warning), no call |

A `PUT` sets `enabled` too, so deploy never calls `/enable` or `/disable` separately.

Failure handling:

- **Rule gone.** A `PUT` answered `404` creates the rule again and replaces the binding, with the warning `exabeam_rule_recreated`. Under `DISABLEMENT` it creates nothing, removes the binding, and warns `exabeam_rule_missing`. A `DELETE` answered `404` succeeds and removes the binding.
- **No id.** A `201` whose `id` is not a UUID fails the rule with `exabeam_create_no_id`, naming the rule `name` so the operator can remove it in the console.
- **Unconfirmed create.** A create with no answer (timeout, connection reset) or a `5xx` answer MUST NOT be retried. It fails the rule with `exabeam_create_unconfirmed`, naming the rule. Exabeam may have created the rule, and deploy never lists rules to find it.
- **Rejected.** A `400` fails the rule with `exabeam_request_rejected` and Exabeam's `errors[].code`, `message`, and `fields`, and the `traceId`.
- **Not licensed.** A `409` ("Feature is not enabled for subscription") stops the tenant with `exabeam_feature_unavailable`.
- **Unauthorized.** A `401` after the retry, or a `403`, stops the tenant with `exabeam_tenant_unauthorized`.
- **Auto-disabled.** When the rule a `PUT` returns has `autoDisabled: true`, deploy warns `exabeam_rule_auto_disabled`. Exabeam stops a rule that matches more than 500 times or triggers more than 50 times in five minutes, or whose query or context table is broken.

### Query validation

| Check | Exabeam |
|-------|---------|
| `opentide validate` (offline) | yes: the block constraints and every sequence query under the language's `rule` profile |
| `opentide validate query` (offline) | yes: a rule's sequence queries (`rule`), a hunt (`search`), or a `.exabeam` file (`search`) |
| `opentide validate query --live` | yes, the filter only: each query is sent to Search on each tenant (below) |
| `opentide query` | yes: a hunt through Search |

**`--live`** sends each query as `POST /search/v2/events` with `filter` set to the query, `fields: ["*"]`, `limit: 1`, and the last 15 minutes (`startTime`, `endTime`), the window the console's "Test Last 15 mins" uses. A `200` means the tenant accepted the filter and is reported as valid, with the row count as information only. A `400` is invalid, with Exabeam's message. Any other answer is an error, never a pass. The condition, windows, grouping, outcomes, and the rule as a whole are not checked: no API previews a rule, and `testMode` creates one.

**`opentide query`** sends the hunt as the `filter` of `POST /search/v2/events`, with `fields: ["*"]` unless the query selects columns, the run's time range, and `limit` at most 3,000 (the API's default and the most it returns). The search is synchronous and has no job id. A runner that stops waiting closes the connection; the API has no cancel. Nothing is saved on the tenant.

## Relationships

- [Exabeam Query Language](../languages/exabeam-1.0.md) — the `query` of every sequence, and `system: exabeam` hunts
- [platforms](index.md) — shared block fields and the capability matrix
- [deployment-state.md](../deployment-state.md) — where the Exabeam rule id lives
- [deployment.md](../deployment.md) — status strategies
- [validation.md](../validation.md) — advisories, language diagnostics, query validation
- [rule-1.0.md](../objects/rule-1.0.md), [rule-1.1.md](../objects/rule-1.1.md) — `configurations.exabeam`, `searches[]` with `system: exabeam`
- [RFC 0017](../../rfcs/0017-exabeam-platform.md) — research and design

## Defaults & overrides

| Setting | Default | Override |
|---------|---------|----------|
| Block `status` | none (required) | Per-block YAML |
| `severity` | from `response.alert_severity`, else `medium` | `severity` |
| `outcome` | `alert` | `outcome` |
| `test_mode` | tenant `test_mode`, else `false` | `test_mode` |
| `delay` | Exabeam's 7 minutes | `delay` |
| `schedule` | always active | `schedule` |
| Correlation group-by | none | `correlation.group_by` |

## Examples

Fixtures and the bodies deploy sends for them:

| Fixture | What it shows |
|---------|---------------|
| [fixtures/platforms/exabeam.yaml](../../fixtures/platforms/exabeam.yaml) | The smallest block: one sequence, any match |
| [fixtures/valid/rule-exabeam-threshold-1.0.yaml](../../fixtures/valid/rule-exabeam-threshold-1.0.yaml) | A threshold (`unique_count` of users per source IP), suppression, a case outcome |
| [fixtures/valid/rule-exabeam-sequence-1.0.yaml](../../fixtures/valid/rule-exabeam-sequence-1.0.yaml) | Two sequences correlated on `host`, a delay, a schedule, an email, and a `system: exabeam` hunt (`rule::1.1`) |
| [fixtures/platforms/exabeam/tenant.toml](../../fixtures/platforms/exabeam/tenant.toml) | The tenant the goldens deploy to |
| [fixtures/platforms/exabeam/](../../fixtures/platforms/exabeam/) `*.api.json` | Create, update, and disable bodies, a sequence create, and the `--live` search body |

A threshold block:

```yaml
configurations:
  exabeam:
    enabled: true
    schema: platform::exabeam::1.0
    status: STAGING
    outcome: case
    sequences:
      - name: Failed logins from outside
        query: |
          activity_type:"app-login" AND outcome:"fail"
          AND NOT src_ip:[10.0.0.0/8] AND NOT src_ip:[172.16.0.0/12] AND NOT src_ip:[192.168.0.0/16]
        group_by: [src_ip]
        threshold:
          function: unique_count
          field: user
          operator: more_than
          value: 3
          within: 30m
    suppression:
      for: 1h
      group_by: [src_ip]
```

Its sequence compiles to:

```json
{
  "name": "Failed logins from outside",
  "query": "activity_type:\"app-login\" AND outcome:\"fail\"\nAND NOT src_ip:[10.0.0.0/8] AND NOT src_ip:[172.16.0.0/12] AND NOT src_ip:[192.168.0.0/16]",
  "condition": {
    "triggerOnAnyMatch": false,
    "groupByOption": true,
    "groupBy": ["src_ip"],
    "functionType": "unique_count",
    "subject": "field",
    "field": "user",
    "operator": "more_than",
    "value": "3",
    "time": 30,
    "unit": "minutes"
  }
}
```

Invalid fixtures: [rule-exabeam-correlation-single.yaml](../../fixtures/invalid/rule-exabeam-correlation-single.yaml) (`exabeam_correlation`), [rule-exabeam-threshold-operator.yaml](../../fixtures/invalid/rule-exabeam-threshold-operator.yaml) (`exabeam_threshold_operator`), [rule-exabeam-context-table-threshold.yaml](../../fixtures/invalid/rule-exabeam-context-table-threshold.yaml) (`exabeam_context_table_trigger`), [rule-exabeam-delay.yaml](../../fixtures/invalid/rule-exabeam-delay.yaml) (`exabeam_duration`), and [rule-exabeam-advanced-query.yaml](../../fixtures/invalid/rule-exabeam-advanced-query.yaml) (`exabeam_advanced_in_rule`).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-11-11 | Draft ([RFC 0017](../../rfcs/0017-exabeam-platform.md)): one correlation rule per block; sequences with any-match or threshold conditions, correlation, suppression, delay, schedule, outcomes; derived name, description (with ATT&CK), and severity; whole-body `PUT`; the rule UUID in deployment state; `--live` filter checks and hunts through Search. |
