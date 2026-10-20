---
spec: platform-elastic
version: "1.0"
schema_id: platform::elastic::1.0
status: normative
supersedes: null
---

# Elastic Security (`platform::elastic::1.0`)

## Summary

`configurations.elastic` is an Elastic Security detection rule. Deploy creates it through the Kibana detection engine API (`/api/detection_engine/rules`, API version `2023-10-31`). One platform serves self-managed, Elastic Cloud Hosted, and Elastic Cloud Serverless Security: the deployment type changes only the tenant URLs, the credentials, and which features the licence or project tier enables.

`type` selects one of seven rule types, every type the Security create-rule UI offers except a saved query. The detection language comes from the block, not from the platform: KQL or Lucene for `query`, `threshold`, `new_terms`, and `threat_match`; EQL for `eql`; ES|QL for `esql`; none for `machine_learning`. Query validation is supported and live only: Kibana rule preview plus the [Elasticsearch checks](#elasticsearch-checks), run against a tenant. There is no offline syntax check.

The Kibana `rule_id` is the rule's `metadata.uuid`, so one UUID addresses the rule in every tenant and space. Elastic never stores an external id: Kibana's internal `id` is not recorded in the block, in the rule file, or in [deployment state](../deployment-state.md).

Shared fields (`enabled`, `name`, `schema`, `status`, `flags`, `tenants`, `contributors`) are defined in [platforms](index.md#shared-platform-block). On this block `status` is required, and it alone decides whether the deployed rule is enabled. The design, the research behind it, and a reference test against Kibana 8.19 and 9.5 are in [RFC 0007](../../rfcs/0007-elastic-security-platform.md).

## Requirements

Static validation (`opentide validate`) and registry load:

- `type` and `status` MUST be present. `type` MUST be one of `query`, `eql`, `esql`, `threshold`, `new_terms`, `threat_match`, or `machine_learning`.
- `query` MUST be present for every type except `machine_learning`. When present it MUST be a non-blank string.
- A block MUST satisfy every [constraint](#constraints). A violation MUST be reported with its constraint code.
- Unknown keys MUST fail, at the block root and inside every object in the field tables. The open objects are `filters[].meta`, `filters[].query`, the entries of `threat.filters`, the entries of `actions.notify`, and the `osquery` object of an `actions.respond` entry.
- Legacy external-id keys (`rule_id`, `rule_id_bundle`, `rule_id::<tenant>`) at the block root MUST fail with `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)). Registry load drops those keys and passes every other key to the model, so registry load accepts exactly the blocks static validation accepts, apart from the legacy keys.
- Field names (`suppression.group_by`, `threshold.field`, `threshold.cardinality.field`, `new_terms.fields`, `highlighted_fields`, `required_fields[].name`, `threat.mapping[].entries[].field` and `value`) name fields in the tenant's data. They MUST NOT be checked against a closed list. Deploy checks the aggregation, timestamp, and indicator fields against the tenant instead ([Elasticsearch checks](#elasticsearch-checks)).
- Durations MUST follow [Durations](#durations).

Deploy:

- Every Kibana request MUST carry `elastic-api-version: 2023-10-31` and `Authorization: ApiKey <api_key>`. Every Kibana request other than `GET` MUST also carry `kbn-xsrf: true`. Elasticsearch requests use the same API key.
- The compiled body MUST NOT contain `id` or `version`. Deploy MUST NOT call `_bulk_create`, `_bulk_update`, or `_bulk_delete`, which Kibana 9.0 removed.
- Deploy MUST run the [Elasticsearch checks](#elasticsearch-checks) before every create or update of a rule. A failed check fails that rule: it is not created, updated, or replaced.
- Deploy MUST NOT modify an Elastic prebuilt rule ([Deploy](#deploy)).
- Deploy MUST NOT write to the rule file and MUST NOT create a deployment-state shard.
- Deploy MUST NOT delete a remote rule that has no MDR. Orphan pruning is not part of this revision.
- Deploy MUST NOT call Kibana Stack alerting (`/api/alerting/rule`), Watcher, Cases, Fleet, Elastic Defend policy or artifact APIs, or the prebuilt-rule installer. It MUST NOT create or edit data views and MUST NOT write the space settings `securitySolution:defaultIndex` or `securitySolution:defaultThreatIndex`.
- When a tenant sets `suppression = false`, deploy MUST omit `alert_suppression` and MUST warn once per affected rule.

Query validation:

- `opentide validate query --platform elastic --live` MUST preview each rule and run the Elasticsearch checks ([Query validation](#query-validation)). Without `--live` the command refuses and names `--live`, as on every platform.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `type` | string | yes | — | Rule type ([Rule types](#rule-types)). Kibana cannot change it in place; see [Deploy](#deploy). |
| `status` | string | yes | — | Shared field, required on this block. A status from [deployment.md](../deployment.md). The rule's own `status` is not read. |
| `query` | string | yes, except `machine_learning` | null | The event query, in the language the type selects. Multiline. Not sent for `machine_learning`. |
| `language` | string | optional | null | `kuery` (KQL) or `lucene`, for the event query of `query`, `threshold`, `new_terms`, and `threat_match`. Compiled as `kuery` when omitted. MUST NOT be set for `eql`, `esql`, or `machine_learning`. |
| `index` | list[string] | optional | null | Index patterns. A single pattern is a one-item list (`[logs-*]`). See [Data source](#data-source). |
| `data_view_id` | string | optional | null | One existing Kibana data view. Replaces `index`. |
| `filters` | list[[ElasticFilter](#filters-elasticfilter)] | optional | null | Rule query filters. Not Elastic Defend event filters. |
| `scheduling` | [ElasticScheduling](#scheduling-elasticscheduling) | optional | null | Runs every, additional look-back, and max alerts per run. |
| `severity` | string \| [ElasticSeverity](#severity-elasticseverity) | optional | null | An `alert_severity` value, or a default plus severity overrides ([Severity and risk](#severity-and-risk)). |
| `risk` | int \| [ElasticRisk](#risk-elasticrisk) | optional | null | Risk score 0–100, or a score plus risk score overrides. |
| `suppression` | [ElasticSuppression](#suppression-elasticsuppression) | optional | null | Alert suppression. |
| `highlighted_fields` | list[string] | optional | null | Custom highlighted fields on the alert. |
| `threshold` | [ElasticThreshold](#threshold-elasticthreshold) | iff `type: threshold` | null | Group-by fields and count. |
| `new_terms` | [ElasticNewTerms](#new_terms-elasticnewterms) | iff `type: new_terms` | null | Fields whose new values alert, and the history window. |
| `eql` | [ElasticEql](#eql-elasticeql) | optional, `type: eql` only | null | EQL-only settings. |
| `threat` | [ElasticThreatMatch](#threat-elasticthreatmatch) | iff `type: threat_match` | null | The indicator side of an indicator match rule. Not the ATT&CK array ([ATT&CK](#attck)). |
| `machine_learning` | [ElasticMachineLearning](#machine_learning-elasticmachinelearning) | iff `type: machine_learning` | null | Anomaly jobs and threshold. |
| `integration` | list[string \| [ElasticIntegration](#integration-elasticintegration)] | optional | null | Integrations the rule expects. Recorded on the rule; Fleet is not touched. |
| `required_fields` | list[[ElasticRequiredField](#required_fields-elasticrequiredfield)] | optional | null | Fields the rule needs, with their mapping types. |
| `guide` | [ElasticGuide](#guide-elasticguide) | optional | null | Investigation guide and Setup guide. |
| `false_positives` | list[string] | optional | null | Known false positives. |
| `tags` | list[string] | optional | null | Rule tags, after `OpenTide` and the tenant tags. |
| `exceptions` | [ElasticExceptions](#exceptions-elasticexceptions) | optional | null | Exception lists to attach. |
| `building_block` | boolean | optional | `false` | Building block rule: alerts are hidden from the default Alerts view. |
| `overrides` | [ElasticOverrides](#overrides-elasticoverrides) | optional | null | Rule name override and timestamp override. |
| `actions` | [ElasticActions](#actions-elasticactions) | optional | null | Rule actions, response actions, and the Timeline template. |

Not authored, because the Security create-rule screens do not ask for them: saved queries (`saved_id`), the prebuilt-rule `license` string, `concurrent_searches`, `items_per_search`, `meta`, `output_index`, `namespace`, and `throttle`. The last six are kept from the remote rule on update ([Deploy](#deploy)).

### Rule types

| `type` | Security UI name | `query` | `language` | Type object |
|--------|------------------|---------|------------|-------------|
| `query` | Custom query | KQL or Lucene | optional | — |
| `eql` | Event correlation | EQL | MUST NOT be set | `eql`, optional |
| `esql` | ES\|QL | ES\|QL | MUST NOT be set | — (`FROM` selects the data) |
| `threshold` | Threshold | KQL or Lucene | optional | `threshold`, required |
| `new_terms` | New terms | KQL or Lucene | optional | `new_terms`, required |
| `threat_match` | Indicator match | KQL or Lucene (the event query) | optional (the event query) | `threat`, required |
| `machine_learning` | Machine learning | not used | MUST NOT be set | `machine_learning`, required |

A **new terms** rule alerts when a value, or a combination of up to three values, appears that the rule has not seen in the history window. It does not count events; a threshold rule does.

### Data source

On `query`, `eql`, `threshold`, `new_terms`, and the event side of `threat_match`, the compiled `index` is the block `index` when set, otherwise the tenant `setup.index`, otherwise absent. When it is absent, Kibana applies the space setting `securitySolution:defaultIndex`. `data_view_id` names one existing data view and replaces that chain. `esql` and `machine_learning` send neither `index` nor `data_view_id`: an ES|QL `FROM` clause and a job's datafeed select their data. `threat.index` is always required; the indicator UI pre-fills `logs-ti_*`, but the API does not.

### Durations

A duration is a string in one of two equivalent forms:

```text
; literals are case-sensitive
duration  = shorthand / iso8601
shorthand = [n "d"] [n "h"] [n "m"] [n "s"]                 ; at least one part
iso8601   = "P" [n "D"] ["T" [n "H"] [n "M"] [n "S"]]       ; at least one part
n         = 1*DIGIT
```

- **Shorthand** is single-unit (`90s`, `5m`, `1h`, `14d`) or compound (`1h10m`, `1d2h`, `2m30s`). Units are lower case, appear in the order `d`, `h`, `m`, `s`, and each appears at most once.
- **ISO 8601** is the same set of whole days, hours, minutes, and seconds (`PT1H`, `P14D`, `P1DT2H`), with upper-case designators. After `T` at least one time part MUST follow.
- The value is the sum of its parts, so `1h10m` and `PT1H10M` are the same duration. Weeks, fractions, signs, and spaces are invalid.
- Every duration MUST be greater than zero, except `scheduling.lookback`, which MAY be zero (`0m`).

Kibana accepts only a single-unit value: it rejects ISO 8601 and weeks in `interval`, and `alert_suppression.duration` has no `d` unit. The compiler therefore sends every duration as one whole number in the largest unit that divides it exactly, choosing from `d`, `h`, `m`, `s`, and from `h`, `m`, `s` for `alert_suppression.duration`:

| Written | `interval` / `from` | `alert_suppression.duration` | `history_window_start` |
|---------|---------------------|------------------------------|------------------------|
| `5m` | `5m` / `now-5m` | `{value: 5, unit: m}` | `now-5m` |
| `90s` | `90s` / `now-90s` | `{value: 90, unit: s}` | `now-90s` |
| `60m` | `1h` / `now-1h` | `{value: 1, unit: h}` | `now-1h` |
| `1d` | `1d` / `now-1d` | `{value: 24, unit: h}` | `now-1d` |
| `14d` | `14d` / `now-14d` | `{value: 336, unit: h}` | `now-14d` |
| `PT1H` | `1h` / `now-1h` | `{value: 1, unit: h}` | `now-1h` |
| `1h10m` | `70m` / `now-70m` | `{value: 70, unit: m}` | `now-70m` |
| `2m30s` | `150s` / `now-150s` | `{value: 150, unit: s}` | `now-150s` |
| `1d2h` | `26h` / `now-26h` | `{value: 26, unit: h}` | `now-26h` |

The `from` column shows the duration alone. A rule's `from` is the sum of `interval` and `lookback` ([Schedule](#schedule)).

### Constraints

Static validation MUST reject a block that breaks any of these, and report the code:

| Code | Constraint |
|------|------------|
| `type_block` | `type` is one of the seven types. `threshold` iff `type: threshold`. `new_terms` iff `type: new_terms`, and it has `fields` and `history_window_start`. `eql` only for `type: eql`. `threat` iff `type: threat_match`, and it has `index`, `query`, and `mapping`. `machine_learning` iff `type: machine_learning`, and it has `job_id` and `anomaly_threshold`. `query` is required except for `machine_learning`. `actions` is an object, not a list. The Kibana flat names and the retired pre-grouping keys are invalid at the block root: `saved_id`, `interval`, `from`, `license`, `meta`, `alert_suppression`, `related_integrations`, `investigation_fields`, `max_signals`, `note`, `setup`, `endpoint_exceptions`, `exceptions_list`, `timeline_id`, `timeline_title`, `timestamp_override`, `timestamp_override_fallback_disabled`, `risk_score`, `risk_score_mapping`, `severity_mapping`, `timestamp_field`, `event_category_override`, `tiebreaker_field`, `new_terms_fields`, `history_window_start`, `threat_index`, `threat_query`, `threat_language`, `threat_mapping`, `threat_filters`, `threat_indicator_path`, `concurrent_searches`, `items_per_search`, `machine_learning_job_id`, `anomaly_threshold`, `rule_name_override`, `response_actions`, `timestamp`, `timeline`, and `passthrough`. |
| `language` | `language` MUST NOT be set for `eql`, `esql`, or `machine_learning`. |
| `esql_source` | `esql` and `machine_learning` MUST NOT set `index`, `data_view_id`, or `filters`. |
| `index_xor_data_view` | `index` and `data_view_id` are mutually exclusive. |
| `index_list` | `index` and `threat.index`, when set, are lists of one or more non-empty pattern strings. A string is invalid. `index` itself is optional. |
| `suppression_shape` | `suppression` is an object. For `threshold`, `suppression.duration` is required and `group_by` is forbidden. For every other type, `group_by` is required, with 1–3 distinct, non-empty field names. |
| `new_terms_fields` | `new_terms.fields` is a list of 1–3 entries. |
| `threshold_fields` | `threshold.field` has 0–5 entries, and `threshold.value` is an integer of at least 1. |
| `risk_score` | `risk`, or `risk.score` when set, is an integer in 0–100. |
| `duration` | Every duration follows [Durations](#durations) and is greater than zero. `scheduling.lookback` may be zero. |
| `filter_shape` | Each entry of `filters` and `threat.filters` is exactly one complete shape: the phrase shorthand `{field, value, negate?}` or a raw `{meta, query}` filter. An entry with keys of both shapes, with neither, or with half of one is invalid. |
| `exception_type` | `exceptions.lists[].type` is `detection` or `rule_default`. The Elastic Endpoint list is attached only by `exceptions.endpoint: true`. |
| `severity` | `severity`, or `severity.default`, is a value of the `alert_severity` vocabulary (`Informational`, `Low`, `Medium`, `High`, `Critical`), compared case-insensitively. An unknown value is invalid. It is never compiled to a fallback. |
| `response_action` | Each `actions.respond` entry is `{endpoint, comment?, field?}` with `endpoint` one of `isolate`, `kill-process`, `suspend-process`, or `runscript`, or `{osquery}` with a non-empty `osquery.query`. No other key is allowed beside them. Kibana's own response-action shape (`action_type_id`, `params`) is invalid. `runscript` needs Kibana 9.4 or later. |

A type object (`threshold`, `new_terms`, `eql`, `threat`, `machine_learning`) whose value is null counts as absent. A retired key in the `type_block` list is invalid even when its value is null. A block that omits `status` fails as a missing required field; implementations MAY report the constraint codes only for blocks that set `status`.

### `scheduling` (ElasticScheduling)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `interval` | duration | optional | `5m` | Runs every. |
| `lookback` | duration | optional | `1m` | Additional look-back time. `0m` is valid. |
| `max_alerts` | int | optional | null | Max alerts per run (`max_signals`). Omitted leaves the detection engine's default of 100. |

#### Schedule

`lookback` is only the overlap added to `interval`. The compiler sends `interval` and sets `from` to `now-` plus the sum, so the defaults become `interval: 5m` and `from: now-6m`, and `lookback: 0m` sends `from` equal to `interval`. The detection engine has no separate field for the overlap; the UI shows `from` minus `interval`. Sentinel's `scheduling.lookback` has a different meaning (the whole query window): an Elastic `lookback` of `1m` with an `interval` of `5m` covers six minutes, not one. `to` is always `now`.

### `severity` (ElasticSeverity)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `default` | string | yes | — | An `alert_severity` value. |
| `mapping` | list[SeverityMapping] | optional | null | Severity override: alerts whose `field` equals `value` get `severity`. |

`mapping[]`:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `field` | string | yes | — | Source event field. |
| `value` | string | yes | — | Value to match. |
| `operator` | string | optional | `equals` | `equals` is the only operator. |
| `severity` | string | yes | — | Kibana severity: `low`, `medium`, `high`, or `critical`. |

### `risk` (ElasticRisk)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `score` | int | optional | null | 0–100. Omitted uses the [severity table](#severity-and-risk). |
| `mapping` | list[RiskScoreMapping] | optional | null | Risk score override: the alert takes its score from `field`. |

`mapping[]`:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `field` | string | yes | — | Source event field holding a score. |
| `operator` | string | optional | `equals` | `equals` is the only operator. |
| `value` | string | optional | `""` | Kibana sends an empty string. |

### `suppression` (ElasticSuppression)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `group_by` | list[string] | conditional | null | 1–3 field names. Required for every type except `threshold`, where it is forbidden. |
| `duration` | duration | conditional | null | Suppression window. Required for `threshold`. Omitted on other types suppresses for the rule execution only. |
| `missing_fields_strategy` | string | optional | `suppress` | `suppress` or `doNotSuppress`: whether alerts missing a `group_by` field are suppressed together. Not sent for `threshold`. |

Alert suppression needs a Platinum licence or higher on self-managed and Hosted deployments, and a project tier that includes it on Serverless. On a Basic licence Kibana stores, previews, and runs `alert_suppression` without error but writes one alert per match. A least-privilege API key cannot read the licence, so the tenant declares it with `setup.suppression` ([Tenant setup](#tenant-setup)).

### `threshold` (ElasticThreshold)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `field` | list[string] | optional | `[]` | Group by, 0–5 fields. `[]` counts all matches. |
| `value` | int | yes | — | Threshold, at least 1. |
| `cardinality` | ElasticCardinality | optional | null | Count: alert only when `field` has at least `value` distinct values. |

`cardinality`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `field` | string | yes | Field whose distinct values are counted. |
| `value` | int | yes | Minimum number of distinct values. |

### `new_terms` (ElasticNewTerms)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fields` | list[string] | yes | 1–3 fields whose value, or combination of values, must be new. |
| `history_window_start` | duration | yes | History window size. Sent as `now-<duration>`. Separate from the schedule. |

### `eql` (ElasticEql)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `timestamp_field` | string | optional | null | Timestamp field for EQL sequencing. |
| `event_category_override` | string | optional | null | Event category field. |
| `tiebreaker_field` | string | optional | null | Tiebreaker for events with equal timestamps. |

### `threat` (ElasticThreatMatch)

The indicator side of an indicator match rule. The event query, `language`, `index`, and `filters` stay on the block. This object is not the detection engine's ATT&CK `threat` array, and the compiler MUST NOT copy it to that body key.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `index` | list[string] | yes | — | Indicator index patterns. Always a list. |
| `query` | string | yes | — | Indicator query. |
| `language` | string | optional | null | `kuery` or `lucene`, for the indicator query. |
| `mapping` | list[ThreatGroup] | yes | — | Groups are OR. Entries in a group are AND. |
| `filters` | list[object] | optional | null | Indicator filters, in the same two shapes as [`filters`](#filters-elasticfilter). |
| `indicator_path` | string | optional | null | Indicator prefix override. Kibana's default is `threat.indicator`. |

`mapping[]` has one key, `entries` (list, required). `entries[]`:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `field` | string | yes | — | Event field. |
| `value` | string | yes | — | Indicator field. |
| `type` | string | optional | `mapping` | `mapping` is the only type. |
| `negate` | boolean | optional | null | `true` is the UI's DOES NOT MATCH. Not sent when null. |

### `machine_learning` (ElasticMachineLearning)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `job_id` | string \| list[string] | yes | Existing anomaly detection job id or ids. Sent unchanged, in either shape. The block does not create jobs. |
| `anomaly_threshold` | int | yes | Anomaly score cutoff on Kibana's 0–100 scale. |

`machine_learning.job_id` and `threat.index` name objects in one tenant. The block carries them as written.

### `filters[]` (ElasticFilter)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `field` | string | with `value` | null | Phrase shorthand: field to match. |
| `value` | string | with `field` | null | Phrase shorthand: value to match. |
| `negate` | boolean | optional | `false` | Phrase shorthand: exclude matches. |
| `meta` | object | with `query` | null | Raw detection-engine filter `meta`. |
| `query` | object | with `meta` | null | Raw detection-engine filter query. |

A shorthand entry compiles to a phrase filter:

```json
{
  "meta": {"key": "<field>", "negate": false, "disabled": false, "type": "phrase", "params": {"query": "<value>"}},
  "query": {"match_phrase": {"<field>": "<value>"}}
}
```

A raw entry is copied unchanged.

### `integration[]` (ElasticIntegration)

An entry is a package name (`endpoint`) or an object:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `package` | string | yes | — | Integration package, for example `windows`, `endpoint`, `aws`. |
| `integration` | string | optional | null | Policy template inside the package, for example `cloudtrail`. |
| `version` | string | optional | `*` | Semver range, for example `^2.0.0`. |

### `required_fields[]` (ElasticRequiredField)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Field name. |
| `type` | string | yes | Elasticsearch mapping type: `keyword`, `constant_keyword`, `wildcard`, `text`, `match_only_text`, `long`, `integer`, `short`, `byte`, `unsigned_long`, `double`, `float`, `half_float`, `scaled_float`, `date`, `date_nanos`, `boolean`, `ip`, `version`, `binary`, `geo_point`, `geo_shape`, `object`, `flattened`, or `nested`. |

Kibana adds `ecs` to each entry on create. It is `true` only when both the name and the type match ECS.

### `guide` (ElasticGuide)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `investigation` | string | optional | null | Investigation guide (Kibana `note`). Markdown. |
| `setup` | string | optional | null | Setup guide (Kibana `setup`). Not the tenant `setup` table. |

### `exceptions` (ElasticExceptions)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `endpoint` | boolean | optional | `false` | Attach the Elastic Endpoint exception list. |
| `lists` | list[ExceptionList] | optional | null | Existing exception lists. |

`lists[]`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Exception list id. |
| `list_id` | string | yes | Exception list `list_id`. |
| `namespace_type` | string | yes | `single` (one space) or `agnostic` (every space). |
| `type` | string | yes | `detection` or `rule_default`. |

### `overrides` (ElasticOverrides)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | optional | null | Rule name override: the alert title comes from this field. |
| `timestamp` | string | optional | null | Timestamp override: the rule's time range runs on this field instead of `@timestamp`. |
| `disable_fallback` | boolean | optional | null | "Do not use @timestamp as a fallback timestamp field". |

### `actions` (ElasticActions)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `notify` | list[object] | optional | null | Rule actions: connector `id`, `action_type_id`, `group`, `params`, and `frequency`, in Kibana's shape. Copied unchanged. |
| `respond` | list[object] | optional | null | Response actions, one of the two shapes below. |
| `timeline` | ElasticTimeline | optional | null | Timeline template attached to the rule: `id` and `title`, both optional strings. |

A `respond` entry compiles as follows:

| Written | Compiled `response_actions[]` entry |
|---------|-------------------------------------|
| `{endpoint: <command>, comment?}` | `{action_type_id: .endpoint, params: {command: <command>, comment?}}`. `comment` is sent when it is not empty. |
| `{endpoint: <command>, field: <f>, comment?}` | as above, plus `params.config: {field: <f>, overwrite: false}` |
| `{endpoint: kill-process\|suspend-process, comment?}`, without `field` | as above, plus `params.config: {field: process.entity_id, overwrite: true}` |
| `{osquery: {...}}` | `{action_type_id: .osquery, params: {...}}`, the `osquery` object copied unchanged |

`field` is the custom process field that `kill-process` and `suspend-process` act on. Kibana rejects those two commands without `params.config`, so when `field` is omitted the compiler sends Kibana's default, the `process.entity_id` field with `overwrite: true` ([opentide#558](https://github.com/opentidehq/opentide/issues/558), [opentide#562](https://github.com/opentidehq/opentide/pull/562)). `isolate` and `runscript` without `field` send no `config`.

### Tenant setup

Tenants are workspace configuration in `.opentide/configurations/platforms/elastic.toml` ([platforms](index.md#platform-configuration-location)), not part of the block. Three setup keys change the compiled body.

| `tenants.setup` field | Type | Required | Default | Meaning |
|-----------------------|------|----------|---------|---------|
| `url` | string | yes | — | Kibana base URL, without `/s/<space>`. |
| `api_key` | string | yes | — | Encoded API key (the `encoded` value from `POST /_security/api_key`). MUST be a `$ENV` reference. |
| `elasticsearch_url` | string | yes | — | Elasticsearch base URL of the same deployment, for the [Elasticsearch checks](#elasticsearch-checks). |
| `space` | string | no | `default` | Kibana space id. `default` uses the unprefixed path. |
| `index` | list[string] | no | null | Index patterns for blocks that set neither `index` nor `data_view_id`. |
| `tags` | list[string] | no | `[]` | Tags added to every rule deployed to this tenant. |
| `suppression` | boolean | no | `true` | Whether the licence or project tier applies alert suppression. `false` omits `alert_suppression` with a warning. |
| `ssl` | boolean | yes | — | Shared tenant setup: TLS verification. |

A tenant that sets `proxy` is refused; the proxy is the global `opentide --proxy` option. One API key serves Kibana and Elasticsearch. Rules run with the privileges of the key that last created or updated them, so each tenant SHOULD use a dedicated, non-personal key with Security rules management `All` in its space, `read` and `view_index_metadata` on every source index the rules query, and, for live validation, `read` on `.preview.alerts-security.alerts-<space>` and `.internal.preview.alerts-security.alerts-<space>-*`. Kibana renames the feature privileges between versions, so this spec does not pin their names.

The supported floor is Kibana 8.19 and 9.x. ES|QL rules need 8.14 or later. The detection engine and the `query`, `eql`, `esql`, `threshold`, and `new_terms` types work on the Basic licence; alert suppression does not ([suppression](#suppression-elasticsuppression)).

### Compiled body

Deploy compiles each rule into one detection-engine create or update body. Kibana's `rule_id` is `metadata.uuid`, verbatim. Every other key:

| Detection-engine field | Source | Rule |
|------------------------|--------|------|
| `type` | `type` | verbatim |
| `name` | block `name`, else rule `name` | |
| `description` | rule `description` | trailing whitespace stripped |
| `enabled` | block `status` | `false` iff that status's strategy is `DISABLEMENT`. Always sent, because an update without it keeps the remote value. |
| `severity`, `risk_score` | `severity`, `risk` | [Severity and risk](#severity-and-risk) |
| `severity_mapping` | `severity.mapping` | `operator` defaults to `equals` |
| `risk_score_mapping` | `risk.mapping` | `operator` defaults to `equals` |
| `interval` | `scheduling.interval` | [Durations](#durations); default `5m` |
| `from` | `scheduling.interval` + `scheduling.lookback` | `now-<sum>` ([Schedule](#schedule)) |
| `to` | — | `now` |
| `language` | `type`, `language` | `eql` for `eql`, `esql` for `esql`, omitted for `machine_learning`, else `language` or `kuery` |
| `query` | `query` | trailing whitespace stripped; omitted for `machine_learning` |
| `index` | block `index`, else tenant `setup.index` | [Data source](#data-source). Omitted for `esql` and `machine_learning`, when `data_view_id` is set, or when both sources are empty. |
| `data_view_id` | `data_view_id` | verbatim |
| `filters` | `filters` | [filters](#filters-elasticfilter); omitted for `esql` and `machine_learning` |
| `threshold` | `threshold` | `{field, value}`, plus `cardinality` as a one-item list when set |
| `new_terms_fields` | `new_terms.fields` | verbatim |
| `history_window_start` | `new_terms.history_window_start` | `now-<duration>` |
| `timestamp_field`, `event_category_override`, `tiebreaker_field` | `eql.*` | verbatim, when set |
| `threat_index` | `threat.index` | list |
| `threat_query`, `threat_language`, `threat_indicator_path` | `threat.query`, `threat.language`, `threat.indicator_path` | verbatim, when set |
| `threat_filters` | `threat.filters` | compiled like `filters` |
| `threat_mapping` | `threat.mapping` | an entry without `type` is sent with `type: mapping`; a null `negate` is not sent |
| `machine_learning_job_id`, `anomaly_threshold` | `machine_learning.job_id`, `machine_learning.anomaly_threshold` | verbatim; a string stays a string and a list stays a list |
| `alert_suppression` | `suppression` | `{group_by, duration?, missing_fields_strategy}`, or `{duration}` for `threshold`. `duration` is `{value, unit}`. Omitted when tenant `setup.suppression` is `false`. |
| `investigation_fields` | `highlighted_fields` | `{field_names: [...]}` |
| `required_fields` | `required_fields` | one `{name, type}` per entry, sorted by `name` |
| `related_integrations` | `integration` | a string `p` becomes `{package: p, version: "*"}`; an object keeps its set keys and `version` defaults to `"*"` |
| `false_positives` | `false_positives` | verbatim |
| `setup` | `guide.setup` | trailing whitespace stripped |
| `note` | `guide.investigation`, else `response.procedure.analysis` | trailing whitespace stripped |
| `max_signals` | `scheduling.max_alerts` | verbatim |
| `rule_name_override` | `overrides.name` | verbatim |
| `timestamp_override` | `overrides.timestamp` | verbatim |
| `timestamp_override_fallback_disabled` | `overrides.disable_fallback` | sent when not null |
| `exceptions_list` | `exceptions.lists`, `exceptions.endpoint` | the lists, then `{id: endpoint_list, list_id: endpoint_list, namespace_type: agnostic, type: endpoint}` when `endpoint` is true; omitted when empty |
| `building_block_type` | `building_block: true` | `"default"`; `false` is not sent |
| `actions` | `actions.notify` | verbatim |
| `response_actions` | `actions.respond` | [actions](#actions-elasticactions) |
| `timeline_id`, `timeline_title` | `actions.timeline.id`, `actions.timeline.title` | verbatim, when set |
| `tags` | `"OpenTide"`, tenant `setup.tags`, block `tags` | in that order, de-duplicated |
| `author` | `metadata.author`, `metadata.contributors` | de-duplicated; omitted when empty |
| `references` | `references.public` | values in ascending key order |
| `threat` | resolved techniques | [ATT&CK](#attck) |

An absent optional source produces no key. Kibana's `concurrent_searches`, `items_per_search`, `meta`, `output_index`, `namespace`, `throttle`, `saved_id`, and `license` are never compiled.

### Severity and risk

The alert severity is `severity` (a string), else `severity.default`, else `response.alert_severity`, else `Informational`, matched case-insensitively:

| `alert_severity` | `severity` | `risk_score` |
|------------------|------------|--------------|
| Informational | low | 1 |
| Low | low | 21 |
| Medium | medium | 47 |
| High | high | 73 |
| Critical | critical | 99 |

`risk` (an integer) or `risk.score` replaces the table score. The table follows Elastic's prebuilt-rule convention and sits inside Kibana's risk bands (0–21 low, 22–47 medium, 48–73 high, 74–100 critical). An explicit score SHOULD stay inside its severity's band.

### ATT&CK

The body key `threat` is the ATT&CK array. It is derived from the rule's `techniques` plus the techniques inherited through `detection_model` (objective, then its threats), de-duplicated. Sentinel uses only the inherited set; Elastic takes the union, so a rule's own `techniques` are never dropped.

1. Keep Enterprise techniques only. Mobile and ICS entries in `att&ck.vocab.toml` carry a `Mobile : ` or `Industrial : ` name prefix. Deploy MUST skip them with a warning.
2. Map each technique's `tide.vocab.stages` to tactics with the table below. A sub-technique uses its own stages. A legacy stage is first renamed through the legacy-stage table; any other stage outside the table emits no tactic.
3. Emit one entry per tactic, in table order, with `framework: "MITRE ATT&CK"`. Techniques are sorted by id. A sub-technique appears under its parent technique, named without the `<parent name>: ` prefix. An empty `subtechnique` list is omitted.
4. `reference` is the vocabulary `link` for a technique and `https://attack.mitre.org/tactics/<id>/` for a tactic.

| Stage | Tactic id |
|-------|-----------|
| Reconnaissance | TA0043 |
| Resource Development | TA0042 |
| Initial Access | TA0001 |
| Execution | TA0002 |
| Persistence | TA0003 |
| Privilege Escalation | TA0004 |
| Stealth | TA0005 |
| Defense Impairment | TA0112 |
| Credential Access | TA0006 |
| Discovery | TA0007 |
| Lateral Movement | TA0008 |
| Collection | TA0009 |
| Command and Control | TA0011 |
| Exfiltration | TA0010 |
| Impact | TA0040 |

ATT&CK v19 renamed Defense Evasion (TA0005) to Stealth and split Defense Impairment (TA0112) out of it. Keys that ATT&CK has since revoked stay in `att&ck::1.x` with `removed = "2.0"` and keep the stage they were last published with. A legacy stage maps to the stage that now holds its tactic id:

| Legacy stage | Stage |
|--------------|-------|
| Defense Evasion | Stealth |

### Deploy

The base path is `<url>/api/detection_engine/rules` in space `default`, and `<url>/s/<space>/api/detection_engine/rules` in any other space.

| Block status strategy | Calls | Result |
|-----------------------|-------|--------|
| `PREVIEW`, `RELEASE` | The Elasticsearch checks, then `GET ?rule_id=<uuid>`. A 404 leads to `POST` with the compiled body. A 200 leads to `PUT` with the compiled body plus the preserved fields, or to `DELETE` then `POST` when the remote `type` differs. | rule created or replaced, `enabled: true` |
| `DISABLEMENT` | as above | rule kept, `enabled: false` |
| `DELETION` | `DELETE ?rule_id=<uuid>` | 200 and 404 are both success |
| `INERT` | none | not deployed |

`PUT` replaces the whole rule, so a key the block omits returns to Kibana's default. These remote fields are the exception: when the compiled body does not set one, deploy copies it from the `GET` response.

| Preserved field | Why |
|-----------------|-----|
| `actions` | notification connectors on this rule |
| `exceptions_list` | exception lists attached to this rule |
| `response_actions` | Elastic Defend and Osquery response actions on this rule |
| `timeline_id`, `timeline_title` | Timeline template on this rule |
| `concurrent_searches`, `items_per_search`, `meta` | detection-engine fields the create UI does not show |
| `output_index`, `namespace`, `throttle` | legacy detection-rule fields |

**Type changes.** Kibana cannot change `type` with `PUT`. When the remote `type` differs, deploy MUST `DELETE` the rule and `POST` the compiled body plus the preserved fields. The `rule_id` stays the same; Kibana assigns a new internal `id`, so execution history restarts.

**Prebuilt rules.** A remote rule with `rule_source.type: external` (customised prebuilt rules included), or with `immutable: true` on versions without `rule_source`, is an Elastic prebuilt rule. Deploy MUST report an error for it and MUST NOT change it.

**Drift.** `GET` also returns server-owned fields (`id`, `revision`, `created_at`, `updated_at`, `execution_summary`, `rule_source`, `immutable`) and defaults such as `max_signals` and `risk_score_mapping`, and Kibana adds `ecs` to each `required_fields` entry. A deployer that compares remote and compiled rules MUST compare only the compiled keys and MUST ignore `required_fields[].ecs`.

**Errors.** HTTP 400 or 409 on one rule, or a failed Elasticsearch check, fails that rule with the server's message, and the batch continues. HTTP 401 or 403 fails the tenant, and deploy moves to the next tenant. HTTP 429 and 5xx are retried up to three times with exponential backoff.

A deployer MAY list managed rules with `GET _find?filter=alert.attributes.tags:"OpenTide"` instead of one `GET` per rule.

### Query validation

`elastic` is in the query-validation allowlist. The language comes from each rule's block: its `type`, and `language` for the types that take one ([Rule types](#rule-types)).

| Mode | Behaviour |
|------|-----------|
| without `--live` | Refuses and names `--live`. There is no offline syntax check. |
| `--live` | `POST <base>/preview` with the compiled body plus `{"invocationCount": 1, "timeframeEnd": "<now>"}`, and the [Elasticsearch checks](#elasticsearch-checks). `timeframeEnd` MUST be UTC with a `Z` suffix (`2026-09-25T11:10:00.000Z`); Kibana rejects a `+00:00` offset. |

| Preview response | Result |
|------------------|--------|
| HTTP 200, every `logs[].errors` empty | valid. `logs[].warnings` are reported as warnings. |
| HTTP 200 with `logs[].errors` | invalid, with the errors. A missing preview-index privilege is a tenant configuration error, not a query error. |
| HTTP 400 | invalid: a rule-level schema error |
| HTTP 401 or 403 | the tenant fails |
| `isAborted: true` | inconclusive, reported as a warning |

Preview runs the rule once against live data and writes only to the preview alerts index. It catches KQL, Lucene, and EQL syntax errors, unknown EQL fields, ES|QL errors inside a command, unknown ES|QL columns, and rule-level schema errors. It does not check licence-gated behaviour, on 9.x it does not catch an unknown ES|QL command, and it cannot tell a misspelt aggregation field from one with no matches. The Elasticsearch checks cover those gaps. CI SHOULD point `--live` at a staging tenant, because preview costs a real query.

### Elasticsearch checks

Kibana accepts some rules that then fail silently. Before every create or update, and during live validation, deploy MUST run these checks against the tenant's `elasticsearch_url` with its API key. HTTP 401, 403, 429, and 5xx follow the deploy error rules. A check that could not run is not a pass.

**ES|QL pre-flight.** Kibana does not parse ES|QL on create: on 8.19 a mistyped command makes every scheduled run fail, and on 9.5 Kibana drops the unknown command and the rule matches everything in its window. For every `esql` rule, deploy sends `POST <elasticsearch_url>/_query` with the query plus `\n| LIMIT 0`. HTTP 200 passes and returns the result `columns`. A `parsing_exception` fails the rule. On a `verification_exception`, deploy calls `GET <elasticsearch_url>/_resolve/index/<FROM sources>?ignore_unavailable=true&allow_no_indices=true`: when `indices`, `aliases`, and `data_streams` are all empty, the sources are not onboarded yet and the rule deploys with a warning; otherwise the rule fails.

**Aggregation fields.** `suppression.group_by`, `threshold.field`, `threshold.cardinality.field`, and `new_terms.fields` MUST each be present with `aggregatable: true` in `GET <elasticsearch_url>/<sources>/_field_caps?fields=<fields>&ignore_unavailable=true&allow_no_indices=true`. `<sources>` is the compiled `index`, or the `title` of the data view from `GET /api/data_views/data_view/<data_view_id>` in the tenant's space. Otherwise the rule fails. A data view lookup or `_field_caps` call that does not return 200 also fails the rule. An empty `indices` list in the response means the sources are not onboarded yet: the rule deploys with a warning. A rule with no explicit source uses the space default index, and the check is skipped with a warning. For `esql`, the `group_by` fields MUST instead be among the pre-flight `columns`.

**Timestamp fields.** When `overrides.timestamp` or `eql.timestamp_field` is set to a field other than `@timestamp`, that field MUST be mapped as `date` or `date_nanos` in the same `<sources>`; any other mapping fails the rule. Sources not onboarded yet, or a field not mapped yet, are a warning.

**Indicator match fields.** For `threat_match`, each `threat.mapping` entry's `field` MUST be searchable in the event `<sources>`, and its `value` searchable in `threat.index`. A field mapped as not searchable fails the rule. Sources not onboarded yet, or a field not mapped yet, are a warning.

### Advisories

Validation SHOULD warn, without rejecting the rule, when:

- `scheduling.lookback` is zero: the next run starts as the window ends, and Elastic recommends at least one minute.
- `scheduling.lookback` exceeds `1h`: `lookback` is overlap added to `interval`, not the whole window as in Sentinel.
- a `threshold` rule's `lookback` exceeds its `interval`: threshold counts are not de-duplicated across overlapping runs.
- a non-aggregating ES|QL query (no `STATS`) lacks `METADATA _id`: alerts are not de-duplicated.
- an EQL `sequence` `maxspan` exceeds `interval` + `lookback` (the sequence cannot fit one run) or `lookback` (a sequence that straddles two runs is missed).
- an explicit risk score is outside its severity's band.
- a technique is skipped because it is not Enterprise ATT&CK.

## Relationships

- [platforms](index.md) — shared fields, capability row, external ids
- [rule-1.0.md](../objects/rule-1.0.md), [rule-1.1.md](../objects/rule-1.1.md) — parent object
- [deployment.md](../deployment.md) — `status` strategies
- [deployment-state.md](../deployment-state.md) — Elastic never writes a shard
- [validation.md](../validation.md) — schema validation and live query validation
- [configuration.md](../configuration.md) — platform TOML merge
- [sentinel-1.0.md](sentinel-1.0.md) — the same shorthand duration grammar (Sentinel's ISO 8601 form also accepts weeks), with a different `lookback` meaning
- [RFC 0007](../../rfcs/0007-elastic-security-platform.md) — design, research, and reference test

## Defaults & overrides

| Field | Default |
|-------|---------|
| `language` | `kuery` at compile, for the types that take a language |
| `scheduling.interval` | `5m` |
| `scheduling.lookback` | `1m`, so `from` is `now-6m` with the default interval |
| `scheduling.max_alerts` | not sent; the detection engine's 100 |
| `severity` | `response.alert_severity`, then `Informational` |
| `risk` | the [severity table](#severity-and-risk) score |
| `suppression.missing_fields_strategy` | `suppress` |
| `threshold.field` | `[]` |
| `threat.mapping[].entries[].type` | `mapping` |
| `integration[].version` | `*` |
| `severity.mapping[].operator`, `risk.mapping[].operator` | `equals` |
| `risk.mapping[].value` | `""` |
| `exceptions.endpoint` | `false` |
| `building_block` | `false` |
| `index` | tenant `setup.index`, then the space's `securitySolution:defaultIndex` |
| kill-process and suspend-process `config` | `{field: process.entity_id, overwrite: true}` when `field` is omitted |
| Tenant `space` | `default` |
| Tenant `suppression` | `true` |

## Examples

The smallest useful block, a custom query:

```yaml
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    status: STAGING
    type: query
    language: kuery
    query: 'event.category : "process"'
    index: [logs-*]
    scheduling:
      interval: 5m
      lookback: 1m
```

With rule `name: Rule name`, `metadata.uuid: 00000000-0000-4000-8000-000000000000`, `metadata.author: Detection Engineering`, `description: What this rule detects.`, `response.alert_severity: Medium`, and no techniques, it compiles for a tenant with no `index` or `tags` to:

```json
{
  "rule_id": "00000000-0000-4000-8000-000000000000",
  "type": "query",
  "name": "Rule name",
  "description": "What this rule detects.",
  "enabled": true,
  "severity": "medium",
  "risk_score": 47,
  "interval": "5m",
  "from": "now-6m",
  "to": "now",
  "language": "kuery",
  "query": "event.category : \"process\"",
  "index": ["logs-*"],
  "tags": ["OpenTide"],
  "author": ["Detection Engineering"]
}
```

The keys that change with the rule type:

```yaml
# eql: no language
type: eql
query: |
  sequence by host.id with maxspan=1m
    [process where event.type == "start" and process.name == "x.exe"]
index: [logs-endpoint.events.process-*]
eql:
  timestamp_field: "@timestamp"

# esql: no index, data_view_id, filters, or language
type: esql
query: |
  FROM logs-*
  | STATS count = COUNT(*) BY host.name
  | WHERE count > 10

# threshold: suppression is a duration, with no group_by
type: threshold
query: 'event.category : "authentication" and event.outcome : "failure"'
threshold:
  field: [source.ip]
  value: 20
  cardinality: {field: user.name, value: 5}
suppression:
  duration: 1h

# new_terms
type: new_terms
query: 'event.category : "iam"'
new_terms:
  fields: [user.name]
  history_window_start: 14d

# threat_match: the event query stays flat; the indicator side is threat
type: threat_match
query: 'event.category : "file"'
threat:
  index: [logs-ti_*]
  query: '@timestamp >= "now-30d/d"'
  mapping:
    - entries:
        - field: file.hash.sha256
          value: threat.indicator.file.hash.sha256

# machine_learning: no query, index, or language
type: machine_learning
machine_learning:
  job_id: rare_process_by_host
  anomaly_threshold: 50
```

This block breaks three constraints and reports `esql_source`, `language`, and `suppression_shape`:

```yaml
elastic:
  enabled: true
  schema: platform::elastic::1.0
  status: STAGING
  type: esql
  language: kuery
  query: FROM logs-* | LIMIT 10
  index: [logs-*]
  suppression: {duration: 1h}
```

Fixtures:

- [fixtures/platforms/elastic.yaml](../../fixtures/platforms/elastic.yaml) — the custom query block above on a full rule
- [fixtures/valid/rule-elastic-1.0.yaml](../../fixtures/valid/rule-elastic-1.0.yaml) — every shared key set (RFC 0007 Example A)
- [fixtures/invalid/rule-elastic-esql-index.yaml](../../fixtures/invalid/rule-elastic-esql-index.yaml) — the invalid block above on a full rule

RFC 0007 has a complete rule for every rule type, and the compiled body of its Example A.

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-10-19 | The tactic table follows ATT&CK v19 as `att&ck::1.2` (ATT&CK 20.0) publishes it: TA0005 is `Stealth`, and `Defense Impairment` is TA0112. Removed keys still staged `Defense Evasion` map to `Stealth` through the legacy-stage table. Without this, techniques staged only in those tactics emitted no `threat` entry ([opentide#568](https://github.com/opentidehq/opentide/issues/568)). |
| 1.0 | 2026-10-19 | Initial field contract from [RFC 0007](../../rfcs/0007-elastic-security-platform.md) and the opentide implementation ([specifications#17](https://github.com/opentidehq/specifications/issues/17)). Amends the RFC in two places. Durations accept compound shorthand (`1h10m`, `1d2h`, `2m30s`) as well as single-unit shorthand and ISO 8601 ([opentide#564](https://github.com/opentidehq/opentide/pull/564)). `kill-process` and `suspend-process` without `field` send Kibana's default process field, `process.entity_id` with `overwrite: true` ([opentide#562](https://github.com/opentidehq/opentide/pull/562)). |
