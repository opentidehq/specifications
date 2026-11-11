---
spec: platform-graylog
version: "1.1"
schema_id: platform::graylog::1.0
status: normative
supersedes: null
---

# Graylog (`platform::graylog::1.0`)

## Summary

`configurations.graylog` is one Graylog **event definition** of the Filter & Aggregation type (`aggregation-v1`). It holds a search query in Graylog's search syntax. It may add an aggregation (group-by fields and a condition over series), streams, a schedule, event fields, notifications, and response text. Event definitions are in every Graylog edition, Graylog Open included.

Deploy creates, updates, schedules, unschedules, and deletes the definition through Graylog's REST API on Graylog **6.3, 7.0, 7.1, and 7.2**. The create body and a few optional fields differ between those versions, so deploy reads the server version first and builds every request for it ([Versions](#versions)).

Graylog assigns every definition a 24-hex id at create time. That id is kept in deployment state ([deployment-state.md](../deployment-state.md)), never on the rule. Every update sends the whole definition.

Graylog checks queries with `POST /api/search/validate`, so Graylog is in the `--live` allowlist. Offline, the analysis engine checks the query as Lucene in its Graylog dialect, chosen by the platform as Carbon Black Cloud's is.

Shared fields are defined in [platforms](index.md#shared-platform-block). The design, the research behind it, and why Sigma is not part of it are in [RFC 0017](../../rfcs/0017-graylog-platform.md).

## Requirements

Static validation (`opentide validate`) and registry load:

- `status` MUST be present, as on `elastic`, `sysdig`, and `bitdefender`.
- `query` MUST be a non-blank string (`graylog_query_blank`).
- A block MUST satisfy every [constraint](#constraints), reported with its code.
- Unknown keys MUST fail, at the block root and inside `schedule`, `aggregation`, and every `event_fields` value that is a map.
- Legacy external-id keys (`rule_id`, `rule_id_bundle`, `rule_id::<tenant>`) MUST fail with `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)).
- A [list field](#list-fields) MUST accept one string or a list of strings, and MUST treat a string as a one-item list.

Deploy:

- Graylog is state-backed. Deploy MUST follow the [deploy decisions](../deployment-state.md#deploy-decisions) of deployment state and store the event definition id under `platforms.graylog.<tenant>`, lower-case, matching `^[0-9a-f]{24}$`.
- Deploy MUST read the server version (`GET /api/system`) once per tenant per run, before any write, and MUST build every request body for that version ([Versions](#versions)). A body MUST NOT carry a property the version does not define: Graylog 6.3 accepts an unknown property on create and silently drops it.
- Deploy MUST NOT send `id` on create. Graylog echoes a client id and stores nothing.
- Deploy MUST NOT find a definition by listing (`GET /api/events/definitions/paginated`), by title, or by tag.
- Deploy MUST NOT create a definition unless the returned id can be kept (`deployment_state_ignored`, `deployment_state_unpersisted`).
- Before every create and update, deploy MUST send the query to `POST /api/search/validate` and MUST NOT save a definition whose query Graylog reports as `ERROR`. Graylog stores an unparseable query without complaint.
- Every `PUT` MUST carry `?schedule=true` or `?schedule=false`. Without it, Graylog re-enables a disabled definition.
- Every request body MUST carry `_scope: DEFAULT`, and MUST NOT carry `state`, `storage`, `scheduler`, `updated_at`, `matched_at`, or `_entity_source`.
- Every `POST`, `PUT`, and `DELETE` MUST send the `X-Requested-By` header.
- Deploy MUST NOT call `POST /api/events/definitions/{id}/execute`, which creates real events and notifications.
- Deploy MUST NOT write to the rule file.

Query validation:

- `opentide validate query --platform graylog --live` MUST send each query to `POST /api/search/validate` on each tenant ([Query validation](#query-validation)). Without `--live`, `validate query` checks the query offline with the Graylog dialect.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | A Graylog search query, in the [Graylog dialect](#query-dialect) |
| `priority` | string | optional | [derived](#priority) | `Informational`, `Low`, `Medium`, `High`, or `Critical` |
| `alert` | boolean | optional | `true` | `false` makes fired events plain events, not alerts |
| `tags` | string or list[string] | optional | `[]` | Extra Graylog tags (Graylog 7.2+). Deploy adds the [derived tags](#tags). |
| `streams` | string or list[string] | optional | tenant `streams` | Aliases from the tenant's `stream_ids` table |
| `stream_categories` | string or list[string] | optional | `[]` | Graylog stream categories, as written |
| `schedule` | [GraylogSchedule](#schedule-graylogschedule) | optional | `{every: 5m}` | When the definition runs and the time range it searches |
| `event_limit` | integer | optional | `100` | Filters only: the most events one run creates, 1–1,000 |
| `aggregation` | [GraylogAggregation](#aggregation-graylogaggregation) | optional | null | Turns the filter into an aggregation |
| `event_fields` | map | optional | `{}` | Event field name → a [value](#event-field-values) |
| `event_key` | string or list[string] | optional | `[]` | Event fields that make up the event key |
| `notifications` | string or list[string] | optional | `[]` | Aliases from the tenant's `notification_ids` table |
| `grace_period` | duration | optional | `0s` | No second notification for the same event key within this time |
| `backlog` | integer | optional | `0` | Messages attached to a notification, 0 or more |
| `summary` | string | optional | null | Event summary template (Graylog 7.1+) |
| `remediation` | string | optional | null | Remediation steps shown with the event |

The shared `name` is the definition title. Empty means the opentide rule `name`.

#### List fields

`tags`, `streams`, `stream_categories`, `event_key`, `notifications`, and `aggregation.group_by` take one string or a list of strings. A string is a one-item list. Every item is a non-blank string, and no item repeats. Templates and documentation write the list form.

### `schedule` (GraylogSchedule)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `every` | duration | `5m` | How often the definition runs (`execute_every_ms`). Exclusive with `cron`. |
| `window` | duration | `every` | The time range each run searches (`search_within_ms`) |
| `cron` | string | null | A Quartz cron expression of 6 or 7 fields (`0 */5 * * * ?`). Exclusive with `every`. |
| `timezone` | string | `UTC` | The IANA time zone `cron` runs in |

Durations follow the [Elastic duration grammar](elastic-1.0.md#durations) and are greater than zero. With `cron`, `window` is required.

### `aggregation` (GraylogAggregation)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `group_by` | string or list[string] | optional | Message fields the events are grouped by |
| `condition` | string | yes | A boolean expression over series, in the [condition grammar](#condition-grammar) |

The block never lists series. Deploy derives them from the functions the condition calls, so a series cannot be declared and unused, or used and undeclared.

#### Condition grammar

```text
condition  = or
or         = and *( "OR" and )
and        = not *( "AND" not )
not        = "NOT" not / primary
primary    = "(" condition ")" / comparison
comparison = series op number
series     = function "(" [ field [ "," number ] ] ")"
function   = "avg" / "card" / "count" / "latest" / "max" / "min" / "percentage"
           / "percentile" / "stddev" / "sum" / "sumofsquares" / "variance"
op         = ">=" / ">" / "<=" / "<" / "=="
number     = ["-"] 1*DIGIT ["." 1*DIGIT]
field      = 1*( ALPHA / DIGIT / "_" / "." / "@" / "-" )
```

Operators are upper case. Whitespace between tokens is free. Arguments:

- `count` takes no field or one field.
- `percentile` takes a field and a percentile `p`, `0 < p ≤ 100`.
- Every other function takes exactly one field.

These are Graylog's 12 aggregation functions, the same on every supported version.

**Compilation.** Each distinct call becomes one series, in the order of first appearance:

- id `<function>-<field>` (`count-` for `count()`, `percentile-bytes-95` for `percentile(bytes, 95)`);
- `type` the function;
- `field` when the call has one;
- `percentile` for `percentile`.

The expression becomes Graylog's condition tree:

| Grammar | Node |
|---------|------|
| `a OR b` | `{"expr": "\|\|", "left": a, "right": b}`, left-associative |
| `a AND b` | `{"expr": "&&", "left": a, "right": b}`, left-associative |
| `NOT a` | `{"expr": "!", "left": a}` |
| `( a )` | `a` (parentheses only group) |
| `s op n` | `{"expr": op, "left": {"expr": "number-ref", "ref": <series id>}, "right": {"expr": "number", "value": n}}` |

`n` is sent as a JSON number, an integer when it has no fraction. Graylog returns a `count` series without a field as `"field": null`; it stores the request otherwise as sent (checked on 6.3.5 and 7.2.2 with the request goldens).

### Event field values

| Written | Meaning | Graylog provider |
|---------|---------|------------------|
| a bare field name (matches `[A-Za-z0-9_.@-]+`) | copy that field of the message that fired the event | `{"type": "template-v1", "template": "${source.<field>}", "require_values": false}` |
| a string containing `${` | a Graylog template, sent as written | `{"type": "template-v1", "template": <string>, "require_values": false}` |
| `{template: <string>}` | a template or constant text, sent as written | as above |
| `{lookup: {table: <name>, key_field: <field>}}` | a lookup-table value keyed by a message field | `{"type": "lookup-v1", "table_name": <name>, "key_field": <field>}` |

Each event field is sent as `{"data_type": "string", "providers": [<provider>]}`. In Graylog's template syntax, `${source.X}` reads field X of the message that fired the event. There, `source` names the message, not the message's `source` field. A string that is neither a field name nor contains `${` is `graylog_event_field`. Constant text is written `{template: "…"}`.

### Constraints

Static validation MUST reject a block that breaks any of these, and report the code:

| Code | Constraint |
|------|------------|
| `graylog_query_blank` | `query` is a non-blank string. |
| `graylog_list_shape` | Each [list field](#list-fields) is a string or a list of non-blank strings, with no item repeated. |
| `graylog_schedule` | Exactly one of `schedule.every` and `schedule.cron`, unless both are omitted. Every duration follows the grammar and is greater than zero. `cron` has 6 or 7 fields and parses as a Quartz expression. `timezone` is an IANA zone name. `window` is set when `cron` is. |
| `graylog_event_limit` | `event_limit` is an integer from 1 to 1,000, and is not set together with `aggregation`. |
| `graylog_aggregation` | `aggregation.condition` parses under the [condition grammar](#condition-grammar), and every call has the arguments its function takes. |
| `graylog_event_field` | Each `event_fields` name matches `[A-Za-z0-9_.@-]+`, and each value is one of the [value forms](#event-field-values). |
| `graylog_event_key` | Each `event_key` item is an `event_fields` name. |
| `graylog_priority` | `priority` is `Informational`, `Low`, `Medium`, `High`, or `Critical`. |
| `graylog_field_name` | Each `aggregation.group_by` item matches `[A-Za-z0-9_.@-]+`. A field in the condition that does not is `graylog_aggregation`: the grammar's `field` rule. |

The query itself is checked by the analysis engine ([Query dialect](#query-dialect)), with its own codes.

Every implementation reports each code at the same `field_path`, so opentide and the editor name the same finding. Paths are under `configurations.graylog`:

| Code | `field_path` |
|------|--------------|
| `graylog_query_blank` | `query` |
| `graylog_list_shape` | the list field (`streams`, `aggregation.group_by`, …) |
| `graylog_schedule` | `schedule`, or the offending `schedule.<key>` |
| `graylog_event_limit` | `event_limit` |
| `graylog_aggregation` | `aggregation.condition`, or `aggregation` when it has no `condition` |
| `graylog_event_field` | `event_fields.<name>` |
| `graylog_event_key` | `event_key` |
| `graylog_priority` | `priority` |
| `graylog_field_name` | `aggregation.group_by` |
| advisories | `schedule` for `graylog_overlapping_window`; the block for `graylog_all_streams` and `graylog_title_duplicate` |
| [query diagnostics](#query-diagnostics) | `query`, with the range of the offending text |

### Advisories

Advisories are [warnings](../validation.md#platform-advisories): validation reports them under their code and never rejects the rule.

| Code | When | Why |
|------|------|-----|
| `graylog_overlapping_window` | `window` is longer than `every` on a filter (no `aggregation`). | Each message alerts once per overlapping run. |
| `graylog_all_streams` | The block and the tenant set no `streams` and no `stream_categories`. | The definition searches every stream the token's user can read. |
| `graylog_title_duplicate` | Workspace check: two enabled `graylog` blocks resolve to one title. | Graylog allows it, and its alert list cannot tell the two apart. |

### Query dialect

The query is Graylog's search syntax. Graylog passes it to OpenSearch or Elasticsearch `query_string` unchanged, with `allow_leading_wildcard` set from the server's `allow_leading_wildcard_searches` (default `false`). The default operator is OR, and an unqualified term searches every field. Field names match `[A-Za-z0-9_.@-]+`, and `_exists_:<field>` tests a field's presence. Regex bodies follow Lucene's regex syntax: anchored, with alternation `(a|b)`, numeric intervals `<16-31>`, `\d`, `\w`, and `\s`.

The analysis engine checks the query as Lucene (`LanguageId` `lucene`) in a Graylog dialect, chosen by the platform as Carbon Black Cloud's dialect is.

#### Query diagnostics

The engine's Lucene codes apply unchanged. For example, `lucene_parse_error` (error) for a query that does not parse, and `lucene_lowercase_operator` (warning) for `and`, `or`, or `not` written in lower case, which Graylog searches as words. The Graylog dialect adds:

| Code | Severity | When | Why |
|------|----------|------|-----|
| `graylog_leading_wildcard` | error | A term starts with `*` or `?`, and a targeted tenant does not set `allow_leading_wildcard`. Offline, with no tenant, it is an error. | Graylog refuses the query ("'*' or '?' not allowed as first character"). A regex with a leading `.*` is the portable form. |
| `graylog_regex_unsupported` | error | A regex uses an inline flag such as `(?i)`, `\b`, `\B`, lookahead or lookbehind, or a backreference. | Lucene's regex engine has none of them. Graylog refuses `\b` and `\B`, and matches nothing for the others without saying so. |
| `graylog_regex_operator` | warning | A regex holds an unescaped `#`, `&`, `<`, `>`, or `~`, other than a numeric interval `<n-m>`. | Lucene reads them as regex operators, and Graylog's validator still says OK. |
| `graylog_regex_quote` | warning | A regex holds a pair of unescaped `"`. | Lucene reads the quoted part as a literal string and drops the quote characters. An unpaired `"` does not parse: that is `lucene_regexp` (error). |
| `graylog_open_range` | error | A range has `*` as a bound (`[1 TO *]`, `{* TO 5}`). | Graylog's validator refuses it, so deploy cannot save the definition. Write `field:>=1` or `field:<5`. |
| `graylog_double_backslash` | warning | The query holds four backslashes in a row. | `\\` is one literal backslash in a Graylog query, so `\\\\` matches two. |
| `graylog_analyzed_field` | warning | A regex, wildcard, or range applies to `message` or `full_message`. | Those fields are tokenised: a regex or wildcard matches single tokens, never the whole value. |

**Case.** `message` and `full_message` are analysed (tokenised and lower-cased), and `source` is a lower-cased keyword. Every other string field is an exact, case-sensitive keyword, and the search syntax has no case-insensitive flag. The documented pattern for case-insensitive rules has two parts:

- a tenant pipeline, which opentide does not manage, writes lower-cased copies of the fields rules match on;
- rules match those copies with lower-case regex and alternation.

```text
rule "lowercase CommandLine"
when
  has_field("CommandLine")
then
  set_field("command_line_lc", lowercase(to_string($message.CommandLine)));
end
```

### Versions

Deploy reads `version` from `GET /api/system` (for example `6.3.5+eaa4b5d`) and compares `major.minor.patch`:

| Server version | Create body | `event_summary_template` | `tags`, `tactics_techniques` | Priority `Informational` |
|----------------|-------------|--------------------------|------------------------------|--------------------------|
| below 6.3 | — the tenant fails with `graylog_version_unsupported` | | | |
| 6.3.x | the definition, with `share_request` beside its fields | not sent | not sent; [ATT&CK fallback](#attck) | sent as 1 |
| 7.0.x | `{"entity": <definition>, "share_request": null}` | not sent | not sent; ATT&CK fallback | sent as 1 |
| 7.1.x | as 7.0 | sent | not sent; ATT&CK fallback | sent as 0 |
| 7.2.x and later | as 7.0 | sent | sent | sent as 0 |

`PUT` takes the bare definition, with its `id`, on every version. Deploy never sends the event-field option `exclude_empty_fields` (7.2+ only, and refused before 7.2).

A field the version cannot take is left out, with `graylog_field_unsupported_version` (warning) when the block set it: `summary` before 7.1, block `tags` before 7.2. `Informational` sent as 1 is `graylog_priority_collapsed` (warning).

A server below 6.3.12, 7.0.16, or 7.1.12 is affected by the access-token revocation flaw [GHSA-j769-9gv9-65gr](https://github.com/Graylog2/graylog2-server/security/advisories/GHSA-j769-9gv9-65gr). Deploy reports `graylog_version_vulnerable` (warning) once per tenant per run.

### Title and description

| Graylog field | Derivation |
|---------------|------------|
| `title` | The shared `name`, else the opentide rule `name` |
| `description` | The opentide `description`, whitespace runs collapsed to one space, trimmed. Before 7.2, when the rule has ATT&CK ids, `\n\nATT&CK: ` and the ids joined by `, ` follow ([ATT&CK](#attck)). |

### Priority

`priority` is the block `priority`, else `response.alert_severity`:

| Severity | `priority` |
|----------|------------|
| `Critical` | 4 |
| `High` | 3 |
| `Medium` | 2 |
| `Low` | 1 |
| `Informational` | 0 (1 before 7.1) |
| missing | 2 |

### Tags

On Graylog 7.2 and later, deploy sends the union, in this order and without duplicates:

1. the block `tags`;
2. `opentide`;
3. `opentide.<metadata.uuid>`;
4. the tenant `tags`.

Each tag is lower-cased. Any character outside `[a-z0-9_.-]` is replaced by `-`, and the tag is cut at 128 characters. A tag that is empty after that is dropped. At most 64 tags are sent, in that order. The `opentide.<uuid>` tag is for analysts and audits; deploy never uses it to find a definition.

### ATT&CK

The ids are:

1. the rule's ATT&CK techniques: its `techniques` plus those inherited through `detection_model`, Enterprise only, sorted by id (the set [elastic-1.0](elastic-1.0.md#attck) uses);
2. then the tactic id of each technique's stages, in the order of the [Elastic tactic table](elastic-1.0.md#attck), without duplicates.

At most 64 are sent. On 7.2 and later they are `tactics_techniques`. Before 7.2, Graylog has no such field. The same list instead goes into the description line, and into an event field `attack_techniques`, a `template-v1` provider whose template is the ids joined by `,`, so every fired event carries them. A block that defines its own `attack_techniques` event field keeps it, and deploy adds none.

### Tenant setup

```toml
[platform]
enabled = true
identifier = "graylog"
name = "Graylog"
subschema = "Graylog"
description = "Graylog event definitions (Filter & Aggregation)."
flags = []

[[tenants]]
name = "graylog-prod"
description = "Production Graylog"
strategies = ["RELEASE"]
[tenants.setup]
ssl = true
url = "https://graylog.example.com"
token = "$GRAYLOG_TOKEN"
allow_leading_wildcard = false
streams = ["sysmon"]
tags = ["managed-by-opentide"]

[tenants.setup.stream_ids]
sysmon = "65f0c0ffee0123456789abcd"

[tenants.setup.notification_ids]
soc-slack = "65f0c0ffee0123456789abcf"
```

| `tenants.setup` field | Type | Required | Default | Meaning |
|-----------------------|------|----------|---------|---------|
| `url` | string | yes | — | The Graylog web interface's base URL. Calls go to `<url>/api/...`. |
| `token` | string | yes | — | A Graylog access token. MUST be a `$ENV` reference. Sent as HTTP Basic, the token as user name and `token` as password. |
| `allow_leading_wildcard` | bool | no | `false` | Mirrors the server's `allow_leading_wildcard_searches` |
| `streams` | string or list[string] | no | `[]` | Default stream aliases for blocks that set no `streams` |
| `stream_ids` | table | no | `{}` | Alias → stream id, 24 hex |
| `notification_ids` | table | no | `{}` | Alias → notification id, 24 hex |
| `tags` | string or list[string] | no | `[]` | Tags added to every definition on this tenant (7.2+) |
| `ssl` | bool | yes | — | Shared tenant setup (TLS verification) |

A tenant with an unknown setup key, a literal `token`, or an id that is not 24 hex fails configuration load. The token's user needs `eventdefinitions:create`, `eventdefinitions:read`, `eventdefinitions:edit`, and `eventdefinitions:delete`, and `streams:read` on every stream a definition names.

### Deploy

Every request goes to `<url>/api/...` with `Accept: application/json`, `X-Requested-By: opentide`, and HTTP Basic `<token>:token`. Bodies are JSON (`Content-Type: application/json`).

**The definition.** A request body holds, for the detected version:

| Property | Value |
|----------|-------|
| `_scope` | `"DEFAULT"` |
| `title`, `description`, `priority` | [Title and description](#title-and-description), [Priority](#priority) |
| `alert` | `alert` |
| `remediation_steps` | `remediation`, only when set |
| `event_summary_template` | `summary`, only when set, 7.1+ |
| `tags`, `tactics_techniques` | [Tags](#tags), [ATT&CK](#attck), 7.2+ |
| `config.type` | `"aggregation-v1"` |
| `config.query` | `query`, verbatim |
| `config.query_parameters`, `config.filters` | `[]` |
| `config.streams` | the stream ids the block's (else the tenant's) `streams` aliases resolve to, in that order |
| `config.stream_categories` | `stream_categories` |
| `config.group_by`, `config.series`, `config.conditions` | from `aggregation` ([Compilation](#condition-grammar)); for a filter `[]`, `[]`, and `{"expression": null}` |
| `config.search_within_ms`, `config.execute_every_ms` | `schedule.window` and `schedule.every` in milliseconds |
| `config.use_cron_scheduling` | `true` with `cron`, else `false` |
| `config.cron_expression`, `config.cron_timezone` | `schedule.cron` and `schedule.timezone`, only with `cron`. With `cron`, `execute_every_ms` is sent equal to `search_within_ms`. |
| `config.event_limit` | `event_limit`, filters only |
| `field_spec` | `event_fields` by the [value forms](#event-field-values), plus `attack_techniques` before 7.2 |
| `key_spec` | `event_key` |
| `notification_settings` | `{"grace_period_ms": <grace_period in ms>, "backlog_size": <backlog>}` |
| `notifications` | `[{"notification_id": <id>}]` for each `notifications` alias |

**Before every create and update**, deploy sends the query:

```http
POST /api/search/validate
{"query": <query>, "streams": [<ids>], "stream_categories": [...], "timerange": {"type": "relative", "range": <window in seconds>}}
```

- `status: ERROR` fails the rule with `graylog_query_invalid` and Graylog's explanations, and nothing is saved. The validator refuses some queries OpenSearch would run: an open range (`graylog_open_range` offline), and `*` or `*:*`. For every message in the streams, write `_exists_:source`.
- Explanations of type `UNKNOWN_FIELD` are `graylog_unknown_field` (warning). `INVALID_VALUE_TYPE` explanations are `graylog_value_type` (warning). Every other `WARNING` or `INFO` explanation is `graylog_query_warning` (warning).

| Block status strategy | Binding in deployment state | Graylog calls |
|-----------------------|-----------------------------|---------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | `POST /api/events/definitions?schedule=true` with the create body for the version. The returned `id` is recorded at once. |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present | `PUT /api/events/definitions/{id}?schedule=true` with the whole definition and its `id` |
| `DISABLEMENT` | present | `PUT /api/events/definitions/{id}?schedule=false`, as above |
| `DELETION` | present | `DELETE /api/events/definitions/{id}`. Any 2xx removes the binding. Graylog answers 204 for an id it does not have. |
| `DISABLEMENT`, `DELETION` | none | `external_id_missing` (warning), no call |

Deploy never reads `state` from a create response: it may say `DISABLED` while the definition is scheduled.

| Situation | Behaviour |
|-----------|-----------|
| A `PUT` answers 404 | Create the definition again and replace the binding, with `graylog_definition_recreated` (warning). Under `DISABLEMENT`, create nothing, remove the binding, and warn `graylog_definition_missing`. |
| "Immutable entity cannot be modified" or "Non-deletable entity cannot be deleted" | `graylog_definition_immutable`. Deploy never changes a scope. |
| A `DELETE` refused because another definition depends on this one | `graylog_definition_in_use`, naming the dependants |
| 400 with `{"errors": {<field>: [<message>]}}` | `graylog_definition_invalid`, with the messages |
| 401 | `graylog_tenant_unauthorized`: the tenant stops |
| 403 | `graylog_forbidden`: the rule fails, most often for want of `streams:read` |
| A stream or notification alias the tenant does not define | `graylog_alias_unknown`, before any call for that rule |
| A create gets no answer (timeout, connection reset) | `graylog_create_unconfirmed`. Not retried: titles are not unique, so a retry may create a second definition. The failure names the title (and, on 7.2, the `opentide.<uuid>` tag). |
| `GET /api/system` reports a version below 6.3, or no version | `graylog_version_unsupported`: the tenant stops |

### Query validation

| Check | Graylog |
|-------|---------|
| `opentide validate` (offline) | yes: the constraints, the condition grammar, and the Graylog dialect |
| `opentide validate query` (offline) | the block's `query`, and `.lucene` query files under `--platform graylog` |
| `opentide validate query --live` | yes: `POST /api/search/validate` per tenant, with the block's streams and a relative range of `window` (a query file: no streams, 300 seconds). `ERROR` explanations are errors; `WARNING` and `INFO` explanations are warnings, with Graylog's line and column. |
| `opentide query` | yes: `POST /api/search/messages`, read-only, language `lucene` in the Graylog dialect. On 6.3 and 7.0, Graylog splits a requested field name on `.`. The runner then requests no dotted field and reads the whole message instead. |

## Relationships

- [platforms](index.md): shared fields, capability matrix, external ids
- [deployment-state.md](../deployment-state.md): the event definition id
- [deployment.md](../deployment.md): status strategies
- [rule-1.0.md](../objects/rule-1.0.md): `response.alert_severity`, `techniques`, `detection_model`, `description`
- [elastic-1.0.md](elastic-1.0.md): durations, the ATT&CK technique set and tactic table
- [validation.md](../validation.md): static validation, advisories, query validation
- [RFC 0017](../../rfcs/0017-graylog-platform.md): design, research, version matrix, and alternatives

## Defaults & overrides

| Field | Default |
|-------|---------|
| Title | Shared `name`, else the opentide rule `name` |
| `priority` | [Priority](#priority), else Medium (2) |
| `alert` | `true` |
| `streams` | Tenant `streams`, else none (every readable stream) |
| `schedule` | `every: 5m`, `window` equal to `every` |
| `event_limit` | `100` (filters) |
| `grace_period`, `backlog` | `0s`, `0` |
| `allow_leading_wildcard` | `false` |

## Examples

A filter:

```yaml
configurations:
  graylog:
    enabled: true
    schema: platform::graylog::1.0
    status: STAGING
    streams: sysmon
    query: EventID:1 AND image_lc:/.*\\mshta\.exe/
```

An aggregation, with event fields, a key, and a notification:

```yaml
configurations:
  graylog:
    enabled: true
    schema: platform::graylog::1.0
    status: PRODUCTION
    streams: sysmon
    schedule: {every: 5m, window: 15m}
    aggregation:
      group_by: source
      condition: count() >= 3 OR card(parent_image_lc) >= 2
    event_fields:
      host: source
      user: User
    event_key: host
    grace_period: 30m
    notifications: soc-slack
    summary: Obfuscated PowerShell from ${source.ParentImage} on ${source.source}
    remediation: Isolate the host and collect the process tree.
    query: >-
      EventID:1
      AND parent_image_lc:/.*\\(winword|excel|powerpnt|outlook)\.exe/
      AND image_lc:/.*\\(powershell|pwsh)\.exe/
      AND command_line_lc:/.*( -enc | -encodedcommand |frombase64string|iex\().*/
      AND NOT command_line_lc:/.*\\program files\\contoso\\admintools\\.*/
```

Fixtures:

- block: [fixtures/platforms/graylog.yaml](../../fixtures/platforms/graylog.yaml);
- rules: [fixtures/valid/rule-graylog-aggregation-1.0.yaml](../../fixtures/valid/rule-graylog-aggregation-1.0.yaml) and [fixtures/valid/rule-graylog-filter-1.1.yaml](../../fixtures/valid/rule-graylog-filter-1.1.yaml);
- the tenant they deploy to: [fixtures/platforms/graylog/tenant.toml](../../fixtures/platforms/graylog/tenant.toml);
- the requests deploy sends, as `{method, path, body}`, per server version, under [fixtures/platforms/graylog/](../../fixtures/platforms/graylog/).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-11-11 | Initial field contract ([RFC 0017](../../rfcs/0017-graylog-platform.md)): one `aggregation-v1` event definition per block. Query, aggregation condition grammar, event-field value forms, and string-or-list fields. Graylog 6.3, 7.0, 7.1, and 7.2, each request built for the detected version. The event definition id in deployment state; `--live` through `/api/search/validate`. |
| 1.1 | 2026-11-11 | Clarifications from the engine's oracle run against Graylog 7.2.2 and 6.3.5: Graylog refuses `\b` and `\B` (`graylog_regex_unsupported`); `graylog_regex_quote` is a paired quote, an unpaired one being `lucene_regexp`; new `graylog_open_range` (error) for an open range bound, which Graylog's validator refuses; `_exists_:source` for every message, since the validator refuses `*` and `*:*`. Schema id unchanged. |
