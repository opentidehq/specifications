# RFC 0017: Graylog detection platform

- **RFC:** 0017
- **Title:** Graylog detection platform (native event definitions)
- **Author:** opentide maintainers
- **Status:** accepted
- **Created:** 2026-11-11
- **Accepted:** 2026-11-11, with the normative text in [specs/platforms/graylog-1.0.md](../specs/platforms/graylog-1.0.md)
- **Issue:** to be opened in opentidehq/specifications (spec-change)
- **Related:** [RFC 0016](0016-bitdefender-gravityzone-platform.md) and [RFC 0014](0014-sysdig-falco-platform.md) (the state-backed platform pattern); [RFC 0010](0010-deployment-external-ids.md) (deployment external ids); [RFC 0007](0007-elastic-security-platform.md) (the ATT&CK and duration conventions reused here)
- **Implementation:** opentidehq/opentide (the `graylog` platform); opentidehq/language-server (`Dialect::Graylog` and the Graylog block checker)

## Summary

Add an eleventh detection platform, `graylog` (display name **Graylog**, schema `platform::graylog::1.0`). A `graylog` block is one Graylog **event definition** of the Filter & Aggregation type (`aggregation-v1`). It holds:

- a search query in Graylog's search syntax;
- optionally, an aggregation (group-by fields and a condition such as `count() >= 3 OR card(user_name) >= 2`);
- streams, schedule, event fields, notifications, and response text.

Event definitions are in every Graylog edition, Open included. They are also the type Graylog itself stores detections as: since 7.2, even an imported Sigma rule becomes an event definition.

Deploy uses the event-definition REST API. Graylog assigns each definition a 24-hex id, which opentide keeps in [deployment state](../specs/deployment-state.md). Supported versions are **Graylog 6.3, 7.0, 7.1, and 7.2**. The API differs between them in its create body and in a few fields, so deploy detects the server version and builds each request for it ([version matrix](#version-matrix-63-to-72)).

Graylog has a real query check, `POST /api/search/validate`, so Graylog joins the `--live` allowlist. Offline, the analysis engine checks queries with a Graylog dialect of its Lucene parser.

**Sigma is not part of this RFC.** It was researched and then dropped ([Sigma](#sigma-researched-and-not-adopted)).

Every behaviour the design relies on was tested on live **Graylog 6.3.5** (Open, the same build as a production user's) and **Graylog 7.2.2** (Enterprise build without a licence) on 2026-11-11. The 7.0 and 7.1 columns come from a diff of the graylog2-server source at every tag in between.

The change is additive. It adds `configurations.graylog`, a `graylog` deployment-state platform, and diagnostics. It changes no existing block.

## Motivation

Graylog is a widely deployed log management platform and SIEM. Graylog Open is free, and Graylog Security is its paid SIEM edition. opentide cannot reach it today. Teams keep Graylog event definitions in the web interface, with no review, no objectives, and no lifecycle. They also have no record of which ATT&CK techniques each definition covers.

Event definitions are Graylog's detection object on every edition and every supported version. One platform block for them covers every Graylog customer.

## Research

Sources are labelled:

- **[live]** tested on Graylog 6.3.5 and 7.2.2, 2026-11-11, with identical requests;
- **[src]** read in `Graylog2/graylog2-server` at tags 6.3.0, 6.3.5, 6.3.15, 7.0.0, 7.0.16, 7.1.0, 7.1.12, 7.2.0, 7.2.1, and 7.2.2;
- **[doc]** Graylog documentation, `UPGRADING.md`, or changelog.

### Verified on Graylog 6.3.5 and 7.2.2

Two stacks ran side by side in Docker, each with its own MongoDB 7.0 and OpenSearch 2.19.2: `graylog/graylog:6.3.5` and `graylog/graylog-enterprise:7.2.2` (no licence). Events came in through GELF TCP. One probe script sent the same requests to both.

| # | Finding | 6.3.5 | 7.2.2 | Consequence |
|---|---------|-------|-------|-------------|
| V1 | Create body (`POST /api/events/definitions`) | the definition itself, or the definition with a sibling `share_request`; `{"entity": …}` is refused ("Missing required properties: title …") | only `{"entity": <definition>, "share_request": …}`; a bare definition is refused ("entity cannot be null") | Deploy sends the create body for the detected version. `PUT` takes the bare definition on both. |
| V2 | Unknown top-level property on create (`bogus`, or `tags`, `tactics_techniques`, `event_summary_template` on 6.3) | **accepted with 200 and silently dropped** | 400 "Unable to map property" | Deploy never sends a field the version does not know. A 200 does not prove the field was stored. |
| V3 | State after a create with `?schedule=true` | the response says `DISABLED`, a later GET says `ENABLED` | the same | Deploy never reads `state` from a create response. |
| V4 | `PUT` without `?schedule=false` | re-enables a disabled definition | the same | Every `PUT` carries an explicit `?schedule=`. |
| V5 | `PUT /{id}/schedule`, `/unschedule`; echoing the whole GET body back in `PUT` | 200; 200 | 200; 200 | Both work for enable and disable. |
| V6 | Missing id: GET, PUT, DELETE | 404, 404, **204** | 404, 404, **204** | A delete is idempotent. Update-on-404 recreates. |
| V7 | Create with a client-chosen `id` | 200, the id echoed, **nothing stored** (GET 404) | the same; the scheduler trigger is left in permanent ERROR | Deploy MUST NOT send `id` on create. Graylog is state-backed with server-assigned ids. |
| V8 | Query parsed at save | no: `Image:(foo` is stored | no | Deploy MUST check the query before it saves. |
| V9 | `POST /api/search/validate` | `status` plus `explanations` with `error_type` and positions: `QUERY_PARSING_ERROR` (ERROR), `UNKNOWN_FIELD`, `INVALID_OPERATOR`, `INVALID_VALUE_TYPE` (WARNING) | identical | A real tenant check on every version: Graylog joins `--live`. |
| V10 | Priority 0, 4, 5 | all stored | all stored | No server range check. opentide sends 0–4 by version ([matrix](#version-matrix-63-to-72)). |
| V11 | 5-field cron; `event_limit` 0 or 5000 on a filter | refused ("expect one of [6, 7]"; "greater than 0"; "less than 1000") | identical | Static constraints mirror them. |
| V12 | `group_by` without series and conditions; `key_spec` not in `field_spec` | refused | refused | Static constraints mirror them. |
| V13 | Aggregation `count() >= 3 OR card(User) >= 2`; series `percentile`, `latest`, `percentage` | accepted | accepted | One condition grammar for every version. |
| V14 | Aggregation functions (`GET /api/events/entity_types`) | `avg card count max min stddev sum sumofsquares variance percentage percentile latest` | identical | The grammar's 12 functions. |
| V15 | `_scope: GRAYLOG_IMMUTABLE_SCOPE` in a create body | stored; the definition can never be edited or deleted again | the same (7.2.2 also refuses PUT on `ILLUMINATE`) | Deploy always sends `_scope: DEFAULT`. |
| V16 | `remediation_steps`, `stream_categories`, 6-field cron | stored | stored | Available on every supported version. |
| V17 | `tags`, `tactics_techniques`, `event_summary_template` | dropped (V2) | stored; tags lower-cased, `[a-z0-9_.-]` only; techniques upper-cased, `T####(.###)`/`TA####` only | Sent on 7.2 only (summary on 7.1+). |
| V18 | `GET …/paginated?query=tags:opentide` | 0 results (no tags) | exact matches | Not used by deploy. Useful to analysts on 7.2. |
| V19 | `POST /api/search/messages` | rows | rows | The `opentide query` runner, on every version. |
| V20 | `POST` without `X-Requested-By` | 400 | 400 | A required header on every version. |
| V21 | Access token creation, with and without a TTL | issued | issued | One auth path for every version. |
| V22 | Titles | not unique | not unique | No name conflict. A workspace advisory warns on duplicates. |
| V23 | Firing (7.2.2) | — | a filter definition fired one alert per message, carrying priority, `tactics_techniques`, and templated fields. An aggregation definition fired one alert per group. Overlapping windows repeated alerts. | The default window equals the interval. Overlap is a warning. |

Query-syntax findings, the same on both versions because the search backend is the same [live]:

| # | Finding | Consequence |
|---|---------|-------------|
| Q1 | Field names are case-sensitive. Ordinary string fields are case-sensitive keywords. `message` and `full_message` are analysed. `source` is a lower-cased keyword. | Native queries match case as written. A lower-casing pipeline makes case-insensitive rules readable ([B.10](#b10-case-insensitive-matching)). |
| Q2 | Leading wildcards fail (`allow_leading_wildcard_searches = false` by default): "'*' or '?' not allowed as first character". | Error offline unless the tenant allows them. Regex with a leading `.*` works. |
| Q3 | Regex is anchored. `\\` in the query text is one literal backslash. `\\\\` matches nothing, with no error. | A warning for doubled backslashes. |
| Q4 | Lucene regex operators are on: an unescaped `#`, `&`, `<…>`, or `~` changes the meaning, and validate returns OK for most of them. | A warning for unescaped operators. |
| Q5 | `(?i)`, `\b`, and lookahead silently match nothing. `\d`, `\w`, `\s`, `{n,m}`, alternation `(a\|b)`, and numeric intervals `<16-31>` work. | An error for silent regex failures. |
| Q6 | `_exists_:f`, numeric ranges, and unqualified phrases work. A bare CIDR is a parse error. A quoted CIDR on a keyword field matches nothing. | Hover guidance. |
| Q7 | A detection rewritten over lower-cased copies of the fields, with regex alternation (`parent_image_lc:/.*\\(winword\|excel\|powerpnt\|outlook)\.exe/ AND …`), matched exactly its 3 positive events out of 8 on 7.2.2, and validate returned OK. | The readable form the documentation teaches ([B.10](#b10-case-insensitive-matching)). |

### Version matrix (6.3 to 7.2)

From the source diff [src], confirmed live where a column says so. Within a minor line, the event-definition fields do not change between patches: 6.3.0 and 6.3.15 are identical.

| Feature | 6.3 | 7.0 | 7.1 | 7.2 | Notes |
|---------|-----|-----|-----|-----|-------|
| Create body | flat (+ `share_request`) [live] | `{entity, share_request}` | same | same [live] | `PUT` and `POST /validate` take the bare definition on every version |
| Unknown top-level property on create | silently dropped [live] | 400 | 400 | 400 [live] | On 6.3, an unknown key on update, or nested inside `config`, is a 400 |
| `aggregation-v1` config and its validation | baseline | identical | identical | identical | The file is byte-identical from 6.3.0 to 7.2.2 |
| Series types (12) | yes | yes | yes | yes | |
| Condition tree JSON | untyped | untyped | boolean/number typed | same | Same JSON. The fired event's `aggregation_conditions` keys change from `count()` to `count` in 7.1 |
| `remediation_steps`, `stream_categories`, cron scheduling | yes | yes | yes | yes | |
| `_entity_source` (read-only) | no | yes | yes | yes | Never sent |
| `event_summary_template` | **no** | **no** | yes | yes | |
| `tags` | **no** | **no** | **no** | yes | Lower-cased, `[a-z0-9_.-]+`, ≤ 128 characters, ≤ 64 |
| `tactics_techniques` | **no** | **no** | **no** | yes | `TA####`, `T####(.###)`, ≤ 64; validation can be switched off on the server |
| Template field option `exclude_empty_fields` | **no** | **no** | **no** | yes (default `true`) | A nested key: a 400 on older versions |
| Priorities in the web interface | 1–4 | 1–4 | 0–4 (0 = Info) | 0–4 | No server-side range check on any version |
| `GET /events/definitions/tags`; status/type/tag list filters | no | no | no | yes | |
| `/search/validate` request and response | baseline | identical | identical | identical [live] | |
| `/search/messages` field names | `.` splits decorators | same | `#` | `#`; default fields: all | Dotted field names break on 6.3 and 7.0. Use POST: GET ignores `streams` before 7.2.2. |
| Notification types (Open) | 8 | 8 | 8 | 8 | Some type configs gain options (email and Slack `include_event_procedure`, PagerDuty title and key) |
| OpenAPI at `/api/openapi` | no | no | yes | yes | Older versions serve Swagger 1.2 at `/api/api-docs` |
| Access tokens | 30-day default TTL on fresh installs | forced on upgrades too | same | same | |
| Token-revocation flaw GHSA-j769-9gv9-65gr | **affected before 6.3.12** | fixed in 7.0.16 | fixed in 7.1.12 | fixed | Deploy warns on an affected version |

**7.x-only features opentide uses:** `event_summary_template` (7.1+), `tags` and `tactics_techniques` (7.2+), priority 0 (7.1+), and `exclude_empty_fields` (7.2+). Everything else in a block works on 6.3. [B.4](#b4-derived-fields) says what each version receives instead.

### Event definitions

The resource is `org/graylog/events/rest/EventDefinitionsResource.java` [src].

| Method and path | Use in opentide |
|-----------------|-----------------|
| `POST /api/events/definitions?schedule=<bool>` | create (V1, V3) |
| `PUT /api/events/definitions/{id}?schedule=<bool>` | update, enable, disable (V4) |
| `DELETE /api/events/definitions/{id}` | delete (V6) |
| `POST /api/search/validate` | the pre-save check, and `validate query --live` (V8, V9) |
| `POST /api/search/messages` | `opentide query` (V19) |
| `GET /api/system` | the version, once per tenant per run |
| `POST …/{id}/execute` | **not used**: it creates real events and notifications |
| `GET …/paginated` | **not used on deploy**: no rediscovery by listing |

Required on every version [src][live]: `title` (non-empty), `description` (non-null), `priority`, `alert`, `config`, `key_spec`, and `notification_settings`. `aggregation-v1` requires `query`, `streams`, `group_by`, `series`, and intervals greater than 0. Empty `streams` means every stream the user can read. A filter needs `event_limit` from 1 to 1,000. The server sets `id`, `updated_at`, `matched_at`, `scheduler`, and `storage`.

Licensing [doc]:

- Open: filter and aggregation definitions, notifications, search validation, the scripting API.
- Enterprise: correlation, search filters, and parameters.
- Security: Sigma, anomaly detection, event procedures, and Threat Coverage.

This RFC uses only Open features.

### Sigma, researched and not adopted

This RFC's earlier drafts delivered Sigma two ways. First, opentide converted Sigma itself. Then, opentide sent Sigma to Graylog's own importer. Both were dropped:

- **The API changed incompatibly in 7.2** [doc: upgrade to 7.2]. Up to 7.1, Sigma rules had their own CRUD API (`/sigma/rules`, with in-place updates). In 7.2, "the first-order Sigma rule entity no longer exists". Rules come in only through `…/sigma/import/*` or Git import, and "all other `/sigma/rules/...`" endpoints were "Deleted (use the event definition API to manage)".
- **A 7.2 import cannot be managed as code.** The import result does not return the created definition's id [api; jar]. A re-upload of the same Sigma `id` is skipped, not updated. Changing Sigma logic therefore means delete and re-import, which gives the definition a new id.
- **Correlations depend on the version.** 6.2–7.1 import `event_count`, `value_count`, and `temporal_ordered` correlations, one file each, and each becomes its own alert. 7.2 imports none: "Sigma correlation rules can no longer be directly imported or uploaded."
- **It is licence-gated.** Every Sigma endpoint returns 402 without a Security licence [live], and the Open build contains no Sigma code at all [live].
- **The result is an event definition.** Once imported, a Sigma rule is an event definition holding the query Graylog's converter generated. Managing event definitions directly gives the same runtime object, on every edition and version, with stable ids and in-place updates.

A later RFC can add Sigma as an authoring source that is converted into native event definitions. Nothing in this design blocks that.

## Detailed design

### Decisions

1. **One kind: native event definitions.** A `graylog` block deploys one `aggregation-v1` event definition.
2. **Graylog 6.3, 7.0, 7.1, and 7.2.** Deploy detects the version and builds each request for it. Fields a version lacks are left out, or carried another way ([B.4](#b4-derived-fields)).
3. **State-backed identity.** The server-assigned id goes in deployment state. Client-assigned ids are rejected (V7).
4. **Graylog checks before save.** Every query goes through `/api/search/validate` first (V8).
5. **One engine language.** `graylog`, a dialect of the existing Lucene parser, injected into `configurations.graylog.query`. The aggregation condition is a field of the block. The block checker parses it, with positions, and it is not a separate language.

---

## Part B: Graylog platform (`platform::graylog::1.0`)

Normative file: [specs/platforms/graylog-1.0.md](../specs/platforms/graylog-1.0.md) (`spec: platform-graylog`, `version: "1.0"`, `schema_id: platform::graylog::1.0`). Part B keeps the letter of earlier drafts, so references in review threads still resolve. Where this RFC and the spec differ, the spec wins.

### B.1 Shape

```yaml
configurations:
  graylog:
    enabled: true
    schema: platform::graylog::1.0
    status: PRODUCTION                  # shared; required
    name: ""                            # shared; empty → the opentide rule name
    streams: sysmon                     # a tenant alias, or a list of them
    schedule: {every: 5m, window: 15m}
    aggregation:
      group_by: source
      condition: count() >= 3 OR card(parent_image_lc) >= 2
    event_fields:
      host: source                      # a bare field name: copy that message field
      user: User
      account: "${source.User}@${source.Domain}"   # a template
    event_key: host
    grace_period: 30m
    notifications: soc-slack            # a tenant alias, or a list of them
    summary: Obfuscated PowerShell from ${source.ParentImage} on ${source.source}   # 7.1+
    remediation: Isolate the host and collect the process tree.
    query: >-
      EventID:1
      AND parent_image_lc:/.*\\(winword|excel|powerpnt|outlook)\.exe/
      AND image_lc:/.*\\(powershell|pwsh)\.exe/
      AND command_line_lc:/.*( -enc | -encodedcommand |frombase64string|iex\().*/
      AND NOT command_line_lc:/.*\\program files\\contoso\\admintools\\.*/
```

### B.2 Block fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | A Graylog search query ([B.7](#b7-graylog-query-dialect)). Non-blank. |
| `priority` | string | optional | [derived](#b4-derived-fields) | `Informational`, `Low`, `Medium`, `High`, or `Critical` |
| `alert` | boolean | optional | `true` | `false` makes fired events plain events, not alerts |
| `tags` | string or list[string] | optional | `[]` | Added to the [derived tags](#b4-derived-fields) (7.2+) |
| `streams` | string or list[string] | optional | tenant `streams` | Aliases from the tenant's `stream_ids` table |
| `stream_categories` | string or list[string] | optional | `[]` | Graylog stream categories, as written |
| `schedule` | [Schedule](#schedule) | optional | `{every: 5m}` | When the definition runs and what it searches |
| `event_limit` | integer | optional | `100` | Filter only: at most this many events per run, 1–1,000 |
| `aggregation` | [Aggregation](#aggregation) | optional | null | Turns the filter into an aggregation |
| `event_fields` | map | optional | `{}` | Event field name → a [value](#event-field-values) |
| `event_key` | string or list[string] | optional | `[]` | Event fields that make up the event key |
| `notifications` | string or list[string] | optional | `[]` | Aliases from the tenant's `notification_ids` table |
| `grace_period` | duration | optional | `0s` | Per event key |
| `backlog` | integer | optional | `0` | Messages attached to a notification (`backlog_size`), 0 or more |
| `summary` | string | optional | null | Event summary template (7.1+) |
| `remediation` | string | optional | null | Remediation steps |

The shared `name` is the definition title. `status` is required, as on `elastic`, `sysdig`, and `bitdefender`.

**List fields.** `tags`, `streams`, `stream_categories`, `event_key`, `notifications`, and `aggregation.group_by` take one string or a list of strings. A string is a one-item list. The list is the canonical form templates and documentation write. opentide already takes this shape elsewhere (Elastic's `job_id`, Sysdig's `fields`).

#### Event field values

| Written | Meaning | Graylog provider |
|---------|---------|------------------|
| a bare field name (`source`, `User`; matches `[A-Za-z0-9_.@-]+`) | copy that field of the message that fired the event | `template-v1`, template `${source.<field>}` |
| a string containing `${` | a Graylog template, sent as written | `template-v1`, the string |
| `{template: <string>}` | a template or constant text, sent as written | `template-v1`, the string |
| `{lookup: {table: <name>, key_field: <field>}}` | a lookup-table value keyed by a message field | `lookup-v1` |

A string that is neither a field name nor contains `${` is `graylog_event_field`: constant text is written `{template: "…"}`. `${source.X}` is Graylog's own syntax, and in it `source` names the message, not the `source` field. The bare form spares authors `${source.source}`.

#### Schedule

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `every` | duration | `5m` | `execute_every_ms`. Exclusive with `cron`. |
| `window` | duration | `every` | `search_within_ms` |
| `cron` | string | null | Quartz cron, 6 or 7 fields (`0 */5 * * * ?`). Exclusive with `every`. |
| `timezone` | string | `UTC` | IANA zone for `cron` |

Durations follow the [Elastic duration grammar](../specs/platforms/elastic-1.0.md#durations) and are sent in milliseconds. With `cron`, `window` is required.

#### Aggregation

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `group_by` | list[string] | optional | Message fields to group by |
| `condition` | string | yes | Boolean expression over series, in [the condition grammar](#aggregation-condition-grammar) |

The series list is not written. It is derived from the functions the condition calls, so a series can never be declared and unused, or used and undeclared.

##### Aggregation condition grammar

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
```

Argument rules:

- `count()` takes an optional field.
- `percentile(field, p)` requires `0 < p ≤ 100`.
- Every other function requires a field.

These are the 12 functions of V14, on every version. Deploy sends one series for each distinct call, with id `<function>-<field>` (`count-` for `count()`). The expression becomes Graylog's condition tree: `&&`, `||`, `!`, the comparison operators, `number-ref` (a series id), and `number`.

Example: `count() >= 3 OR card(parent_image_lc) >= 2` becomes:

- series `[{id: "count-", type: "count"}, {id: "card-parent_image_lc", type: "card", field: "parent_image_lc"}]`;
- the condition `{expr: "||", left: {expr: ">=", left: {expr: "number-ref", ref: "count-"}, right: {expr: "number", value: 3}}, right: {…}}`.

V13 accepted this shape on both versions.

### B.3 Constraints

Static validation MUST reject a block that breaks any of these, and report the code.

| Code | Constraint |
|------|------------|
| `graylog_query_blank` | `query` is non-blank |
| `graylog_schedule` | Exactly one of `every` and `cron`. Durations follow the grammar and are greater than zero. `cron` has 6 or 7 fields and parses as Quartz (V11). `timezone` is an IANA zone. `window` is set with `cron`. |
| `graylog_event_limit` | `event_limit` is 1–1,000 (V11). It is not set together with `aggregation`. |
| `graylog_aggregation` | `condition` parses under the [grammar](#aggregation-condition-grammar). Each function has the arguments it needs. `group_by` has unique, non-empty field names, and needs a `condition` (V12). |
| `graylog_event_field` | Each `event_fields` name is a valid Graylog field name (`[A-Za-z0-9_.@-]+`). Each value is one of the [value forms](#event-field-values): a bare field name, a string containing `${`, `{template}` with a non-blank string, or `{lookup}` naming `table` and `key_field`. |
| `graylog_event_key` | Each `event_key` entry is an `event_fields` key (V12) |
| `graylog_priority` | `priority` is one of the five names |
| `graylog_field_name` | A field name in `query`, `group_by`, or a condition is a valid Graylog field name |
| `graylog_query_syntax` | `query` parses under the [Graylog dialect](#b7-graylog-query-dialect) |
| `graylog_leading_wildcard` | A term in `query` starts with `*` or `?`, and a targeted tenant does not set `allow_leading_wildcard` (Q2) |
| `graylog_regex_unsupported` | A regex uses a construct Lucene RegExp silently fails on: `(?i)` or another inline flag, `\b`, `\B`, lookaround, or a backreference (Q5) |

Advisories (warnings, [validation.md](../specs/validation.md#platform-advisories)):

| Code | When |
|------|------|
| `graylog_overlapping_window` | `window` is longer than `every` on a filter (no `aggregation`): each message alerts once per overlapping run (V23) |
| `graylog_lowercase_operator` | `and`, `or`, or `not` as a bare term: Graylog searches the word (V9) |
| `graylog_regex_operator` | An unescaped `#`, `&`, `<`, `>`, or `~` inside a regex (Q4) |
| `graylog_regex_quote` | An unescaped `"` inside a regex |
| `graylog_double_backslash` | `\\\\` where the value most likely has one backslash (Q3) |
| `graylog_analyzed_field` | A regex, wildcard, or range on `message` or `full_message` (Q1) |
| `graylog_case_sensitive` | A term with letters on a keyword field, not written lower-case against a lower-cased field: Graylog matches it case-sensitively (Q1). Reported once per query. |
| `graylog_all_streams` | No `streams` and no `stream_categories`, on the block or the tenant |
| `graylog_title_duplicate` | Workspace check: two enabled blocks resolve to one title (V22) |

### B.4 Derived fields

| Graylog field | Derivation | Versions |
|---------------|-----------|----------|
| `title` | Shared `name`, else the rule `name` | all |
| `description` | The rule `description`, whitespace collapsed. Before 7.2, deploy appends `ATT&CK: <technique ids>` (see `tactics_techniques`). | all |
| `priority` | `priority`, else from the rule severity: Critical 4, High 3, Medium 2, Low 1, Informational 0. Before 7.1, Informational is sent as 1 (`graylog_priority_collapsed`, warning). | all |
| `alert` | `alert` | all |
| `tags` | Union, de-duplicated: block `tags`; `opentide`; `opentide.<metadata.uuid>`; tenant `tags`. Each lower-cased, any character outside `[a-z0-9_.-]` replaced by `-`, cut at 128 characters, at most 64. | **7.2+**; left out before 7.2 |
| `tactics_techniques` | The rule's techniques and those inherited through `detection_model`, Enterprise only ([Elastic ATT&CK rule](../specs/platforms/elastic-1.0.md#attck)), then their tactic ids from the same table. At most 64. | **7.2+**. Before 7.2: a description line, plus an event field `attack_techniques` (a constant template, the comma-separated ids), so every fired event still carries them. |
| `event_summary_template` | `summary` | **7.1+**; left out before 7.1, with `graylog_field_unsupported_version` (warning) |
| `remediation_steps` | `remediation` | all |
| `config.query` | `query` | all |
| `config.streams`, `stream_categories` | ids resolved from the aliases; categories as written | all |
| `config.series`, `conditions`, `group_by` | from `aggregation` (`group_by` as a list); empty and `{"expression": null}` for a filter | all |
| `config` intervals and cron | from `schedule` | all |
| `field_spec` | `event_fields`, by the [value forms](#event-field-values); each template provider `{type: template-v1, template, require_values: false}`, each lookup `{type: lookup-v1, table_name, key_field}`. `exclude_empty_fields` is never sent: it is 7.2+ only, nested, and refused before 7.2. | all |
| `key_spec` | `event_key`, as a list | all |
| `notification_settings` | `grace_period` in ms, `backlog` | all |
| `notifications` | ids resolved from the aliases | all |
| `_scope` | always `DEFAULT` (V15) | all |

`opentide.<uuid>` is for analysts and audits. Deploy never uses it to find a definition.

### B.5 Version handling

Once per tenant per run, deploy reads `GET /api/system`:

| Version | Behaviour |
|---------|-----------|
| below 6.3 | `graylog_version_unsupported`: the tenant fails |
| 6.3.x | flat create body; no `tags`, `tactics_techniques`, or `event_summary_template`; Informational sent as 1 |
| 7.0.x | wrapped create body; otherwise as 6.3 |
| 7.1.x | wrapped; `event_summary_template`; priority 0 |
| 7.2.x and later | wrapped; every field |
| below 6.3.12, 7.0.16, or 7.1.12 | `graylog_version_vulnerable` (warning): the token-revocation flaw GHSA-j769-9gv9-65gr |

A request body never carries a field the detected version does not define (V2). Deploy builds the body from the version table, not from a trial and error with the server.

### B.6 Tenant setup

```toml
[platform]
enabled = true
identifier = "graylog"
name = "Graylog"
description = "Graylog event definitions."
flags = []

[[tenants]]
name = "graylog-prod"
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
| `url` | string | yes | — | Base URL of the Graylog web interface. The client appends `/api`. |
| `token` | string | yes | — | Graylog access token. MUST be a `$ENV` reference. Sent as HTTP Basic `<token>:token`. |
| `allow_leading_wildcard` | bool | no | `false` | Mirrors the server's `allow_leading_wildcard_searches` |
| `streams` | list[string] | no | `[]` | Default stream aliases |
| `stream_ids` | table | no | `{}` | Alias → stream id (24 hex) |
| `notification_ids` | table | no | `{}` | Alias → notification id (24 hex) |
| `tags` | list[string] | no | `[]` | Tags added to every definition (7.2+) |
| `ssl` | bool | yes | — | Shared tenant setup (TLS verification) |

The token's user needs `eventdefinitions:create`, `:read`, `:edit`, and `:delete`, plus `streams:read` on every stream a definition names, on every version. A stream or notification alias the tenant does not define fails that rule at deploy (`graylog_alias_unknown`).

### B.7 Graylog query dialect

The engine adds `Dialect::Graylog` to its Lucene `query_string` parser (`opentide-lucene`, beside `Elastic` and `CarbonBlack`). The dialect differs from `Elastic` in four ways:

- A leading wildcard is an error unless the tenant allows it (Q2).
- A lower-case operator is a warning (V9).
- Regex bodies are checked against Lucene RegExp, including alternation and numeric intervals. Q3–Q5's silent failures are diagnosed.
- Field names follow Graylog's `Message.validKey`. A GIM catalogue supplies completion and hover.

`/api/search/validate` is the dialect's oracle. Its request and response are byte-identical from 6.3.0 to 7.2.2 [src][live]. On the conformance corpus, the engine's syntax verdict MUST equal Graylog's `QUERY_PARSING_ERROR` verdict.

### B.8 Deploy

Graylog is **state-backed**, like Defender for Endpoint, SentinelOne, CrowdStrike, Sysdig, and Bitdefender:

- **Where.** `platforms.graylog.<tenant>` in `.opentide/states/deployment/<uuid>.json` (`deployment.state::1.0`), one binding per tenant.
- **Shape.** The 24-hex id from the create response, lower-case, `^[0-9a-f]{24}$`. The shard schema's existing `objectIdTenants` covers it.
- **No rediscovery.** Deploy MUST NOT find a definition by listing, by title, or by tag.
- **No client ids.** Deploy MUST NOT send `id` on create (V7).
- **No orphan creates.** As for Bitdefender, `deployment_state_ignored` and `deployment_state_unpersisted` refuse a create whose id cannot be kept.

Before each create or update, deploy MUST send the query to `POST /api/search/validate`, with the definition's streams, stream categories, and a relative time range of `window`:

- `ERROR` fails the rule with `graylog_query_invalid` and Graylog's explanations, and nothing is saved.
- `WARNING` explanations are reported as warnings: `UNKNOWN_FIELD` is `graylog_unknown_field`, and `INVALID_VALUE_TYPE` is `graylog_value_type`.

| Block status strategy | Binding | Graylog calls |
|-----------------------|---------|---------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | `POST /api/events/definitions?schedule=true`, with the body for the version (B.5); the returned `id` is recorded |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present | `PUT /api/events/definitions/{id}?schedule=true` with the **whole** definition |
| `DISABLEMENT` | present | `PUT /api/events/definitions/{id}?schedule=false` with the whole definition |
| `DELETION` | present | `DELETE /api/events/definitions/{id}`; any 2xx (V6) removes the binding |
| `DISABLEMENT`, `DELETION` | none | `external_id_missing` (warning), no call |

The body never carries `id` (on create), `state`, `storage`, `scheduler`, `updated_at`, `matched_at`, or `_entity_source`. It carries `_scope: DEFAULT`. Every request sends `X-Requested-By: opentide` and `Accept: application/json` (V20).

A 7.2 create body (abridged):

```json
{
  "entity": {
    "_scope": "DEFAULT",
    "title": "Office application spawns obfuscated PowerShell",
    "description": "An Office application started PowerShell with an encoded or downloaded command.",
    "priority": 3,
    "alert": true,
    "tags": ["opentide", "opentide.00000000-0000-4000-8003-000000000040", "managed-by-opentide"],
    "tactics_techniques": ["T1059.001", "T1566.001", "TA0001", "TA0002"],
    "event_summary_template": "Obfuscated PowerShell from ${source.ParentImage} on ${source.source}",
    "remediation_steps": "Isolate the host and collect the process tree.",
    "config": {
      "type": "aggregation-v1",
      "query": "EventID:1 AND parent_image_lc:/.*\\\\(winword|excel|powerpnt|outlook)\\.exe/ AND …",
      "query_parameters": [], "filters": [],
      "streams": ["65f0c0ffee0123456789abcd"], "stream_categories": [],
      "group_by": ["source"],
      "series": [{"id": "count-", "type": "count"}, {"id": "card-parent_image_lc", "type": "card", "field": "parent_image_lc"}],
      "conditions": {"expression": {"expr": "||",
        "left":  {"expr": ">=", "left": {"expr": "number-ref", "ref": "count-"}, "right": {"expr": "number", "value": 3}},
        "right": {"expr": ">=", "left": {"expr": "number-ref", "ref": "card-parent_image_lc"}, "right": {"expr": "number", "value": 2}}}},
      "search_within_ms": 900000, "execute_every_ms": 300000, "use_cron_scheduling": false
    },
    "field_spec": {"host": {"data_type": "string", "providers": [{"type": "template-v1", "template": "${source.source}", "require_values": false}]}},
    "key_spec": ["host"],
    "notification_settings": {"grace_period_ms": 1800000, "backlog_size": 0},
    "notifications": [{"notification_id": "65f0c0ffee0123456789abcf"}]
  },
  "share_request": null
}
```

The 6.3 body is the same definition with `share_request` beside its fields instead of `entity` around them. It has no `tags`, `tactics_techniques`, or `event_summary_template`, and it gains the `ATT&CK:` description line and the `attack_techniques` event field.

Failure handling:

- **Definition gone.** A `PUT` answered 404 creates the definition again and replaces the binding (`graylog_definition_recreated`, warning). Under `DISABLEMENT`, deploy creates nothing, removes the binding, and warns `graylog_definition_missing`.
- **Immutable.** "Immutable entity cannot be modified" or "Non-deletable entity cannot be deleted" (V15) fails the rule with `graylog_definition_immutable`.
- **In use.** A `DELETE` refused because a correlation depends on the definition fails with `graylog_definition_in_use`.
- **Refused body.** A 400 with `{"errors": {field: [messages]}}` fails the rule with `graylog_definition_invalid`.
- **Authorisation.** 401 stops the tenant (`graylog_tenant_unauthorized`). 403 fails the rule (`graylog_forbidden`); it is most often a stream permission.
- **Unconfirmed create.** A create with no answer MUST NOT be retried: titles are not unique (V22), so a retry can create a second definition. The rule fails with `graylog_create_unconfirmed`, which names the title and, on 7.2, the `opentide.<uuid>` tag.

Deploy MUST NOT call `/execute`, MUST NOT list definitions, and MUST NOT write to the rule file.

### B.9 Validation and query

| Check | Graylog |
|-------|---------|
| `opentide validate` (offline) | block constraints, the aggregation condition, and the Graylog dialect |
| `opentide validate query` (offline) | the query, or a `.graylog` file |
| `opentide validate query --live` | `POST /api/search/validate` per tenant, with the block's streams and `window`. `ERROR` is an error; `WARNING` and `INFO` are warnings, with Graylog's positions. |
| `opentide query` | `POST /api/search/messages`, read-only, language `graylog`. On 6.3 and 7.0, a dotted field name in `fields` is split for decorators: the runner asks for such fields only from 7.1. |

Graylog joins the query-validation allowlist ([platforms](../specs/platforms/index.md#query-validation-platforms)). `OFFLINE_QUERY_LANGUAGES["graylog"]` is `("graylog",)`.

### B.10 Case-insensitive matching

Graylog keyword fields are case-sensitive, and Graylog's search syntax has no case-insensitive flag (Q1, Q5). The platform spec documents one pattern, and opentide does not manage it: a tenant pipeline that writes lower-cased copies of the fields detections match on. The originals stay untouched for forensics. Rules then match the copies with lower-case regex and alternation:

```text
rule "lowercase CommandLine"
when
  has_field("CommandLine")
then
  set_field("command_line_lc", lowercase(to_string($message.CommandLine)));
end
```

Q7 tested this pattern. Pipelines are in Graylog Open on every supported version. Without it, a case-insensitive match needs a letter class for every letter (`[Cc][Mm][Dd]`). That works, but it is unreadable, and `graylog_case_sensitive` points authors to the pattern.

---

## Part C: Analysis engine and language server

### C.1 One language

| `LanguageId` | Where it appears | Built on |
|--------------|------------------|----------|
| `graylog` | `configurations.graylog.query` (injected, as for every query string); `.graylog` query files | `opentide-lucene` with `Dialect::Graylog` |

The aggregation `condition` is a block field. `opentide-tide`'s Graylog block checker (like `bitdefender.rs` and `sysdig.rs`) parses it with the [grammar](#aggregation-condition-grammar). It reports `graylog_aggregation` at the exact span. Completion of the 12 function names comes from the same checker. Injection would only buy separate highlighting for a one-line expression, which does not justify a second language.

### C.2 Engine work

- `Dialect::Graylog` at the four dialect sites (`opentide-analysis` ×3, `opentide-tide` ×1), with the differences in [B.7](#b7-graylog-query-dialect).
- `catalogs/graylog/fields.toml`: Graylog's built-in message fields (`message`, `full_message`, `source`, `timestamp`, `streams`, `gl2_*`) and GIM fields with their types. It is generated from graylog2-server's `org/graylog/schema/*Fields.java` constants (names only) by `scripts/sync_graylog_fields.py`, pinned to a Graylog tag.
- Hover and completion: fields, operators, `_exists_`, and the condition functions; stream and notification aliases from the workspace's tenant tables; guidance for Q1–Q6 (lower-cased copies, CIDR as interval regex).
- The Graylog block checker: every [constraint](#b3-constraints) and advisory that does not need a tenant.

### C.3 Tide catalogue

The new `GraylogConfig` model adds `configurations.graylog.*` to the generated Tide catalogue. The engine's bundled catalogue then goes stale, and `scripts/build/check_engine_catalog.py` fails until three steps are done:

1. language-server regenerates the catalogue (`scripts/sync_opentide_schemas.py`);
2. language-server releases;
3. opentide bumps the engine pin.

### C.4 Conformance and test plan

| Layer | Corpus | Oracle | Gate |
|-------|--------|--------|------|
| Graylog dialect | the existing SigmaHQ Lucene corpus, `lucene-queryparser/cases.tsv`, plus hand cases for Q2–Q6 | `POST /api/search/validate` on Graylog 6.3 and 7.2 (Open) | syntax verdicts equal |
| Condition grammar | hand cases for every function, operator, and precedence | the condition tree Graylog accepts (V13) | exact trees |
| Request bodies | fixture rules → expected 6.3 and 7.2 bodies (`fixtures/platforms/graylog/*.api.json`) | review | exact JSON |
| Deployer | create, update, disable, delete, recreate on 404, immutable, unconfirmed create, per version | a fake Graylog (unit); live **Graylog 6.3 and 7.2 Open** in CI (Docker, no licence) | the decision table in [B.8](#b8-deploy) on both versions |

Every live job runs on Graylog Open, with no licence, on the same Docker stacks this RFC was verified on.

---

## Engineering plan

| # | Work package | Repo | Person-days |
|---|--------------|------|-------------|
| S1 | `specs/platforms/graylog-1.0.md`; `platforms/index.md` 1.8 (eleven platforms, Graylog in `--live`); `validation.md` codes; `deployment-state.md` (`graylog`); the `rule-1.x` block table; `SPECS.md`, `llms.txt`, `CHANGELOG.md`; fixtures (`fixtures/platforms/graylog.yaml`, `graylog/*.api.json` for 6.3 and 7.2, invalid twins); fixture checkers (`validate_graylog_block`, `scripts/test_platform_graylog.py`); the three "ten platforms" assertions | specifications | 3–4 |
| L1 | `Dialect::Graylog`, the field catalogue and sync script, injection, hover and completion | language-server | 3–4 |
| L2 | Graylog block checker: constraints, the condition grammar, advisories | language-server | 2 |
| L3 | Conformance: the `search/validate` oracle on 6.3 and 7.2, hand cases | language-server | 1–2 |
| O1 | Models: `GraylogConfig`, schedule, aggregation; tenant setup | opentide | 2 |
| O2 | REST client on `TenantSession`: auth, CSRF header, version probe and table, error mapping | opentide | 2 |
| O3 | Compile: derived fields per version, ATT&CK, tag normalisation, the condition tree; `api_body` goldens for 6.3 and 7.2 | opentide | 2–3 |
| O4 | Deployer on deployment state (`graylog` in `STATE_PLATFORMS` and `OBJECT_ID_PLATFORMS`): pre-save check, decision table | opentide | 2–3 |
| O5 | Live validator (`LiveQueryValidator`) and the `opentide query` runner | opentide | 2 |
| O6 | Wiring (about 38 registration sites), bundled TOML, template, diagnostics pages, docs (usage, CLI, MCP, SDK), MCP default language | opentide | 3 |
| O7 | Tests: model, compile, deployer (fake Graylog), live validator, runner, CLI E2E, MCP; nightly live jobs on 6.3 and 7.2 Open | opentide | 3–4 |

About 25–31 person-days.

Delivery order:

1. S1.
2. L1–L3 with O1–O2: queries are checked offline.
3. O3–O7, then a release: Graylog rules deploy end to end on 6.3, 7.0, 7.1, and 7.2.

## Drawbacks

- **Two create formats.** 6.3 and 7.x disagree on the create body. A wrong guess is a 400, and on 6.3 an unknown field is dropped silently (V2). The version table is a small, tested branch, but it has to follow Graylog's releases.
- **ATT&CK is weaker before 7.2.** 6.3–7.1 have no `tactics_techniques` field. A description line and an event field carry the ids, but Graylog's own coverage views cannot read them.
- **Case-insensitive matching is the tenant's job.** The readable form needs a lower-casing pipeline, which opentide documents but does not deploy.
- **No Sigma.** Teams that author in Sigma convert their rules to Graylog queries themselves until a later RFC adds a conversion path.

## Alternatives

- **Graylog Sigma import** as a second kind. Rejected ([Sigma](#sigma-researched-and-not-adopted)): the API changed incompatibly in 7.2, and a 7.2 import returns no id and has no update path. It is licence-gated, and correlations depend on the version.
- **opentide converts Sigma to Graylog queries.** Rejected for 1.0: it makes opentide responsible for a converter, and for Graylog's field mappings. A later RFC can add it as an authoring source on top of this platform.
- **Deterministic client-assigned ids.** Rejected (V7): Graylog echoes a client id and stores nothing.
- **Find definitions by tag or title.** Rejected: [deployment-state](../specs/deployment-state.md) forbids rediscovery, tags exist only on 7.2, and titles are not unique.
- **Content packs.** Rejected as the deploy path. A change means uninstall and reinstall, which gives every definition a new id.
- **Support only 7.2.** Rejected: 6.3 is in production use and differs only in the create body and four optional fields.

## Unresolved questions

- **The lower bound.** Is 6.3 the right floor? 6.2 and earlier differ again (bare create body, no `share_request`) and were not tested.
- **Vulnerable versions.** Is a warning enough for versions below 6.3.12, 7.0.16, and 7.1.12, or should deploy refuse them?
- **ATT&CK before 7.2.** Is the description line plus the `attack_techniques` event field the right carrier, or should 6.3–7.1 carry nothing?
- **A tenant pipeline as a block prerequisite.** Should a block be able to declare the lower-cased fields it needs, so validate can check the tenant has them (through `--live` `UNKNOWN_FIELD`)?
- **Scheduling defaults.** Is `5m`, with `window` equal to `every`, the right default?

## References

- Graylog: [event definitions](https://go2docs.graylog.org/current/interacting_with_your_log_data/event_definitions.html); [search syntax](https://go2docs.graylog.org/current/making_sense_of_your_log_data/search_syntax_reference.htm); [access tokens](https://go2docs.graylog.org/current/setting_up_graylog/rest_api_access_tokens.htm); [upgrade to 7.2](https://go2docs.graylog.org/current/upgrading_graylog/upgrade_to_graylog_7.2.htm); [Enterprise changelog](https://go2docs.graylog.org/current/changelogs/operations_changelog.html); [GHSA-j769-9gv9-65gr](https://github.com/Graylog2/graylog2-server/security/advisories/GHSA-j769-9gv9-65gr)
- graylog2-server (tags 6.3.0–7.2.2): `org/graylog/events/rest/EventDefinitionsResource.java`, `org/graylog/events/processor/EventDefinitionDto.java`, `org/graylog/events/processor/aggregation/AggregationEventProcessorConfig.java`, `org/graylog/events/conditions/*`, `org/graylog/plugins/views/search/rest/QueryValidationResource.java`, `org/graylog/security/shares/*CreateEntityRequest.java`, `graylog2-web-interface/src/logic/alerts/EventDefinitionPriorityEnum.ts`, `UPGRADING.md`
- opentide: [RFC 0016](0016-bitdefender-gravityzone-platform.md), [RFC 0014](0014-sysdig-falco-platform.md), [RFC 0010](0010-deployment-external-ids.md), [RFC 0007](0007-elastic-security-platform.md); [deployment-state](../specs/deployment-state.md)

## Appendix: reproducing the Graylog tests

Two stacks, each needing about 4 GB of memory:

```yaml
name: gl63            # and a second project with graylog/graylog:7.2.2 on port 9000
services:
  mongodb:
    image: mongo:7.0
  opensearch:
    image: opensearchproject/opensearch:2.19.2
    environment:
      - discovery.type=single-node
      - DISABLE_SECURITY_PLUGIN=true
      - DISABLE_INSTALL_DEMO_CONFIG=true
      - action.auto_create_index=false
      - OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g
  graylog:
    image: graylog/graylog:6.3.5
    depends_on: [mongodb, opensearch]
    entrypoint: /usr/bin/tini -- wait-for-it opensearch:9200 -- /docker-entrypoint.sh
    environment:
      - GRAYLOG_PASSWORD_SECRET=<at least 16 characters>
      - GRAYLOG_ROOT_PASSWORD_SHA2=<sha256 of the admin password>
      - GRAYLOG_HTTP_EXTERNAL_URI=http://127.0.0.1:9001/
      - GRAYLOG_ELASTICSEARCH_HOSTS=http://opensearch:9200
      - GRAYLOG_MONGODB_URI=mongodb://mongodb:27017/graylog
    ports: ["127.0.0.1:9001:9000", "127.0.0.1:12202:12201"]
```

Steps:

1. Create a global GELF TCP input.
2. Send events as null-terminated GELF JSON.
3. Run the same probe against both servers: event-definition create, update, schedule, and delete; `/api/search/validate`; `/api/search/messages`.

Every V-row and Q-row is one such probe.
