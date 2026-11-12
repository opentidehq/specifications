# RFC 0018: Exabeam New-Scale SIEM and the Exabeam Query Language

- **RFC:** 0018
- **Title:** Exabeam New-Scale SIEM and the Exabeam Query Language
- **Author:** opentide maintainers
- **Status:** draft
- **Created:** 2026-11-11
- **Issue:** none yet. A spec-change issue is to be opened before this RFC is accepted.
- **Normative text (draft):** [specs/platforms/exabeam-1.0.md](../specs/platforms/exabeam-1.0.md), [specs/languages/exabeam-1.0.md](../specs/languages/exabeam-1.0.md)
- **Implementation:** opentidehq/opentide (the `exabeam` platform, deployer, `--live`, query runner); opentidehq/language-server (the `exabeam` language: grammar, CIM catalogue, diagnostics, highlighting)

## Summary

Add a twelfth detection platform, `exabeam` (display name **Exabeam New-Scale SIEM**, schema `platform::exabeam::1.0`), and a second language spec, the **Exabeam Query Language** (language id `exabeam`).

A `configurations.exabeam` block is one Exabeam **correlation rule**: one or more sequences, each a filter query and a condition (any match, or a threshold over a window), correlated within a common window when there are several. Deploy goes through the Correlation Rules API (`/correlation-rules/v2/rules`) with full-body `PUT` updates. Exabeam assigns each rule a UUID, kept in [deployment state](../specs/deployment-state.md).

The language spec defines Exabeam's search language once, for correlation-rule sequences (profile `rule`: filters only) and for hunts (profile `search`: filters and the SQL-like advanced operators). It gives the grammar the analysis engine parses, the highlight captures editors show, and stable `exabeam_*` diagnostics. Exabeam publishes neither a grammar nor a parser. The spec is built from Exabeam's Search guide and API reference, and checked against Exabeam's own published rules.

`--live` validation sends each sequence filter to Exabeam Search, the only tenant check the API offers. `opentide query` runs `system: exabeam` hunts through the same endpoint.

The change is additive. It adds `configurations.exabeam`, a deployment-state platform, and a hunt `system`, and changes no existing block.

## Motivation

Exabeam merged with LogRhythm in July 2024 and kept Exabeam's cloud SIEM, now the New-Scale Security Operations Platform, as its product line. Teams on it keep correlation rules in the console's Threat Detection Management app, outside their detection catalogue, with no review and no lifecycle. The platform has a documented Correlation Rules API with create, update, enable, disable, and delete, so detection-as-code is possible. Its search language has no editor support anywhere: no grammar, no linter, no highlighter. Exabeam's own guide says a query that "uses incorrect query syntax" stops the rule in production.

## Research

All sources were fetched on 2026-11-11. developers.exabeam.com serves each reference page as Markdown with its full OpenAPI 3.0.1 definition (append `.md` to the page URL); endpoint and schema facts come from those definitions. Search-language facts come from Exabeam's Search guide on docs.exabeam.com, fetched raw. Real queries come from Exabeam's GitHub content: [ExabeamLabs/new-scale-content-hub](https://github.com/ExabeamLabs/new-scale-content-hub) and [ExabeamLabs/CIMLibrary](https://github.com/ExabeamLabs/CIMLibrary). Third-party clients confirm the transport: the Cortex XSOAR `ExabeamSecurityOperationsPlatform` pack (demisto/content) and the Swimlane "Exabeam AA v2" connector.

### Naming

| Fact | Source |
|------|--------|
| The merged company kept the Exabeam name. Docs now title the product "New-Scale Security Operations Platform". The old `/en/exabeam-soc-platform/…` URLs redirect to `/en/new-scale-soc-platform/…`. | [press release](https://www.exabeam.com/?p=238815); docs.exabeam.com redirect |
| Correlation rules are documented under **Threat Detection Management**. | [Threat Detection Management guide](https://docs.exabeam.com/en/threat-detection-management/all/threat-detection-management-guide/correlation-rules.html) |
| The Search guide calls the language "Exabeam Query Language (EQL)". The API describes a sequence `query` as "EQL Query for the sequence evaluation". | [Advanced search](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search.html); [create rule](https://developers.exabeam.com/exabeam/reference/correlation-create-rule.md) |

### Transport and authentication

| Item | Fact | Source |
|------|------|--------|
| Base URL | `https://api.<region>.exabeam.cloud`, region `us-west`, `us-east`, `ca`, `eu`, `sa`, `sg`, `ch`, `jp`, `au`; `uk` only in the OpenAPI `servers` lists. The console subdomain is not the region label (`use1` → `us-east`, `euw6` → `ch`). | [API base URLs](https://developers.exabeam.com/exabeam/docs/exabeam-api-base-urls.md) |
| Token | `POST /auth/v1/token`, `{client_id, client_secret, grant_type: "client_credentials"}` → `{access_token, token_type, expires_in}`. "Tokens are good for 4 hours - only request 6 tokens per 24 hours." | [get access token](https://developers.exabeam.com/exabeam/reference/get-access-token.md); [API keys](https://developers.exabeam.com/exabeam/docs/api-keys.md) |
| Expired token | XSOAR refreshes on HTTP 401 with "Jwt is expired". | XSOAR `ExabeamSecOpsPlatform.py` |
| Permissions | The key carries a role. "Correlation Rules" at Read Write Delete; "Search, Analyze and Export" for Search. OAuth scopes are empty. | [user permissions](https://docs.exabeam.com/en/new-scale-soc-platform/all/administration-guide/universal-role-based-access/user-roles/user-permissions.html) |
| Rate limits | 100 requests per minute per client source IP; 50 token requests per 5 minutes per IP. No 429 shape is documented. | [API keys](https://developers.exabeam.com/exabeam/docs/api-keys.md) |
| Errors | `{errors: [{code, message, messageParams, fields}], traceId}`; `409` is "Feature is not enabled for subscription". | create-rule definition |

### Correlation Rules API

| Operation | Call | Source slug |
|-----------|------|-------------|
| List | `GET /correlation-rules/v2/rules?nameContains=` (an array, no paging) | `correlation-get-all-rules` |
| Get | `GET /correlation-rules/v2/rules/{ruleId}` | `correlation-get-rule-by-id` |
| Create | `POST /correlation-rules/v2/rules` → `201` with the rule and a `location` header | `correlation-create-rule` |
| Update | `PUT /correlation-rules/v2/rules/{ruleId}`, the same required fields as create (a replacement). No `PATCH`, no version or ETag. | `correlation-update-rule` |
| Enable, disable | `POST /correlation-rules/v2/rules/{ruleId}/enable` or `/disable`; bulk `POST …/setrulesstate` | `correlation-set-rule-state-by-id` |
| Delete | `DELETE /correlation-rules/v2/rules/{ruleId}`; bulk `POST …/delete` | `correlation-delete-rule-by-id` |
| Import, export | `POST …/import` (multipart, ≤ 50 rules, ≤ 4 MB; answers `CREATED`/`NOT_CREATED` with no id); `POST …/export` (≤ 50) | `correlation-import-rules`, `correlation-export-rules` |

`ruleId` is a UUID. The request body (`RuleAddRequest`) is `name`, `description`, `severity` (`none`, `low`, `medium`, `high`, `critical`), `enabled`, `testMode`, `sequencesConfig` (required: `sequences[]` of `{name?, query, condition}`, `commonProperties {groupBy ≤ 3, time, unit}`, `outcomes`), `suppressConfig`, `delayConfig` (`delayTimeInMinutes` 7–180), and `scheduleConfig` (`recurrences[]` discriminated by `recurrenceType`: `DAILY`, `WEEKLY` with `daysOfWeek`, `MONTHLY` with `daysInMonth` and `lastDayOfMonth`, `CUSTOM` with `dayFrom` and `dayTo`; `startTime`/`endTime` `HH:MMZ`).

A sequence `condition` is discriminated by `triggerOnAnyMatch`. `true` takes `groupByOption` and `groupBy` (≤ 3). `false` takes `functionType` (`count`, `unique_count`, `value`, `max`, `min`, `sum`, `average`), `subject` (`event`, `field`), `field` (required with `subject: field`), `operator` (`more_than`, `less_than`, `in`, `not_in`, `between`, `changed`), `value` (a **string**, lists comma-joined: `"0.0.0.0,1.1.1.1"`), `time` ≥ 1, and `unit` (`minutes`, `hours`, `days`).

`outcomes` is `sendAlertTriage` + `alertTriage {name}`, or `createCase` + `case {description}` ("If createCase is enabled, sendAlertTriage should be disabled and vice versa"), and optionally `sendEmail` + `email {recipients, subject, description, attachCsv}`.

The create/update schema has **no MITRE, use case, tag, webhook, or sequence-ordering field**. MITRE (`[{tacticKey, tactic, techniqueKey, technique}]`), `useCase`, and `sequencesExecution` (`ANY_ORDER`, `CREATION_ORDER`) exist only in the import/export `RuleDefinition`. Tags and webhooks are UI only.

From the Threat Detection Management guide: a rule auto-stops when its sequences match more than 500 times or it triggers more than 50 times in five minutes, or "the sequence uses incorrect query syntax or references an empty context table". A rule that uses a context table lookup requires "Trigger on first match". Each trigger writes an event with activity type `rule-trigger` (`rule-trigger-test` in test mode). Sources: [manual rule creator](https://docs.exabeam.com/en/threat-detection-management/all/threat-detection-management-guide/correlation-rules/create-correlation-rules/create-a-correlation-rule-from-scratch-using-the-manual-rule-creator.html), [test a rule](https://docs.exabeam.com/en/threat-detection-management/all/threat-detection-management-guide/correlation-rules/manage-correlation-rules/test-a-correlation-rule.html).

### Validation and preview

No endpoint validates a query or previews a rule. The full reference has no `validate`, `test`, `preview`, or `dry-run` operation. `testMode: true` creates the rule and suppresses its outcomes. "Test Last 15 mins" is a console button that runs the sequence query in Search. A malformed Search `filter` returns `400` (`ApiErrors`).

### Search API

`POST /search/v2/events`: `{filter, fields, startTime, endTime, limit (default 3000), groupBy, orderBy, distinct}` → `{timeStartedMillis, timeCompletedMillis, rows, totalRows}`. It is synchronous, with no job id, paging, or cancel. The time range has a licence-specific limit. Verbatim examples include `"filter": "SELECT app, COUNT(*) AS app_count WHERE product:\"Audit Log\" GROUP-BY app ORDER-BY app_count DESC"` and `"filter": "src_ip IN \"Context_Table\""`. Source: [search](https://developers.exabeam.com/exabeam/reference/search-2.md).

### The query language

Exabeam's Search guide is the only reference. Key pages: [query syntax](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/query-syntax.html) (QS), [query by field and value](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/query-by-field-and-value.html) (QFV), [regex](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/query-using-regex.html), [wildcards](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/query-using-wildcards.html), [free text](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/free-text-search.html), [context tables](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/context-tables-in-search.html), [advanced operators](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/query-using-advanced-query-language-operators.html) (AQL), [aggregations](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/query-using-aggregation-functions.html), [dynamic field extraction](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/dynamic-field-extraction.html) (DFE), the [Data Lake migration table](https://docs.exabeam.com/en/data-lake/all/data-lake-migration-guide/migration-resources/adjust-query-syntax.html) (MIG), and [known issues](https://docs.exabeam.com/en/new-scale-soc-platform/all/release-notes/known-issues.html) (KI).

| Fact | Source |
|------|--------|
| "Search semantics applies a limited subset of Lucene." | QS |
| `:` and `=` are interchangeable; `==` is an exact, case-sensitive full match; backticks inside quotes are an exact case-sensitive keyword match | QFV |
| `AND`, `OR`, `NOT`, `TO` "can be upper- or lower-case". Parentheses around a single expression are an error: `(exa_category:"Web") AND network:"HTTP"`. | QS |
| `a NOT b` "does not result in an error, despite this syntax being invalid and not officially supported … always use the explicit operators: `AND NOT` or `OR NOT`" | KI (ENG-75846) |
| Lists `user:("joe","jane")`; ranges `[a TO b]` inclusive, `{a TO b}` exclusive, `*` open; IP ranges and CIDR `[10.0.0.0/8]`, IPv4 only | QFV, QS |
| `field:null`, `NOT field:null` (no `_exists_`) | QFV, MIG |
| `RGX`/`RGXi` (RE2, "back-references are unsupported") and `WLD`/`WLDi`, one quoted argument each; `*`/`?` in quoted values; "You cannot use wildcards inside of phrases"; `*` alone is not allowed | regex, wildcards, QS |
| Context tables: `field IN "table"` or `"table"."column"`; at most two per query; "The OR operator is not allowed with a context table" | context tables |
| Unquoted free text with special characters is not supported; a query cannot start with `/` | free text |
| No comment syntax, no `!=`, and no `contains()`, `startswith()`, `cidr()`, `exists()` appear in any Search page | QS, QFV (absence) |
| Advanced form: `[SELECT] [WHERE] [GROUP-BY] [ORDER-BY] [LIMIT]`, `AS`, pipes (≤ 5), `FOREACH f [ … @f … ]`, `COUNT/MIN/MAX/SUM/AVG`, `RGX_EXTRACT` (≤ 3); keywords all lower or all upper case; a reserved-word list for aliases | AQL, DFE |
| "The Convert to Rule functionality is disabled when using dynamic field extraction." Every published correlation rule uses a filter only. | DFE; new-scale-content-hub |
| A correlation sequence uses "the same syntax when typing a search" | [sequences](https://docs.exabeam.com/en/threat-detection-management/all/threat-detection-management-guide/correlation-rules/correlation-rule-sequences.html) |

**Field catalogue.** `ExabeamLabs/CIMLibrary` holds `cim.json` (84 subjects, 880 activity-type × outcome entries, 545 vendor/product extensions) and `Fields_Descriptions.md` (1,130 typed fields: string 935, array 42, integer 29, number 28, boolean 26, datetime 21, hex 19, ip 18, email 10, json 2). Its header says the fields "can be used to build events and to create searches and correlation rules". `event_code` is a string, which is why the guide writes `event_code:"4624"`.

**Real content.** `new-scale-content-hub/Correlation-Rules/` holds import-ready rules, including Exabeam's conversion of most of the Sigma library (`exabeam_new_scale_correlation_rule_json-2025/`). Examples the language spec's reference checker parses without a finding:

```text
activity_type: "endpoint-stop" AND (result_reason: ("unplanned","No title for this reason could be found") OR NOT result_reason: "Planned")  AND dest_host IN "Domain Controllers"
event_code: "4688" AND process_name: "mshta.exe" AND process_command_line: RGXi("(https?|ftp:?):\/\/[^\/]*\/\S+\.hta")
dest_port: (102, 502, 1911, 2222, 2404, 4840, 4911, 20000, 44818, 47808) AND NOT dest_ip: NULL AND NOT src_ip: [10.0.0.0/8]
subject: "endpoint" | FOREACH dest_host [ select src_host WHERE src_host: @dest_host AND subject: "network" AND activity_type: "network-connection" ] | SELECT src_host, count(src_host) AS src_host_count GROUP-BY src_host
```

**Converters.** No pySigma backend for Exabeam exists. SOC Prime Uncoder does not translate to it.

### Contradictions, and the reading the specs chose

| Topic | Contradiction | Chosen |
|-------|---------------|--------|
| Advanced operators in a rule | Undocumented; "Convert to Rule" is disabled for one of them; no published rule uses them | Error under `rule` (`exabeam_advanced_in_rule`) |
| Precedence of `AND`/`OR` | Undocumented | `AND` binds tighter; mixing them unparenthesised is the warning `exabeam_mixed_boolean` |
| A one-value list | QFV: "also works for a single value"; MIG: "will result in an error" | Warning `exabeam_single_value_list` |
| Value case | QS/FTS: case-insensitive; one QFV table: "not case-insensitive" | Not checked; documented as case-insensitive |
| Regex form | `RGX("…")` throughout Search; MIG and QFV also show `"/…/"` | `RGX` is the form; `"/…/"` is the warning `exabeam_legacy_regex` |
| Unquoted values | MIG: strings "always enclosed"; real rules use unquoted numbers, IPs, `null` | Numbers, booleans, `null`, IPs unquoted; any other bare value is the warning `exabeam_unquoted_value` |
| Delay maximum | Docs: 360 minutes; API: `maximum: 180` | 180 (the API is what deploy calls) |
| Common group-by | UI: "up to 10 fields"; API: `maxItems: 3` | 3 |
| Time units | API: `minutes`/`hours`; exported files: `m`/`h` | The API spelling |
| `daysOfWeek` | Schema `daysOfWeek`; the schema's own example `daysOfWeeks` | The schema |

## Detailed design

The normative text is in the two draft specs. This section gives the reasons.

### 1. Two specs, one language

The language is used in two places with different rules: a correlation sequence and a hunt. It is defined once ([exabeam-1.0 language](../specs/languages/exabeam-1.0.md)) with two profiles, as YARA is defined once for two platforms ([RFC 0015](0015-yara-language.md)). The language id is `exabeam`, never `eql`: the language server's `eql` is Elastic EQL, and two languages under one id would be checked by the wrong engine.

### 2. The block mirrors the API, in YAML terms

- **Sequences are a list, conditions are optional.** A sequence without `threshold` is any-match, the common case, so it needs no `trigger: any`. A threshold is `function`/`field`/`operator`/`value`/`within`. `subject` is derived (`field` when `field` is set), since a separate key could only disagree with `field`.
- **Values are YAML values, sent as strings.** `value: 3`, `value: [a, b]`, `value: [2, 10]` for `between`, nothing for `changed`. The compiler writes the API's string. The block can therefore type-check a value against its operator (`exabeam_threshold_value`), which the API's string cannot.
- **Durations are one number and one unit** (`30m`, `4h`, `1d`, `2w`), because Exabeam takes `time` and `unit`. Compound durations would need a lossy conversion, so they are invalid.
- **`correlation` is required with two or more sequences and forbidden with one**, the API's own rule for `commonProperties`, so a mistake is caught before deploy.
- **`outcome: alert | case | none`** makes the API's "one of `createCase` and `sendAlertTriage`" a single key. `email` is independent.
- **Name, description, and severity are derived**, as on Bitdefender. Severity maps one to one (`Informational` → `none`).
- **ATT&CK goes in the description.** The create/update schema has no MITRE field. Import has one but returns no id (below), so the technique ids are appended to the description for analysts, with an `opentide: <uuid>` line. Deploy never reads them back.

### 3. Deploy: state-backed, full replacement

Exabeam assigns a UUID on create, so the platform is state-backed, with ids in `.opentide/states/deployment/<uuid>.json` under a new `uuidTenants` shape. `PUT` replaces the rule, so every update sends the whole body and the rule matches the block after every deploy, whatever the console changed. `DISABLEMENT` is the same `PUT` with `enabled: false`, not a second call. A create with no answer is never retried: Exabeam may have created the rule, deploy may not list rules to find it, and a retry could create a second live rule.

### 4. Validation: offline first, `--live` for the filter

The engine checks every query offline: the grammar, the diagnostics, the CIM catalogue as warnings. `--live` sends each sequence filter to Search over the last 15 minutes, as the console's "Test Last 15 mins" does: a `400` is a real syntax verdict from the tenant. It is reported as a filter check only, because nothing previews the condition. Exabeam joins the `--live` allowlist on those terms. `testMode` is not used for validation because it creates a rule.

### 5. Editors: no new capture

Highlighting maps every token class onto existing HighlightSpec captures (`keyword`, `operator`, `operator.pipe`, `function.builtin`, `property`, `type` for context tables, `variable` for `@field` and aliases, `string`, `number`, `boolean`, `constant` for `null`, IPs, CIDRs, and datetimes, punctuation, `error`). Adding a capture would be a HighlightSpec minor with no visible gain. Tide YAML injects the language at `configurations.exabeam.sequences[].query` (`rule`) and at `searches[].query` with `system: exabeam` (`search`).

### 6. Conformance tooling in this repository

`scripts/exabeam_language.py` is a reference checker, like `object_fixtures.py`. It proves that the grammar is coherent, that the spec's examples and Exabeam's published rules parse, that every catalogue-free code has a fixture that triggers it, and that the highlight goldens follow the capture table. `scripts/test_platform_exabeam.py` derives every request golden from its rule fixture by the spec's rules. Neither is opentide's engine.

## Engineering plan

| # | Work package | Repo | Person-days |
|---|--------------|------|-------------|
| L1 | `LanguageId::Exabeam` (`exabeam`, `.exabeam`), codes, tree-sitter grammar `tree-sitter-opentide-exabeam` (filter and advanced), corpus gate | language-server | 4–5 |
| L2 | `catalogs/exabeam/` from CIMLibrary (`cim.json`, `Fields_Descriptions.md`) with a sync script pinned by commit; hover and completion for fields, `activity_type`, `subject`, `outcome` | language-server | 2–3 |
| L3 | `opentide-exabeam` checks (every code in the language spec), RE2 via the `regex` crate's syntax parser, profiles, YAML injection | language-server | 4–5 |
| L4 | `highlights/queries/exabeam/highlights.scm` on existing captures; external corpus from new-scale-content-hub (licence permitting) with `.broken.` twins; no oracle (closed source), recorded in `scripts/oracles/README.md` | language-server | 2–3 |
| O1 | `exabeam` models (block, sequence, threshold, correlation, suppression, email, schedule) and tenant setup | opentide | 2 |
| O2 | Client: token cache and refresh, 100/min limiter, error mapping | opentide | 2 |
| O3 | Compiler and goldens against `fixtures/platforms/exabeam/` | opentide | 2 |
| O4 | Deployer on deployment state (`exabeam` in `STATE_PLATFORMS`, UUID ids), recreate, unconfirmed create | opentide | 2–3 |
| O5 | `--live` filter check, `opentide query` runner, `OFFLINE_QUERY_LANGUAGES["exabeam"]`, MCP, docs, templates, wiring | opentide | 3–4 |
| O6 | Tests: model, compile, deployer against a fake API, live, query, CLI E2E | opentide | 4 |
| E1 | Engine pin bump once L1–L4 ship; catalog gate | opentide | <1 |

About 28–34 person-days. A tenant is needed before the specs become normative ([Unresolved questions](#unresolved-questions)).

## Drawbacks

- **No MITRE through the API.** The mapping lives in the description, not in Exabeam's MITRE field, so Exabeam's MITRE views will not show opentide rules.
- **No ordered sequences.** The API cannot set `sequencesExecution`, so multi-sequence rules are evaluated in Exabeam's default order.
- **No grammar from the vendor.** The language spec is reverse-engineered from guides that contradict each other in places. Some verdicts are deliberately warnings.
- **Rate limit by source IP.** 100 requests a minute is shared by everything a CI runner's IP does against Exabeam.

## Alternatives

- **Import/export for deploy.** Rejected. Import returns no id (`CREATED`/`NOT_CREATED` only), cannot update, and refuses a rule whose name exists. It would carry MITRE, use case, and ordering, but only by finding the rule by name afterwards, which [deployment state](../specs/deployment-state.md) forbids.
- **Identity by name or by the `opentide:` marker.** Rejected: rediscovery by listing is forbidden, and `nameContains` is a substring match.
- **One language spec per use** (a rule filter spec and a search spec). Rejected: one grammar, two profiles, as YARA.
- **Accepting the advanced operators in rules.** Rejected for 1.0: undocumented, and no published rule uses them. A tenant test can relax it (a new profile option, additive).
- **Analytics rules (UEBA) as a second kind.** Deferred. New-Scale Analytics rules use a different, function-call expression language (`containsAny(toLower(operation), '…') && …`) with a `Draft`/`Training`/`Active` lifecycle and import-only writes (`/detection-management/v1/analytics-rules/import`). They would be a second language spec and a kind with no stable id.
- **LogRhythm SIEM AI Engine rules.** Out of scope: a different, self-hosted product with its own API.
- **Validate through `testMode`.** Rejected: it creates and runs a rule.

## Unresolved questions

To settle on a tenant before the specs become normative:

1. Whether the advanced operators are accepted in a sequence `query`.
2. Whether rule names must be unique, and what a duplicate returns.
3. Whether create/update syntax-checks `query` (a `400`), or a bad query is only found when the rule stops.
4. The `value` string for `between` (assumed `low,high`) and for `changed` (assumed `""`).
5. Whether a `PUT` without `scheduleConfig` clears a schedule.
6. Whether `PUT` accepts `mitre`, `useCase`, or `sequencesExecution` (undocumented extra properties), which would remove the description workaround and the ordering drawback.
7. The default sequence order without `sequencesExecution`.
8. Whether `triggerOnAnyMatch: false` is required on a threshold condition (the schema says so; the examples omit it). The compiler always sends it.
9. The response to a rate-limit breach (status, `Retry-After`).
10. Whether `"/…/"` is still a regex in Search, and whether a one-value list is accepted.
11. Whether a Search request a client abandons keeps running on the tenant.

## References

- Exabeam API reference (OpenAPI in each `.md` page): [create rule](https://developers.exabeam.com/exabeam/reference/correlation-create-rule.md), [update rule](https://developers.exabeam.com/exabeam/reference/correlation-update-rule.md), [export](https://developers.exabeam.com/exabeam/reference/correlation-export-rules.md), [search](https://developers.exabeam.com/exabeam/reference/search-2.md), [token](https://developers.exabeam.com/exabeam/reference/get-access-token.md), [base URLs](https://developers.exabeam.com/exabeam/docs/exabeam-api-base-urls.md), [API keys](https://developers.exabeam.com/exabeam/docs/api-keys.md)
- Exabeam Search guide and Threat Detection Management guide (pages linked in [Research](#research))
- [ExabeamLabs/CIMLibrary](https://github.com/ExabeamLabs/CIMLibrary), [ExabeamLabs/new-scale-content-hub](https://github.com/ExabeamLabs/new-scale-content-hub)
- [RFC 0010](0010-deployment-external-ids.md) (deployment external ids), [RFC 0015](0015-yara-language.md) (a language spec shared by platforms), [RFC 0016](0016-bitdefender-gravityzone-platform.md) (the state-backed platform pattern)
