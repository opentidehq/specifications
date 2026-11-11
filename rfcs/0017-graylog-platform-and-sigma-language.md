# RFC 0017: Graylog detection platform, and Sigma as a language

- **RFC:** 0017
- **Title:** Graylog detection platform, and Sigma as a language
- **Author:** opentide maintainers
- **Status:** draft
- **Created:** 2026-11-11
- **Issue:** to be opened in opentidehq/specifications (spec-change)
- **Related:** [RFC 0015](0015-yara-language.md) (the language-spec pattern this follows); [RFC 0016](0016-bitdefender-gravityzone-platform.md) and [RFC 0014](0014-sysdig-falco-platform.md) (the state-backed platform pattern); [RFC 0010](0010-deployment-external-ids.md) (deployment external ids); [RFC 0007](0007-elastic-security-platform.md) (the ATT&CK and duration conventions reused here)
- **Implementation:** not started. This RFC is research and design only. The normative files it proposes ([Part A](#part-a-sigma-language-language-sigma-10) and [Part B](#part-b-graylog-platform-platformgraylog10)) land in a later specifications PR.

## Summary

Add an eleventh detection platform, `graylog` (display name **Graylog**, schema `platform::graylog::1.0`), and make **Sigma** a language spec that any platform can embed, as [RFC 0015](0015-yara-language.md) did for YARA.

A `graylog` block is one Graylog **event definition**. It holds exactly one of two kinds of detection logic:

- `query`: a native Graylog search query, written in Graylog's search syntax;
- `sigma`: a Sigma detection (`logsource` plus `detection`), as defined by the new [Sigma language](#part-a-sigma-language-language-sigma-10).

Both kinds deploy as a Graylog **Filter & Aggregation** event definition (`aggregation-v1`). That type is in every Graylog edition, Open included. opentide compiles a Sigma detection to a Graylog query itself, in the analysis engine. It does not use Graylog Security's Sigma import. The root of the block carries what Graylog adds on top of the query: streams, schedule, an optional aggregation, event fields, notifications, and priority.

Deploy uses the Graylog REST API: create, update, schedule, unschedule, and delete on `/api/events/definitions`. Graylog assigns each definition a 24-hex ObjectId. The id lives in [deployment state](../specs/deployment-state.md), as for Bitdefender. Graylog has a real query check, `POST /api/search/validate`, so Graylog joins the `--live` allowlist. The engine also checks offline: a Graylog dialect of its Lucene parser, a Sigma checker, and the Sigma-to-Graylog compiler.

Every Graylog behaviour this design relies on was tested on a live **Graylog 7.2.2** (Enterprise build without a licence, so Graylog Open features plus the licence gates), on 2026-11-11. See [Verified on Graylog 7.2.2](#verified-on-graylog-722).

The change is additive. It adds `configurations.graylog`, a `graylog` deployment-state platform, a language spec, and diagnostics. It changes no existing block.

## Motivation

Graylog is a widely deployed log management platform and SIEM. Graylog Open is free, and Graylog Security is its paid SIEM edition. opentide cannot reach it today. Graylog users keep event definitions in the web interface, with no review, no objectives, and no lifecycle.

Sigma is the vendor-neutral detection format most detection engineers already write. opentide models it only as HarfangLab's decomposed `sigma` block. That block is never parsed, never checked ("Sigma is not checked", [harfanglab-1.0](../specs/platforms/harfanglab-1.0.md)), and cannot express keyword searches, lists of maps, or `1 of` conditions. SigmaHQ publishes 3,779 maintained rules (`rules/`, `rules-emerging-threats/`, `rules-threat-hunting/`, DRL 1.1). Teams want to adopt them with the review and lifecycle opentide gives every other rule.

The two needs meet on Graylog. Graylog Security imports Sigma, but only with a Security licence, and with gaps that the research below found and tested. A Sigma language in opentide, compiled to Graylog by opentide, gives Sigma to every Graylog edition. It also gives Sigma a checker that HarfangLab gains as well.

## Research

Sources are labelled: **[live]** tested on Graylog 7.2.2, 2026-11-11; **[src]** read in `Graylog2/graylog2-server` (tag `7.2.2`, and `master` at `c4f3025`); **[doc]** Graylog documentation, upgrade notes, or changelog; **[jar]** a class or string constant in the 7.2.2 `graylog-plugin-enterprise` jar (names only, no decompiled logic); **[spec]** the Sigma specification v2.1.0 (`SigmaHQ/sigma-specification` at `ba9251a`).

### Verified on Graylog 7.2.2

The test stack was `graylog/graylog-enterprise:7.2.2`, `opensearchproject/opensearch:2.19.2`, and `mongo:7.0` in Docker, with no licence installed. Events came in through a GELF TCP input. The OpenAPI document (`GET /api/openapi.json`, 1,018 paths) was read from the running server.

| # | Finding | Consequence for the design |
|---|---------|----------------------------|
| V1 | `POST /api/events/definitions` takes `{"entity": <dto>, "share_request": …}`. A bare DTO is refused: `entity cannot be null` (400). `PUT` takes the bare DTO. | The client wraps creates only. 7.0 is the minimum version. |
| V2 | The create response shows `state: DISABLED`, but a later `GET` shows `ENABLED` when `?schedule=true`. | Deploy never reads `state` from a create response. |
| V3 | `PUT` without `?schedule=false` **re-enables** a disabled definition. `PUT ?schedule=false`, `PUT /{id}/unschedule`, and `PUT /{id}/schedule` each set the state. | Every `PUT` carries an explicit `?schedule=`. |
| V4 | `GET` or `PUT` on a missing id returns 404. **`DELETE` on a missing id returns 204.** `DELETE` on an existing id returns 204, or 200 with the body. | A delete is idempotent. Update-on-404 recreates. |
| V5 | The query is **not parsed at save**. A create with `Image:(foo`, `Image:*cmd.exe` (leading wildcard), an unknown field, or an empty query returns 200. The definition then fails or matches nothing at run time. | Deploy MUST check the query before it saves. |
| V6 | `POST /api/search/validate` returns `status` (`OK`, `INFO`, `WARNING`, `ERROR`) and `explanations` with `error_type`, a message, and line/column positions. It reports `QUERY_PARSING_ERROR` (ERROR) for syntax errors and for a leading wildcard, `UNKNOWN_FIELD`, `INVALID_OPERATOR` for lower-case `and`/`not`, and `INVALID_VALUE_TYPE` (`event_code:>=abc`, "Type of event_code is long"), all three WARNING. It needs no licence. | This is a real tenant check: Graylog joins `--live`. |
| V7 | Field names are case-sensitive (`image:` finds nothing). Values of ordinary string fields are case-sensitive keywords. `message` and `source` match case-insensitively. | Sigma's case-insensitive matching needs explicit compilation. |
| V8 | `Image:*cmd.exe`, `CommandLine:*-enc*`, and `CommandLine:*urlcache*` fail: "'*' or '?' not allowed as first character" (`allow_leading_wildcard_searches` is false by default). `CommandLine:certutil*urlcache*` works. | `contains` and `endswith` cannot compile to wildcards. |
| V9 | Regex works on keyword fields and is **anchored**: `Image:/.*\\cmd\.exe/` matches, and `Image:/C:.Windows.System32.cmd\.exe/` matches the whole value. Per-letter classes give case-insensitive matching: `Image:/.*\\[Cc][Mm][Dd]\.[Ee][Xx][Ee]/` matched `cmd.exe` and `CMD.EXE`. | Sigma string matching compiles to anchored, case-folded regex. |
| V10 | In both terms and regex, `\\` in the query text is one literal backslash. `\\\\` matches nothing. | The compiler's escaping is fixed. A wrong count is silent (V5). |
| V11 | Lucene regex operators are on: unescaped `#`, `&`, `<…>`, and `~` change the meaning. `/.*f~g.*/` matched 2 documents, the escaped form 1. `/.*a#b.*/` matched 0, the escaped form 1. `/search/validate` returns OK for all but `<…>`. | The compiler escapes them. The engine warns on them in native queries. |
| V12 | `(?i)` matches nothing. `\b` and lookahead `(?=…)` **silently match nothing**. `\d`, `\w`, `\s`, `{n,m}`, and lazy `*?` work. `.` matches a newline. | Sigma `re` is translated. Unsupported PCRE constructs are compile errors, never silent. |
| V13 | Numeric interval syntax works in regex: `DestinationIp:/172\.<16-31>\.<0-255>\.<0-255>/` matches `172.20.5.9`, and `<32-63>` does not. A bare CIDR (`source_ip:10.0.0.0/8`) is a parse error. A quoted CIDR matches nothing on a dynamically mapped (keyword) field. | Sigma `cidr` compiles exactly to interval regex for IPv4. |
| V14 | An empty string field (`OriginalFileName: ""`) is not stored by the GELF input: `_exists_` finds 0 documents, and `field:""` finds 0. | Sigma `''` cannot match: it is a compile error. |
| V15 | `_exists_:f`, `NOT _exists_:f`, `f:4625`, `f:>=4625`, `f:[100 TO *]`, and unqualified phrases (`"sekurlsa::logonpasswords"`, which searches every field) all work. | Direct mappings for `exists`, `null`, numeric modifiers, and keywords. |
| V16 | Event-definition `tags` refuse `opentide:<uuid>` ("may only contain lowercase letters, digits, hyphens, underscores, and dots"). Upper case is accepted and lower-cased. | The audit tag is `opentide.<uuid>`. |
| V17 | `tactics_techniques` refuses `FOO` ("Expected format: TA0000, T0000, or T0000.000") and accepts and upper-cases `t1059`. A fired alert carries the definition's `tactics_techniques`. | ATT&CK goes on the definition and reaches every alert. |
| V18 | `priority` is not range-checked (0 and 5 are stored). | opentide maps severity itself and sends 0–4 only. |
| V19 | Titles are not unique: two definitions with one title are both created. An empty title is refused. | No name-conflict path. A workspace advisory warns on duplicates. |
| V20 | `execute_every_ms` and `search_within_ms` must be greater than 0, with no minimum (1 s is stored). A 5-field cron is refused ("expect one of [6, 7]"). `key_spec` must name `field_spec` keys. Unknown JSON properties are refused (400, "Unable to map property"). | Static constraints mirror these. |
| V21 | `_scope` is taken from the create body. `ILLUMINATE` and `GRAYLOG_IMMUTABLE_SCOPE` definitions refuse `PUT` ("Immutable entity cannot be modified", HTTP 500). `GRAYLOG_IMMUTABLE_SCOPE` and `GRAYLOG_NONDELETEABLE_SCOPE` refuse `DELETE`. A client can create a definition it can never edit or delete again. | Deploy always sends `_scope: DEFAULT`. |
| V22 | **A client-supplied `id` on create is honoured** (`0123456789abcdef01234567` was stored). A second create with an id that exists returns 200, after which the definition is **gone (404)** and its scheduler trigger is in a permanent ERROR state. | Client-chosen ids are unsafe. Graylog is state-backed with server-assigned ids. |
| V23 | A filter definition fired one alert per matching message, with the definition's priority, `tactics_techniques`, and templated event fields. An aggregation definition (`group_by: [source_ip]`, `count() >= 5`) fired one alert per source, with the key. Overlapping windows (`search_within` > `execute_every`) and the first run after an update repeated alerts for the same messages. | The default window equals the interval. Overlap is a warning. |
| V24 | Sigma import (`/plugins/org.graylog.plugins.securityapp.sigma/sigma/import/validate`, `…/import/bulk/upload`) returns **402 "A valid Security license was not found."** | Graylog-side Sigma is Security-only. |
| V25 | `GET /api/events/entity_types` lists `aggregation-v1`, `correlation-v1`, `sigma-v1`, `sigma-correlation-v1`, `anomaly-v1`, and others, and the 12 aggregation functions `avg card count max min stddev sum sumofsquares variance percentage percentile latest`. | The aggregation grammar uses exactly these functions. |
| V26 | `POST /api/search/messages` (the scripting API) returns `schema` and `datarows` for a query, time range, and field list. A `POST` without `X-Requested-By` is refused (400, "CSRF protection header is missing"). | The `opentide query` runner, and a required header. |
| V27 | A `sigma-v1` config needs `parsed_rule`, Graylog's internal Sigma AST (`SigmaDetectionRule`: `logSource`, `detection.condition` as a list, `detection.searches`). Hand-written configs fail with Java deserialisation errors. | Writing `sigma-v1` directly is not a public contract. |
| V28 | The compiled query in [B.8](#b8-deploy), sent as written there, matched exactly the five Office-spawned PowerShell events with `-enc`, `-ENC`, `-Enc`, `/ENC`, and an en-dash `–enc`, and not `-NoProfile`. `/search/validate` returned OK. The same query with the `/` in `[\-/–—―]` unescaped is a parse error ("expected ']'"). | The `graylog` profile's output is executable as specified. |

### Event definitions

The resource is `org/graylog/events/rest/EventDefinitionsResource.java` [src]. It is annotated `@PublicCloudAPI`, so Graylog Cloud documents it too.

| Method and path | Use in opentide |
|-----------------|-----------------|
| `POST /api/events/definitions?schedule=<bool>` | create (V1, V2) |
| `PUT /api/events/definitions/{id}?schedule=<bool>` | update, enable, disable (V3) |
| `DELETE /api/events/definitions/{id}` | delete (V4) |
| `GET /api/events/definitions/{id}` | not on the deploy path; `opentide deploy plan` may show drift |
| `POST /api/search/validate` | the pre-save check and `validate query --live` (V5, V6) |
| `POST /api/search/messages` | `opentide query` (V26) |
| `GET /api/system` | version and lifecycle, once per tenant per run |
| `POST /api/events/definitions/{id}/execute` | **not used**: it creates real events and notifications [src] |
| `GET /api/events/definitions/paginated` | **not used on deploy**: no rediscovery by listing ([deployment-state](../specs/deployment-state.md)) |

`EventDefinitionDto` fields (7.2) [src][live]: `title` (non-empty), `description` (non-null), `priority` (int), `alert` (bool), `config`, `field_spec`, `key_spec`, `notification_settings` (`grace_period_ms`, `backlog_size`), and `notifications` (`[{notification_id}]`). Optional: `remediation_steps` (6.0+), `event_procedure` (6.2+, a Security feature), `event_summary_template` (7.1+), `tags` and `tactics_techniques` (7.2+, at most 64 each). Read-only or server-set: `id`, `_scope`, `_entity_source`, `state`, `updated_at`, `matched_at`, `scheduler`, and `storage` (forced to the "All events" stream).

`aggregation-v1` config [src][live]: `query`, `query_parameters`, `filters`, `streams` (empty means every stream the user may read), `stream_categories` (6.1+), `group_by`, `series` (`[{id, type, field?}]`), `conditions.expression` (a tree of `expr` nodes; a `number-ref` names a series `id`), `search_within_ms`, `execute_every_ms`, `use_cron_scheduling`, `cron_expression`, `cron_timezone` (6.1+), and `event_limit`. A filter-only definition needs `event_limit` from 1 to `event_definition_max_event_limit` (default 1,000).

Priority meanings come from the web interface's `EventDefinitionPriorityEnum` [src]. Up to 6.1: 1 low, 2 normal, 3 high. From 6.2: adds 4 critical. From 7.1: adds 0 info. Graylog 7.2 maps Sigma levels the same way: informational 0 … critical 4 [doc, UPGRADING-7.2.0].

Licensing [doc]: Open has filter and aggregation definitions and notifications. Enterprise adds correlation (`correlation-v1`), search filters, and parameters. Security adds Sigma, anomaly detection, event procedures, and the MITRE coverage view. The free Enterprise ("SMB") licence was retired on 31 December 2025.

### Graylog search syntax

The query goes unchanged to OpenSearch or Elasticsearch `query_string`, with only `allow_leading_wildcard` set from `allow_leading_wildcard_searches` [src: `OpenSearchBackend.translateQueryString`]. The default operator is OR, and the default field is all fields. `AND`, `OR`, and `NOT` must be upper case (V6). `message` and `full_message` are analysed text, `source` is a lower-cased keyword, and every other dynamic string field is an exact, case-sensitive keyword [src: `IndexMapping`; V7]. Illuminate's index templates type some GIM fields differently (`loweronly` normaliser, `ip`) [doc].

The server's own syntax check is Lucene's classic `QueryParser`. Unknown-field and type checks need the tenant's streams and data (V6) [src].

### Graylog and Sigma

- **Edition.** Sigma needs a Graylog Security licence [doc; V24].
- **7.2 redesign.** "Sigma rules are now folded into event definitions, and the first-order Sigma rule entity no longer exists" [doc: upgrade to 7.2]. Sigma comes in only by file upload or Git import. "Manual modification of Sigma rule source YAML is no longer supported." The `/sigma/rules/*` endpoints were deleted. Correlation rules "can no longer be directly imported". The migration class is `V20260513120000_MergeSigmaRulesIntoEventDefinitions` [jar].
- **Import result.** `SigmaImportResult` is `{status: created|skipped|failed, event_definition_name, source_name, error}` (OpenAPI). It returns a name, not the created definition's id.
- **Converter.** Graylog converts with its own Java code (`SigmaQueryBuilder`, `SigmaDetectionRuleParser`) [jar]. Its constants name `contains`, `startswith`, `endswith`, `re`, and `all`. `base64`, `base64_offset`, `utf16`, `utf16le`, `utf16be`, `wide`, and `windash` appear as names, and the parser has the message "Searches contain unsupported modifiers". The documented support table matches: only `contains`, `all`, `endswith`, `startswith`, and `re` are supported, and `''`, `null`, `1/all of them`, and the encoding modifiers are not [doc]. `cidr`, `exists`, `fieldref`, `expand`, `cased`, numeric, and time modifiers have no constant [jar]. Other messages: "Empty field values are not supported", "Conditions with aggregations are not supported" [jar]. Correlation types: `EVENT_COUNT`, `VALUE_COUNT`, `TEMPORAL`, `TEMPORAL_ORDERED` [jar].
- **Field mapping.** A lookup table, `core-sigma-field-map`, shipped by Illuminate, maps Sigma field names to GIM names. A field it does not map is used as written [jar; doc].
- **Known gaps.** Graylog's own issue graylog2-server#27742 is titled "Sigma import translates field values as case-sensitive exact terms (Sigma matching is case-insensitive)" [doc]. 7.1.9 and 7.2.0 changed how plain values are quoted [doc: changelog].

### Sigma

Sigma v2.1.0 (2025-08-02) [spec]: a rule has `title`, `logsource`, and `detection` (with `condition`) required, plus optional metadata. Search identifiers are maps (keys ANDed), lists of maps (ORed), or keyword lists. Values are case-insensitive strings with `*` and `?` wildcards and `\` escapes. The condition language has `and`, `or`, `not`, parentheses, `1 of`/`any of`/`all of` a pattern or `them`, and a list of conditions that are ORed. The 2.1 modifiers:

- generic: `all`, `startswith`, `endswith`, `contains`, `exists`, `cased`, `neq`;
- string: `windash`;
- regex: `re` with `i`, `m`, `s`;
- encoding: `base64`, `base64offset`, `utf16le`, `utf16be`, `utf16`, `wide`;
- numeric: `lt`, `lte`, `gt`, `gte`;
- time: `minute`, `hour`, `day`, `week`, `month`, `year`;
- other: `cidr`, `expand`, `fieldref`.

Correlation and filter rules are separate document types.

Reference tooling: pySigma 2.1.0 (LGPL-2.1) has a parser, 31 core validators, and processing pipelines. It has **no Graylog backend** (PyPI 404). Its Elasticsearch `LuceneBackend` emits leading wildcards and case-sensitive terms that Graylog refuses or mismatches (V8, V7). rsigma (Rust, MIT, 0.26.0) has a parser, an evaluator, a linter, and an LSP, with MSRV 1.96. Graylog-related prior art is two small third-party repositories. Each post-processes pySigma Lucene output into case-folded regex, which agrees with V8 and V9.

Corpus usage across the 3,779 SigmaHQ rules: `contains` appears 4,134 times, `endswith` 2,729, `all` 963, `startswith` 539. By file: `re` 131, `windash` 88, `null` 89, `''` 48, `cidr` 25, `base64offset` 8, `fieldref` 6. Graylog's own converter refuses at least `windash`, `null`, `''`, and `base64offset`: 233 file-level uses (some files use several).

## Detailed design

### Decisions

1. **One platform, two kinds.** A `graylog` block deploys one event definition. `query` and `sigma` differ only in where the query comes from. Schedule, streams, aggregation, fields, notifications, and metadata are shared at the block root.
2. **opentide compiles Sigma.** The engine compiles a Sigma detection to a Graylog query, and deploy sends an `aggregation-v1` definition. Graylog's Sigma import is not used, because:
   - it needs a Security licence (V24);
   - it returns a name, not an id, so binding the id would mean listing ([deployment-state](../specs/deployment-state.md) forbids rediscovery);
   - 7.2 has no Sigma update path, and `sigma-v1` cannot be written directly (V27);
   - its documented semantics differ from Sigma's (case, refused modifiers).
3. **Sigma is a language, not a Graylog feature.** `specs/languages/sigma-1.0.md` defines the embedded `SigmaDetection`, its checks, and per-platform profiles. Graylog's profile includes the compilation. HarfangLab is checked under its own profile.
4. **State-backed identity.** The server-assigned ObjectId goes in deployment state. Client-assigned ids (V22) and lookup by title or tag are rejected.
5. **Check before save.** Graylog stores any query (V5). Deploy MUST run `/api/search/validate` first and MUST NOT save a query it reports as `ERROR`.
6. **Minimum Graylog 7.0.** That is the version of the create wrapper (V1) and of strict JSON properties. Fields that need a newer version are left out on older servers, with a warning.

---

## Part A: Sigma language (`language-sigma` 1.0)

Proposed file: `specs/languages/sigma-1.0.md`, with front matter `spec: language-sigma`, `version: "1.0"`, `schema_id: null`, `status: normative`.

### A.1 Summary

Sigma is a detection language that several platforms deploy. This spec defines the Sigma **detection** that a platform block embeds, as a `SigmaDetection`: Sigma's own `logsource` and `detection` sections, written as YAML in the block. The opentide rule supplies the rule metadata: title, id, description, level, status, and ATT&CK tags. A platform either compiles the detection into its own query language (Graylog) or assembles a complete Sigma document from it (HarfangLab).

The contract is the Sigma specification **v2.1.0**, detection rules only. Correlation and filter rules are not part of 1.0 ([A.7](#a7-correlation-and-filter-rules)).

### A.2 Requirements

- A platform block that deploys Sigma MUST embed a `SigmaDetection` under the key `sigma`.
- `sigma` MUST be a YAML mapping written out in the block. A YAML alias at `sigma` or at `sigma.detection` MUST fail static validation with `sigma_alias`.
- `sigma` MUST NOT carry Sigma rule metadata (`sigma_metadata_key`, [A.3](#a3-sigmadetection)). Deploy derives it from the opentide rule.
- Static validation MUST report every [error](#a51-errors) as a failure, and every [warning](#a52-warnings) without failing the rule.
- Static validation MUST apply the profile of the platform whose block holds the detection ([A.6](#a6-platform-profiles)). A profile MAY refuse constructs the language allows. It MUST NOT accept a construct the language refuses.
- A compiling profile MUST be deterministic: the same detection, profile, and tenant mapping give the same query, byte for byte.
- A compiling profile MUST NOT produce a query that matches differently from Sigma's semantics without reporting it. A construct it cannot express exactly is an error, or, where its spec says so, a warning that names the approximation.

### A.3 `SigmaDetection`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `logsource` | mapping | yes | Sigma `logsource`: `category`, `product`, `service`, `definition`, all optional strings, at least one of the first three set. |
| `detection` | mapping | yes | Sigma `detection`: search identifiers and `condition`. |
| `taxonomy` | string | optional | Sigma `taxonomy`. Default `sigma`. A profile MAY refuse other taxonomies. |
| `fields` | list[string] | optional | Sigma `fields`: fields an analyst should look at. Profiles MAY use them (Graylog: [event fields](#b4-derived-fields)). |
| `falsepositives` | list[string] | optional | Kept with the detection. Deploy MAY add them to the description. |

Every other Sigma top-level key is refused with `sigma_metadata_key`. Each one has an opentide home:

| Sigma key | opentide source |
|-----------|-----------------|
| `title`, `name` | the block `name`, else the rule `name` |
| `id` | `metadata.uuid` |
| `description` | the rule `description` |
| `status` | the block `status` ([A.6](#a6-platform-profiles) maps it per platform) |
| `level` | the rule severity (`response.alert_severity` in `rule::1.0`, `severity` in `rule::1.1`) |
| `tags` (`attack.*`) | the rule `techniques`, and those inherited through `detection_model` |
| `author`, `date`, `modified`, `references`, `license`, `related`, `scope` | `metadata` and the rule's references |

A complete SigmaHQ rule is therefore pasted as its `logsource` and `detection`, and its metadata moves to the opentide rule. The language server offers that move as a quick fix ([C.3](#c3-sigma-in-the-engine)).

### A.4 Dialect

The language is Sigma v2.1.0 detection semantics:

- **Search identifiers.** A map ANDs its items. A list of maps ORs them. A list of scalars under no field is a **keyword** search. A key's list of values ORs the values, or ANDs them under `|all`. Identifiers match `[A-Za-z0-9_-]+`.
- **Values.** Strings are case-insensitive unless `|cased`. `*` and `?` are wildcards. `\` escapes `*`, `?`, and `\`, as the spec's escaping table defines. Integers and booleans are typed values. `null` matches a missing field. `''` matches an empty value.
- **Condition.** `and`, `or`, `not`, parentheses, `1 of`/`any of`/`all of` with an identifier, a `*` pattern, or `them` (`them` excludes identifiers that start with `_`). A list of conditions is ORed. Precedence, loosest first: `or`, `and`, `not`, `x of`, parentheses. Pipes (`| count() > 5`, `| near`) are **not** part of the language (`sigma_condition_pipe`).
- **Modifiers.** Every modifier in [Research](#sigma), plus pySigma's aliases `ignorecase` (= `i`), `multiline` (= `m`), and `dotall` (= `s`). They chain left to right, and each one's input type must fit the output type of the one before (the pySigma type rules). Transformation modifiers are applied by the engine, so every profile gets the same values:
  - `windash` expands each `-` or `/` that starts an option (pySigma's rule: the regex `\B[-/]\b`, so in `-param-name` only the first dash) into the five dash characters the spec lists. The spec text says "all possible permutations"; pySigma, the oracle, is narrower, and opentide follows pySigma. A compiling profile MAY emit a character class instead of the permutations, which avoids pySigma's three-dash expansion cap;
  - `base64`, `base64offset`, `utf16le`/`wide`, `utf16be`, and `utf16` encode;
  - `expand` substitutes placeholders from the tenant ([B.6](#b6-tenant-setup)), and refuses the rule when one is missing.
- **Regex** (`re`): the spec's PCRE subset. Anything outside it is `sigma_regex`.

### A.5 Diagnostics

Codes are stable. The language server's `docs/SIGMA.md` maps each to the clause of the Sigma specification, or to the pySigma check, that proves it.

#### A.5.1 Errors

| Code | Condition |
|------|-----------|
| `sigma_alias` | `sigma` or `sigma.detection` is a YAML alias |
| `sigma_shape` | `logsource` or `detection` is missing or not a mapping; `logsource` has none of `category`, `product`, `service`; a search identifier is neither a map nor a list; a list mixes maps and scalars |
| `sigma_metadata_key` | a Sigma metadata key in the block ([A.3](#a3-sigmadetection)) |
| `sigma_condition_missing` | `detection` has no `condition` |
| `sigma_condition_syntax` | the condition does not parse |
| `sigma_condition_pipe` | an aggregation pipe or `near` in the condition |
| `sigma_undefined_identifier` | the condition names an identifier, or a pattern that matches none |
| `sigma_unknown_modifier` | a modifier that Sigma 2.1 and pySigma do not define |
| `sigma_modifier_chain` | a chain whose types do not fit (`|re|contains`, `|i` without `re`, `|gt` on a string), or a modifier repeated (except `base64`) |
| `sigma_all_single_value` | `|all` on a single value |
| `sigma_null_in_list` | `null` inside a list of values |
| `sigma_value_type` | a value of the wrong type for its modifiers (`|exists: "yes"`, `|cidr: 10.0.0`, `|gt: abc`) |
| `sigma_regex` | a `re` value that is not a valid regex in the spec's subset |
| `sigma_escape` | a trailing single `\` that escapes nothing at the end of a value |

#### A.5.2 Warnings

| Code | Condition | pySigma equivalent |
|------|-----------|--------------------|
| `sigma_unused_identifier` | a search identifier the condition never reaches | `dangling_detection` |
| `sigma_all_of_them` | `all of them` (the spec discourages it) | `all_of_them_condition` |
| `sigma_them_single` | `1 of them` or `all of them` with one identifier | `them_condition_with_single_detection` |
| `sigma_modifier_combination` | a field-bound `|all` without `contains`; `base64offset` without `contains`; `windash` with `all` | `invalid_modifier_combinations` |
| `sigma_double_wildcard` | `**` in a value | `double_wildcard` |
| `sigma_wildcard_instead_of_modifier` | `*x*`, `x*`, `*x` where `contains`, `startswith`, or `endswith` says it | `wildcards_instead_of_modifiers` |
| `sigma_number_as_string` | a quoted integer on a field the taxonomy types as a number (`EventID: '4688'`) | `number_as_string` |
| `sigma_control_character` | a control character in a value | `control_character` |
| `sigma_logsource_unknown` | a `category`, `product`, or `service` not in the Sigma taxonomy appendix | — |
| `sigma_field_unknown` | a field name not in the taxonomy for the log source, where the catalogue covers that log source | `fieldname_logsource` |

pySigma 2.1 is the conformance oracle for the language: every rule of the pinned SigmaHQ corpus that pySigma loads without error MUST produce no `sigma_*` error, and every broken twin ([C.5](#c5-conformance-and-test-plan)) MUST produce the error the twin targets.

### A.6 Platform profiles

| | `graylog` | `harfanglab` |
|---|---|---|
| Delivery | compiled to a Graylog search query by the engine ([B.5](#b5-sigma-compilation-graylog-profile)) | assembled into a Sigma document and sent to HarfangLab |
| Block form | `SigmaDetection` | HarfangLab's decomposed `sigma` (unchanged), assembled into a `SigmaDetection` before checking |
| Taxonomy | `sigma` only | `sigma` only |
| Keywords | phrases without wildcards | as written |
| `null`, `exists` | yes | as written |
| `''` | no (`graylog_sigma_empty_value`) | as written |
| Encoding modifiers, `windash`, `expand` | yes (engine transformations) | as written |
| `cidr` | IPv4 always; IPv6 on `ip`-typed fields | as written |
| `fieldref`, time modifiers | no (`graylog_sigma_unsupported`) | as written |
| `re` | translated to Lucene RegExp; unsupported constructs refused | as written |
| Field names | mapped by the tenant's field mapping | as written |
| Status mapping | none (the block `status` drives deploy) | `maturity` |
| Profile codes | `graylog_sigma_*` ([B.3](#b3-constraints)) | none in 1.0 |

The HarfangLab row records today's behaviour: HarfangLab's engine and its modifier support are not published. Checking its assembled detection against the language is the gain. Moving HarfangLab to the `SigmaDetection` form is a later change ([Unresolved questions](#unresolved-questions)).

### A.7 Correlation and filter rules

Sigma correlation rules reference other rules by `id` or `name`. In opentide, that would be a reference from one rule object to others: a cross-object relation that the object model does not have yet ([RFC 0011](0011-signal-reuse.md) is related). Sigma filter rules tune many rules at once, which is tenant configuration, not a detection. Neither type is part of `language-sigma` 1.0. A `sigma` block with a `correlation` or `filter` key fails `sigma_metadata_key`.

What Sigma `event_count`, `value_count`, `value_sum`, `value_avg`, and `value_percentile` express over one base rule is expressible today. A `graylog` block's [`aggregation`](#b2-block-fields) applies to a `sigma` detection as it does to a `query`. A later RFC adds correlation rules once opentide can reference rules from rules.

---

## Part B: Graylog platform (`platform::graylog::1.0`)

Proposed file: `specs/platforms/graylog-1.0.md` (`spec: platform-graylog`, `version: "1.0"`, `schema_id: platform::graylog::1.0`).

### B.1 Shape

```yaml
configurations:
  graylog:
    enabled: true
    schema: platform::graylog::1.0
    status: STAGING                     # shared; required
    name: ""                            # shared; empty → the opentide rule name
    priority: null                      # Informational | Low | Medium | High | Critical; default from the rule severity
    alert: true                         # Graylog alert flag
    tags: [windows, office]             # added to the derived tags
    streams: [sysmon]                   # tenant aliases; default: tenant streams
    stream_categories: []               # Graylog stream categories, as written
    schedule:
      every: 5m                         # or cron + timezone
      window: 5m                        # default: every
    event_fields:
      host: ${source.source}
      user: ${source.user_name}
    event_key: [host]
    notifications: [soc-slack]          # tenant aliases
    grace_period: 10m
    summary: "Encoded PowerShell on ${source.source}"
    remediation: Isolate the host and collect the process tree.
    sigma:                              # exactly one of query | sigma
      logsource:
        category: process_creation
        product: windows
      detection:
        selection_parent:
          ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
        selection_child:
          Image|endswith: '\powershell.exe'
          CommandLine|contains|windash: ' -enc'
        condition: all of selection_*
```

```yaml
configurations:
  graylog:
    enabled: true
    schema: platform::graylog::1.0
    status: PRODUCTION
    streams: [windows-security]
    schedule: {every: 5m}
    aggregation:
      group_by: [source_ip]
      condition: count() >= 10 AND card(user_name) >= 3
    query: event_code:4625 AND NOT user_name:/.*\$/
```

### B.2 Block fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | conditional | — | A Graylog search query ([B.7](#b7-graylog-query-dialect)). Non-blank. |
| `sigma` | [`SigmaDetection`](#a3-sigmadetection) | conditional | — | A Sigma detection, compiled under the `graylog` profile. |
| `priority` | string | optional | [derived](#b4-derived-fields) | `Informational`, `Low`, `Medium`, `High`, or `Critical` |
| `alert` | boolean | optional | `true` | `false` makes fired events plain events, not alerts |
| `tags` | list[string] | optional | `[]` | Added to the [derived tags](#b4-derived-fields) |
| `streams` | list[string] | optional | tenant `streams` | Aliases from the tenant's `streams` table |
| `stream_categories` | list[string] | optional | `[]` | Graylog stream categories (6.1+), as written. Portable across tenants. |
| `schedule` | [Schedule](#schedule) | optional | `{every: 5m}` | When the definition runs and what it searches |
| `event_limit` | integer | optional | `100` | Filter only: at most this many events per run, 1–1,000 |
| `aggregation` | [Aggregation](#aggregation) | optional | null | Turns the filter into an aggregation |
| `event_fields` | map | optional | [derived](#b4-derived-fields) | Event field name → template string, or `{lookup: {table, key_field}}` |
| `event_key` | list[string] | optional | `[]` | Event fields that make up the event key. Each one MUST be an `event_fields` key, or a derived one. |
| `notifications` | list[string] | optional | `[]` | Aliases from the tenant's `notifications` table |
| `grace_period` | duration | optional | `0s` | Per event key |
| `backlog` | integer | optional | `0` | Messages attached to a notification (`backlog_size`), 0 or more |
| `summary` | string | optional | null | Event summary template (7.1+) |
| `remediation` | string | optional | null | Remediation steps |

The shared `name` is the definition `title`. `status` is required, as on `elastic`, `sysdig`, and `bitdefender`.

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

`count()` takes an optional field, `percentile(field, p)` requires `0 < p ≤ 100`, and every other function requires a field. These are the 12 functions of V25. One series is sent for each distinct call, with id `<function>-<field>` (`count-` for `count()`, the form V23 used). The expression becomes Graylog's `expr` tree: `&&`, `||`, `!`, the comparison operators, `number-ref`, and `number`.

### B.3 Constraints

Static validation MUST reject a block that breaks any of these, and report the code.

| Code | Constraint |
|------|------------|
| `graylog_rule_kind` | Exactly one of `query` and `sigma` |
| `graylog_query_blank` | `query` is non-blank |
| `graylog_schedule` | Exactly one of `every` and `cron`. Durations follow the grammar and are greater than zero. `cron` has 6 or 7 fields and parses as Quartz. `timezone` is an IANA zone. `window` is set with `cron`. |
| `graylog_event_limit` | `event_limit` is 1–1,000. It is not set together with `aggregation`. |
| `graylog_aggregation` | `condition` parses under the [grammar](#aggregation-condition-grammar). Each function has the arguments it needs. `group_by` has unique, non-empty field names. |
| `graylog_event_field` | Each `event_fields` name is a valid Graylog field name (`[A-Za-z0-9_.@-]+`). A template is non-blank. A lookup names `table` and `key_field`. |
| `graylog_event_key` | Each `event_key` entry is an event field (V20) |
| `graylog_priority` | `priority` is one of the five names |
| `graylog_field_name` | A field name in `query`, `group_by`, or a condition is a valid Graylog field name |
| `graylog_query_syntax` | `query` parses under the [Graylog dialect](#b7-graylog-query-dialect) |
| `graylog_leading_wildcard` | A term in `query` starts with `*` or `?`, and a targeted tenant does not set `allow_leading_wildcard` (V8) |
| `graylog_sigma_empty_value` | A Sigma `''` value (V14) |
| `graylog_sigma_unsupported` | `fieldref`, a time modifier, or a `taxonomy` other than `sigma` |
| `graylog_sigma_regex` | A `re` value uses a construct with no Lucene RegExp equivalent: lookaround, backreference, `\b`, `\B`, `\A`, `\z`, possessive quantifiers, named groups, or an inline flag other than a leading `(?i)` (V12) |
| `graylog_sigma_keyword_wildcard` | A keyword value with a wildcard |
| `graylog_sigma_cidr` | An IPv6 `cidr` on a field the tenant does not type as `ip` |

The `sigma` block is also checked against [Part A](#a5-diagnostics) under the `graylog` profile. A `sigma` block's compiled query is checked like a `query` ([B.7](#b7-graylog-query-dialect)), with positions mapped back to the Sigma value that produced each clause.

Advisories (warnings, [validation.md](../specs/validation.md#platform-advisories)):

| Code | When |
|------|------|
| `graylog_overlapping_window` | `window` is longer than `every` on a filter (no `aggregation`). Each message alerts once per overlapping run (V23). |
| `graylog_lowercase_operator` | `and`, `or`, or `not` as a bare term in `query`: Graylog searches the word (V6) |
| `graylog_regex_operator` | An unescaped `#`, `&`, `<`, `>`, or `~` inside a regex in `query`: Lucene reads it as an operator (V11) |
| `graylog_regex_quote` | An unescaped `"` inside a regex in `query` (V9: it matches nothing) |
| `graylog_analyzed_field` | A regex, wildcard, or range on `message` or `full_message`, which are tokenised (V7) |
| `graylog_case_sensitive` | A `query` term on a keyword field with letters, not quoted as a regex or a phrase. Graylog matches it case-sensitively (V7). Reported once per query. |
| `graylog_all_streams` | No `streams` and no `stream_categories` on the block or the tenant: the definition searches every stream |
| `graylog_sigma_field_unmapped` | A Sigma field the tenant mapping does not map. It is sent as written. |
| `graylog_sigma_query_size` | The compiled query has more than 1,024 clauses (Graylog's limit is `opensearch_indices_query_bool_max_clause_count`, default 32,768) |
| `graylog_title_duplicate` | Workspace check: two enabled blocks resolve to one title. Graylog allows it (V19), and the alert list cannot tell them apart. |
| `graylog_priority_collapsed` | `Informational` on a tenant older than 7.1, sent as Low (1) |

### B.4 Derived fields

| Graylog field | Derivation |
|---------------|------------|
| `title` | Shared `name`, else the rule `name` |
| `description` | The rule `description`, whitespace collapsed. With a `sigma` block, `falsepositives` follow as "False positives: …". |
| `priority` | `priority`, else from the rule severity: Critical 4, High 3, Medium 2, Low 1, Informational 0 (1 before 7.1) |
| `alert` | `alert` |
| `tags` (7.2+) | Union, without duplicates and in this order: the block `tags`; `opentide`; `opentide.<metadata.uuid>`; the tenant `tags`. Each one lower-cased, with any character outside `[a-z0-9_.-]` replaced by `-`, and cut at 128 characters. At most 64; the block's are kept first. |
| `tactics_techniques` (7.2+) | The rule's techniques plus those inherited through `detection_model`, Enterprise only (the [Elastic ATT&CK rule](../specs/platforms/elastic-1.0.md#attck)), then their tactic ids from the same table. Techniques by id, then tactics. At most 64. |
| `config.query` | `query`, or the compiled `sigma` |
| `config.streams` | Stream ids resolved from the aliases |
| `config.series`, `conditions`, `group_by` | From `aggregation`; empty and `{"expression": null}` for a filter |
| `field_spec` | `event_fields`. With a `sigma` block that has none, one field per Sigma `fields` entry (mapped), templated from the source message. |
| `key_spec` | `event_key` |
| `notification_settings` | `grace_period` in ms, `backlog` |
| `event_summary_template` (7.1+), `remediation_steps` | `summary`, `remediation` |
| `_scope` | Always `DEFAULT` (V21) |

`opentide.<uuid>` is for analysts and audits. Deploy never uses it to find a definition.

### B.5 Sigma compilation (`graylog` profile)

The engine compiles a `SigmaDetection` in four steps:

1. Apply transformation modifiers ([A.4](#a4-dialect)).
2. Map fields through the tenant's field mapping ([B.6](#b6-tenant-setup)).
3. Lower each detection item to a Graylog clause.
4. Combine the clauses as the condition says.

Where Graylog typing matters, the compiler uses the mapping's field types. A field with no declared type is a keyword, as Graylog maps it dynamically (V7).

#### Values on keyword fields

The compiler emits the simplest clause that keeps Sigma's semantics:

| Sigma value | Clause | Evidence |
|-------------|--------|----------|
| integer `n` | `f:n` | V15 |
| string with no letter that changes case, no wildcard, no modifier, or `|cased` with no wildcard | `f:"<phrase-escaped>"` | V9, V10 |
| any other string: case-insensitive, or with a wildcard, `contains`, `startswith`, or `endswith` | `f:/<regex>/`, built below | V8, V9 |
| `|cased` with a wildcard | `f:/<regex>/`, without case folding | V9 |

The regex for a string value:

1. Split the value into literals and wildcards, using Sigma escapes (`\*`, `\?`, `\\`).
2. For each literal character: a letter with distinct upper- and lower-case forms becomes `[Xx]` (simple Unicode case folding), unless `|cased` or an encoding modifier applies. One of `. ? + * | { } [ ] ( ) " \ # @ & < > ~ /` gets a `\` before it. Any other character stays as written.
3. `*` becomes `.*`, and `?` becomes `.`.
4. `contains` wraps the result in `.*` on both sides, `startswith` appends `.*`, and `endswith` prepends `.*`. Lucene regex is anchored (V9), so an exact match needs nothing more.

Example (verified, V9): `Image|endswith: '\powershell.exe'` compiles to `Image:/.*\\[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]\.[Ee][Xx][Ee]/`.

#### Other items

| Sigma | Clause | Evidence |
|-------|--------|----------|
| `f: null`, `f|exists: false` | `NOT _exists_:f` | V15 |
| `f|exists: true` | `_exists_:f` | V15 |
| `f|gt: n` (`gte`, `lt`, `lte`) | `f:>n` (`>=`, `<`, `<=`) | V15 |
| `f|neq: v` | `NOT (<clause for v>)` | — |
| list of values | `(<c1> OR <c2> …)`; `|all`: `(<c1> AND <c2> …)` | — |
| `f|re: p` | `f:/<translated p>/`: a leading `^` and trailing `$` are dropped, and `.*` is added at an end that was not anchored. `|i` folds literal letters as above, and a leading `(?i)` is read as `|i`. `|s` is native. `|m` is an error when `^` or `$` occurs inside the pattern. Lucene operator characters are escaped. `\d`, `\w`, `\s` stay. | V12 |
| `f|cidr: a.b.c.d/n` (IPv4) | regex over the four octets: whole octets fixed, the octet that holds the boundary as an interval `<lo-hi>`, the rest `<0-255>` | V13 |
| `f|cidr` (IPv6) on an `ip` field | `f:"<cidr>"` | — |
| keyword `v` | `"<phrase-escaped v>"`, unqualified (all fields) | V15 |
| `windash` | each dash position becomes the class `[\-\/–—―]` in the regex (`/` escaped, or it ends the regex) | V28 |
| `base64`, `base64offset`, `utf16*`, `wide` | the encoded strings, each matched **case-sensitively** | — |

On `message` and `full_message`, which are analysed: a value with no wildcard and no `startswith`/`endswith` compiles to a phrase (case-insensitive by the analyser). Anything else on those fields is `graylog_analyzed_field`. On `source`, a lower-cased keyword: the value is lower-cased and matched without case folding.

The condition compiles to `AND`, `OR`, `NOT`, and parentheses. `1 of p` is the OR of the matching identifiers, and `all of p` is their AND. A list of conditions is ORed. Every compound is parenthesised, so precedence never depends on Graylog's default operator.

#### Log source

The tenant mapping MAY attach a clause and streams to a log source. For example, `windows/process_creation` maps to `gim_event_type_code:190000` with `stream_categories: [windows_logs]`. The clause is ANDed before the detection, and the streams apply when the block sets none. This is how a Sigma backend's pipeline narrows a log source.

### B.6 Tenant setup

```toml
[platform]
enabled = true
identifier = "graylog"
name = "Graylog"
description = "Graylog event definitions from native queries and Sigma."
flags = []

[[tenants]]
name = "graylog-prod"
strategies = ["RELEASE"]
[tenants.setup]
ssl = true
url = "https://graylog.example.com"
token = "$GRAYLOG_TOKEN"
allow_leading_wildcard = false
field_mapping = "gim"
streams = ["sysmon"]
tags = ["managed-by-opentide"]

[tenants.setup.stream_ids]
sysmon = "65f0c0ffee0123456789abcd"
windows-security = "65f0c0ffee0123456789abce"

[tenants.setup.notification_ids]
soc-slack = "65f0c0ffee0123456789abcf"

[tenants.setup.field_overrides]
CommandLine = "process_command_line"

[tenants.setup.field_types]
source_ip = "ip"
destination_ip = "ip"

[tenants.setup.placeholders]
Servers = ["srv-*", "dc-*"]
```

| `tenants.setup` field | Type | Required | Default | Meaning |
|-----------------------|------|----------|---------|---------|
| `url` | string | yes | — | Base URL of the Graylog web interface. The client appends `/api`. |
| `token` | string | yes | — | Graylog access token. MUST be a `$ENV` reference. Sent as HTTP Basic `<token>:token`. |
| `allow_leading_wildcard` | bool | no | `false` | Mirrors the server's `allow_leading_wildcard_searches` |
| `field_mapping` | string | no | `none` | Sigma field mapping: `none` (as written), `gim` (bundled Sigma-to-GIM), or a workspace path to a mapping TOML |
| `field_overrides` | table | no | `{}` | Sigma field → Graylog field, applied after `field_mapping` |
| `field_types` | table | no | `{}` | Graylog field → `keyword`, `text`, `lowercase`, `number`, or `ip` |
| `streams` | list[string] | no | `[]` | Default stream aliases |
| `stream_ids` | table | no | `{}` | Alias → stream id (24 hex) |
| `notification_ids` | table | no | `{}` | Alias → notification id (24 hex) |
| `placeholders` | table | no | `{}` | Sigma `expand` placeholder → values |
| `tags` | list[string] | no | `[]` | Tags added to every definition on this tenant |
| `ssl` | bool | yes | — | Shared tenant setup (TLS verification) |

The token's user needs `eventdefinitions:create`, `:read`, `:edit`, and `:delete`, and `streams:read` on every stream a definition names. A stream or notification alias that the tenant does not define fails that rule at deploy (`graylog_alias_unknown`).

A mapping TOML has a `[fields]` table (Sigma field → Graylog field), an optional `[fields.<category>]` per log-source category, a `[types]` table, and a `[logsource."<product>/<category>"]` table with `condition` and `stream_categories`. The bundled `gim` mapping is data in the language server (`catalogs/sigma/graylog-gim.toml`), generated and pinned like Bitdefender's criteria catalogue. Its log-source clauses come from Graylog's documented Illuminate event codes. For example, the Sysmon content pack maps EID 1 to `gim_event_type_code` 190000, EID 3 to 120000, and EID 11 to 200000.

### B.7 Graylog query dialect

The engine adds `Dialect::Graylog` to its Lucene `query_string` parser (`opentide-lucene`, beside `Elastic` and `CarbonBlack`). The dialect differs from `Elastic` in four ways:

- A leading wildcard is `graylog_leading_wildcard` (error) unless the tenant allows it.
- A lower-case operator is `graylog_lowercase_operator` (warning) instead of being parsed silently.
- Regex bodies are checked for Lucene operator characters (`graylog_regex_operator`, `graylog_regex_quote`) and against Lucene RegExp syntax.
- Field names follow Graylog's `Message.validKey`, and the GIM catalogue supplies completion and hover.

`/api/search/validate` is the dialect's oracle: on the conformance corpus, the engine's syntax verdict MUST equal Graylog's `QUERY_PARSING_ERROR` verdict ([C.5](#c5-conformance-and-test-plan)).

### B.8 Deploy

Graylog is **state-backed**, like Defender for Endpoint, SentinelOne, CrowdStrike, Sysdig, and Bitdefender:

- **Where.** `platforms.graylog.<tenant>` in `.opentide/states/deployment/<uuid>.json` (`deployment.state::1.0`), one binding per tenant. The tenant key is the configured tenant `name`, whitespace-stripped.
- **Shape.** The 24-hex id from the create response, lower-case, matching `^[0-9a-f]{24}$`. The shard schema's existing `objectIdTenants` covers it.
- **No rediscovery.** Deploy MUST NOT find a definition by listing, by title, or by the `opentide.<uuid>` tag.
- **No client ids.** Deploy MUST NOT send `id` on create (V22).
- **No orphan creates.** As for Bitdefender: `deployment_state_ignored` and `deployment_state_unpersisted` refuse a create whose id cannot be kept.

Once per tenant per run, deploy reads `GET /api/system`. A version below 7.0 fails the tenant (`graylog_version_unsupported`). The version decides which optional fields are sent ([B.4](#b4-derived-fields)). A field the version cannot take is left out, with `graylog_field_unsupported_version` (warning).

Before each create or update, deploy MUST send the compiled query to `POST /api/search/validate`, with the definition's streams, stream categories, and a relative time range of `window`. `ERROR` fails the rule with `graylog_query_invalid` and the explanations, and the definition is not saved. `WARNING` explanations are reported as warnings: `UNKNOWN_FIELD` is `graylog_unknown_field`, and `INVALID_VALUE_TYPE` is `graylog_value_type`.

| Block status strategy | Binding | Graylog calls |
|-----------------------|---------|---------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | `POST /api/events/definitions?schedule=true` with `{"entity": <dto>, "share_request": null}`; the returned `id` is recorded |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present | `PUT /api/events/definitions/{id}?schedule=true` with the **whole** DTO |
| `DISABLEMENT` | present | `PUT /api/events/definitions/{id}?schedule=false` with the whole DTO |
| `DELETION` | present | `DELETE /api/events/definitions/{id}`; any 2xx (V4) removes the binding |
| `DISABLEMENT`, `DELETION` | none | `external_id_missing` (warning), no call |

Every request sends `X-Requested-By: opentide` and `Accept: application/json` (V26). The DTO never carries `state`, `storage`, `scheduler`, `updated_at`, `matched_at`, or `_entity_source`. It carries `_scope: DEFAULT`, and, on update, the bound `id`.

A create sends (abridged):

```json
{
  "entity": {
    "_scope": "DEFAULT",
    "title": "Office application spawns encoded PowerShell",
    "description": "Detects an Office application starting PowerShell with an encoded command.",
    "priority": 3,
    "alert": true,
    "tags": ["windows", "office", "opentide", "opentide.00000000-0000-4000-8003-000000000040", "managed-by-opentide"],
    "tactics_techniques": ["T1059.001", "T1566.001", "TA0001", "TA0002"],
    "config": {
      "type": "aggregation-v1",
      "query": "((ParentImage:/.*\\\\[Ww][Ii][Nn][Ww][Oo][Rr][Dd]\\.[Ee][Xx][Ee]/ OR ParentImage:/.*\\\\[Ee][Xx][Cc][Ee][Ll]\\.[Ee][Xx][Ee]/)) AND (Image:/.*\\\\[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]\\.[Ee][Xx][Ee]/ AND CommandLine:/.* [\\-\\/–—―][Ee][Nn][Cc].*/)",
      "query_parameters": [],
      "filters": [],
      "streams": ["65f0c0ffee0123456789abcd"],
      "stream_categories": [],
      "group_by": [],
      "series": [],
      "conditions": {"expression": null},
      "search_within_ms": 300000,
      "execute_every_ms": 300000,
      "use_cron_scheduling": false,
      "event_limit": 100
    },
    "field_spec": {
      "host": {"data_type": "string", "providers": [{"type": "template-v1", "template": "${source.source}", "require_values": false}]}
    },
    "key_spec": ["host"],
    "notification_settings": {"grace_period_ms": 600000, "backlog_size": 0},
    "notifications": [{"notification_id": "65f0c0ffee0123456789abcf"}],
    "event_summary_template": "Encoded PowerShell on ${source.source}",
    "remediation_steps": "Isolate the host and collect the process tree."
  },
  "share_request": null
}
```

Failure handling:

- **Definition gone.** A `PUT` answered 404 creates the definition again and replaces the binding, with `graylog_definition_recreated` (warning). Under `DISABLEMENT` deploy creates nothing, removes the binding, and warns `graylog_definition_missing`.
- **Immutable.** "Immutable entity cannot be modified" or "Non-deletable entity cannot be deleted" (V21) fails the rule with `graylog_definition_immutable`. Deploy never changes a scope.
- **In use.** A `DELETE` refused because another definition (a correlation) depends on it fails with `graylog_definition_in_use` and the dependants' ids.
- **Refused body.** 400 with `{"errors": {field: [messages]}}` fails the rule with `graylog_definition_invalid` and the messages.
- **Authorisation.** 401 stops the tenant (`graylog_tenant_unauthorized`). 403 fails the rule (`graylog_forbidden`), most often a stream permission.
- **Unconfirmed create.** A create with no answer MUST NOT be retried: titles are not unique (V19), so a retry may create a second definition. It fails with `graylog_create_unconfirmed`, which names the `opentide.<uuid>` tag so the operator can find the definition in the web interface.

Deploy MUST NOT call `/execute`, MUST NOT list definitions, and MUST NOT write to the rule file.

### B.9 Validation and query

| Check | Graylog |
|-------|---------|
| `opentide validate` (offline) | yes: block constraints, the Graylog dialect for `query`, the Sigma language and `graylog` profile for `sigma`, and the compiled query under the dialect |
| `opentide validate query` (offline) | yes: `query` or the compiled `sigma` |
| `opentide validate query --live` | **yes**: `POST /api/search/validate` per tenant, with the block's streams and `window`. `ERROR` is an error; `WARNING` and `INFO` are warnings, with Graylog's positions. |
| `opentide query` | yes: `POST /api/search/messages` (Graylog 5.0+), read-only. Language `graylog`; a `sigma` block runs its compiled query. |

Graylog joins the query-validation allowlist ([platforms](../specs/platforms/index.md#query-validation-platforms)). `OFFLINE_QUERY_LANGUAGES["graylog"]` is `("graylog", "sigma")`.

---

## Part C: Analysis engine and language server

### C.1 New languages

| `LanguageId` | Where it appears | Built on |
|--------------|------------------|----------|
| `graylog` | `configurations.graylog.query`; `.graylog` query files | `opentide-lucene` with `Dialect::Graylog` |
| `graylog-condition` | `configurations.graylog.aggregation.condition` | a small hand-written parser in `opentide-tide` ([grammar](#aggregation-condition-grammar)) |
| `sigma` | `configurations.<platform>.sigma`, a structured YAML block; `.yml` Sigma files under `validate query --platform` | new crate `opentide-sigma` |
| `sigma-condition` | `sigma.detection.condition` | a tree-sitter grammar `tree-sitter-opentide-sigma-condition` (injected), so highlighting follows the shared HighlightSpec |

### C.2 Graylog in the engine

- `Dialect::Graylog` at the four dialect sites (`opentide-analysis` ×3, `opentide-tide` ×1), with the differences in [B.7](#b7-graylog-query-dialect).
- `catalogs/graylog/fields.toml`: Graylog's built-in message fields (`message`, `full_message`, `source`, `timestamp`, `streams`, `gl2_*`) and GIM fields with their types. It is generated from graylog2-server's `org/graylog/schema/*Fields.java` constants (field names only) by `scripts/sync_graylog_fields.py`, and pinned to a Graylog tag.
- Hover and completion for fields, operators, `_exists_`, and the condition functions. Completion of stream and notification aliases from the workspace's tenant tables.
- Injection rows in `crates/opentide-tide/src/injection.rs` for `query` and `aggregation.condition`.

### C.3 Sigma in the engine

`opentide-sigma` holds:

- **Parser.** It works on the Tide YAML tree the engine already has, so every diagnostic has a position in the rule file. It covers search identifiers, values, the modifier chains, and the condition (through the injected grammar).
- **Checks.** Every `sigma_*` code ([A.5](#a5-diagnostics)).
- **Catalogues.** `catalogs/sigma/modifiers.toml` (name, input and output types, aliases, documentation), `catalogs/sigma/taxonomy.toml` (log sources and their fields, from the specification's taxonomy appendix), and `catalogs/sigma/graylog-gim.toml`. Each is generated by a sync script and pinned to a source commit.
- **Compiler.** A `Target` trait with one implementation in 1.0, `graylog`. The result carries the query, the warnings, and a **source map** (compiled clause span → Sigma value span), so compiled-query diagnostics point at the Sigma line that caused them.
- **Binding.** `compile_sigma(block, profile, mapping) -> Compiled` through PyO3 (`opentide._native`, `src/opentide/_native.pyi`). Deploy and the editor use the same compiler.

Editor features:

| Feature | Detail |
|---------|--------|
| Diagnostics | `sigma_*` and `graylog_sigma_*`, positioned in the block; compiled-query diagnostics positioned through the source map |
| Completion | modifiers after `|`, filtered by the chain's current type; log-source values from the taxonomy; field names for the log source; identifiers and `1 of`/`all of`/`them` in `condition` |
| Hover | a modifier's meaning and types; a field's taxonomy entry and its Graylog mapping; on `sigma:`, the compiled Graylog query |
| Code actions | "Move Sigma metadata to the rule" for `sigma_metadata_key`; "Convert to native `query`" (replaces `sigma` with its compiled query) |
| Highlighting | modifiers, identifiers, and condition keywords, through the HighlightSpec |

Parsing Sigma ourselves rather than depending on rsigma is deliberate. The detection is embedded in a Tide YAML document, and diagnostics need positions in that document. rsigma parses standalone files, and its MSRV (1.96) is above the engine's (1.95). rsigma is a second **differential oracle** in conformance testing ([C.5](#c5-conformance-and-test-plan)).

### C.4 Tide catalogue

The new `GraylogConfig` model adds `configurations.graylog.*` to the generated Tide catalogue. The engine's bundled catalogue therefore goes stale, and `scripts/build/check_engine_catalog.py` fails until language-server regenerates it (`scripts/sync_opentide_schemas.py` with the opentide checkout), releases, and opentide bumps the engine pin. Order: specifications, then opentide models, then the language-server catalogue and engine, then the opentide pin bump and the deployer.

### C.5 Conformance and test plan

| Layer | Corpus | Oracle | Gate |
|-------|--------|--------|------|
| Sigma language | SigmaHQ `rules/`, `rules-emerging-threats/`, `rules-threat-hunting/` at a pinned commit (DRL 1.1, attribution in `SOURCES.md`), plus one broken twin per error code | pySigma 2.1 (load plus core validators); rsigma as a second opinion | 100% agreement on accept/reject; every twin raises its code |
| Graylog dialect | the existing SigmaHQ Lucene corpus, `lucene-queryparser/cases.tsv`, every compiled query, plus hand cases for V8–V13 | `POST /api/search/validate` on Graylog 7.2 (Open) | syntax verdicts equal |
| Compiler, golden | each modifier, value form, and condition form → expected Graylog query, as fixtures in specifications (`fixtures/languages/sigma/graylog/*.yml` and `*.query`) | review | exact text |
| Compiler, semantic | for every golden: generated positive and negative events (case flipped, prefix and suffix added, dash variants, encoded variants), ingested over GELF | a **live Graylog 7.2 Open** in CI (Docker: Graylog, OpenSearch, MongoDB), searching the compiled query | each event matches iff Sigma says it should |
| Deployer | create, update, disable, delete, recreate on 404, immutable, unconfirmed create | a fake Graylog server (unit) and the live Graylog (nightly) | the decision table in [B.8](#b8-deploy) |

The semantic harness is possible because the design needs only Graylog Open: CI can start the same stack this RFC was verified on, with no licence. It is the check that would have caught V10 and V11.

---

## Engineering plan

| # | Work package | Repo | Person-days |
|---|--------------|------|-------------|
| S1 | `specs/languages/sigma-1.0.md`, `specs/platforms/graylog-1.0.md`; `platforms/index.md` 1.8 (eleven platforms, Graylog in `--live`); `validation.md` codes; `deployment-state.md` (`graylog`); `rule-1.x` block table; `SPECS.md`, `llms.txt`, `CHANGELOG.md`; fixtures (`fixtures/platforms/graylog-query.yaml`, `graylog-sigma.yaml`, `graylog/*.api.json`, invalid twins); fixture checkers (`validate_graylog_block`, `scripts/test_platform_graylog.py`, `test_language_sigma.py`); the three "ten platforms" assertions | specifications | 4–5 |
| L1 | `Dialect::Graylog`, Graylog field catalogue and sync script, injection, hover and completion | language-server | 3–4 |
| L2 | `graylog-condition` parser, checks, completion | language-server | 1–2 |
| L3 | `opentide-sigma`: parser on the Tide YAML tree, condition grammar, modifier and taxonomy catalogues, every `sigma_*` check | language-server | 7–9 |
| L4 | Graylog compiler with source map, `gim` mapping catalogue, `graylog_sigma_*` checks, PyO3 binding, editor features | language-server | 6–8 |
| L5 | Conformance: pySigma and rsigma oracles over SigmaHQ, broken twins, the Graylog `search/validate` oracle, the live semantic harness in CI | language-server | 5–6 |
| O1 | Models: `GraylogConfig`, schedule, aggregation, `SigmaDetection`; tenant setup; mapping TOML loader | opentide | 2–3 |
| O2 | REST client on `TenantSession`: auth, CSRF header, version probe, error mapping | opentide | 1–2 |
| O3 | Compile: derived fields, ATT&CK, tags normalisation, version gating, `api_body` goldens against the fixtures | opentide | 2–3 |
| O4 | Deployer on deployment state (`graylog` in `STATE_PLATFORMS` and `OBJECT_ID_PLATFORMS`), pre-save check, the decision table | opentide | 3 |
| O5 | Live validator (`LiveQueryValidator`), `opentide query` runner (`/api/search/messages`) | opentide | 2 |
| O6 | Wiring (about 38 registration sites), bundled TOML, template, diagnostics pages, docs (usage, CLI, MCP, SDK), MCP default language | opentide | 3 |
| O7 | Tests: model, compile, deployer (fake server), live validator, runner, CLI E2E, MCP; a nightly live-Graylog job | opentide | 4–5 |

About 43–55 person-days. The Sigma language (L3, part of L5) is about a third of it, and HarfangLab reuses it.

Delivery order:

1. **S1** specifications.
2. **L1–L2** with **O1–O2**: native `query` blocks are checked offline.
3. **O3–O7** for the native kind, then a release. Graylog native rules are usable end to end.
4. **L3–L5**, then the `sigma` kind in opentide. Sigma for Graylog, and HarfangLab Sigma checking, ship in the release after.

## Drawbacks

- **opentide owns a Sigma converter.** Getting Sigma semantics right on Graylog is now opentide's job, including case folding, escaping, and CIDR. The golden fixtures and the live semantic harness exist to keep that honest. Graylog Security's own converter would have been less code, but V24 and V27 rule it out as a deploy path.
- **Regex-heavy queries.** Case-insensitive matching on keyword fields compiles to regex with leading `.*`. That is about as costly as a leading wildcard, and OpenSearch scans the field's terms. It is also the only correct form on default Graylog mappings (V7–V9). Tenants with lower-cased (`loweronly`) GIM fields can declare them `lowercase` in `field_types`, and the compiler then emits lower-cased terms instead.
- **Field mapping is tenant work.** Sigma field names rarely match a Graylog pipeline's. The bundled `gim` mapping covers Illuminate-parsed data. Every other pipeline needs `field_overrides`.
- **Graylog's own Sigma view is not used.** Definitions deployed from `sigma` blocks are `aggregation-v1`, not `sigma-v1`. Graylog Security shows them as Filter & Aggregation. Their `tactics_techniques` still reach alerts and the MITRE coverage view.
- **No cross-rule Sigma correlation in 1.0.** Count-style correlations are expressible with `aggregation`. Temporal correlations wait for a cross-rule model.

## Alternatives

- **Deploy through Graylog Security's Sigma import** (`/sigma/import/bulk/upload`). Rejected: it needs a Security licence (V24); it returns the definition name, not its id, so deploy would have to list to bind; 7.2 has no update path; and it refuses `windash`, `null`, `''`, and the encoding modifiers, 233 file-level uses in SigmaHQ. It could come back as an opt-in delivery if Graylog returns ids and supports updates.
- **Write `sigma-v1` definitions directly.** Rejected: `parsed_rule` is Graylog's internal Java model (V27), with no public contract.
- **Convert with pySigma's Lucene backend at deploy.** Rejected: it emits leading wildcards and case-sensitive terms that Graylog refuses or mismatches (V7, V8). Converting in Python would also keep the compiler out of the editor and out of offline validation. pySigma remains the oracle for parsing.
- **Deterministic client-assigned ids** (an ObjectId derived from `metadata.uuid`, which would make Graylog stateless like Sentinel). Graylog accepts a client `id` (V22), but a create with an id that exists corrupts the definition. The behaviour is undocumented and destructive. Rejected.
- **Find definitions by the `opentide.<uuid>` tag.** Rejected: [deployment-state](../specs/deployment-state.md) forbids rediscovery, and tags exist only from 7.2.
- **Content packs.** Rejected as the deploy path. A change means uninstall and reinstall, which gives every definition a new id; in-place upgrades are reachable only from closed-source Illuminate code [src]. A content-pack export could be a later, separate feature.
- **Two platforms** (`graylog` for queries, `graylog_sigma` for Sigma). Rejected: everything except the query is shared, and one rule would need two blocks to switch kinds.
- **Sigma metadata in the block.** Rejected: title, level, and ATT&CK would be written twice and could drift. The quick fix makes moving a SigmaHQ rule in a one-step edit.
- **Wildcard queries with `allow_leading_wildcard`.** Rejected as the default: it needs a server setting Graylog advises against, and wildcards are still case-sensitive. A tenant that enables it gets native `query` leading wildcards. The compiler still emits regex, which is correct either way.

## Unresolved questions

- **Graylog Security behaviour.** Not tested, for lack of a licence: whether Security's `TacticsTechniquesValidator` refuses technique or tactic ids missing from its own MITRE data (TA0112 *Defense Impairment* is recent), and what a Security tenant shows for `aggregation-v1` definitions in its MITRE coverage view. Confirm on a trial licence before the Graylog spec is accepted.
- **Graylog's field map as a mapping source.** `field_mapping = "lookup"` could read the tenant's `core-sigma-field-map` lookup table at deploy, matching what Graylog Security itself uses. Offline validation could not see it. Is a deploy-time mapping acceptable?
- **The bundled `gim` mapping's provenance.** Graylog's own map is closed. opentide's would be built from the GIM schema and the Sysmon and Windows content-pack documentation, then checked against Illuminate-parsed data. Who keeps it current?
- **Graylog 6.x.** 6.x takes a bare create body (6.3: bare body plus a top-level `share_request`) and has no `tags` or `tactics_techniques`. Supporting it is a small client branch. Is it in scope, given Graylog's support window for 6.x?
- **HarfangLab Sigma form.** Move `platform::harfanglab` to the `SigmaDetection` form (a new key beside the decomposed `sigma`), or keep only checking the assembled form?
- **Sigma as a hunt language.** `opentide query --language sigma` against any platform with a compiler target. Out of scope here, and natural once a second target exists.
- **Cross-rule Sigma correlation.** The cross-object model in [A.7](#a7-correlation-and-filter-rules), and which Graylog type (`correlation-v1`, Enterprise) temporal correlations would use.
- **Scheduling defaults.** Is `5m`, with `window` equal to `every`, the right default?

## References

- Graylog: [event definitions](https://go2docs.graylog.org/current/interacting_with_your_log_data/event_definitions.html); [search syntax](https://go2docs.graylog.org/current/making_sense_of_your_log_data/search_syntax_reference.htm); [access tokens](https://go2docs.graylog.org/current/setting_up_graylog/rest_api_access_tokens.htm); [upgrade to 7.2](https://go2docs.graylog.org/current/upgrading_graylog/upgrade_to_graylog_7.2.htm); [manage Sigma rules](https://go2docs.graylog.org/current/what_more_can_graylog_do_for_me/manage_sigma_rules.htm); [Sysmon content pack](https://go2docs.graylog.org/illuminate-current/content_packs/sysmon_content_pack.html); [pricing](https://www.graylog.org/pricing); [SMB licence retirement](https://community.graylog.org/t/smb-license-program-retiring-dec-31-2025-updated/36402)
- graylog2-server (tag `7.2.2`): `org/graylog/events/rest/EventDefinitionsResource.java`, `org/graylog/events/processor/EventDefinitionDto.java`, `org/graylog/events/processor/aggregation/AggregationEventProcessorConfig.java`, `org/graylog/plugins/views/search/rest/QueryValidationResource.java`, `org/graylog2/indexer/template/IndexMapping.java`, `org/graylog/schema/*Fields.java`, `UPGRADING.md`
- Sigma: [sigma-specification](https://github.com/SigmaHQ/sigma-specification) v2.1.0 (rules, modifiers, taxonomy, correlation, filters); [pySigma](https://github.com/SigmaHQ/pySigma) 2.1.0; [SigmaHQ rules](https://github.com/SigmaHQ/sigma) (DRL 1.1); [rsigma](https://github.com/timescale/rsigma); [pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch); legacy sigmac `tools/sigma/backends/graylog.py`
- opentide: [RFC 0015](0015-yara-language.md), [RFC 0016](0016-bitdefender-gravityzone-platform.md), [RFC 0014](0014-sysdig-falco-platform.md), [RFC 0010](0010-deployment-external-ids.md), [RFC 0007](0007-elastic-security-platform.md); [harfanglab-1.0](../specs/platforms/harfanglab-1.0.md); [deployment-state](../specs/deployment-state.md)

## Appendix: reproducing the Graylog tests

The verification stack runs on one machine with Docker and 4 GB of memory:

```yaml
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
    image: graylog/graylog:7.2.2          # graylog-enterprise:7.2.2 for the licence gates (V24)
    depends_on: [mongodb, opensearch]
    entrypoint: /usr/bin/tini -- wait-for-it opensearch:9200 -- /docker-entrypoint.sh
    environment:
      - GRAYLOG_PASSWORD_SECRET=<at least 16 characters>
      - GRAYLOG_ROOT_PASSWORD_SHA2=<sha256 of the admin password>
      - GRAYLOG_HTTP_EXTERNAL_URI=http://127.0.0.1:9000/
      - GRAYLOG_ELASTICSEARCH_HOSTS=http://opensearch:9200
      - GRAYLOG_MONGODB_URI=mongodb://mongodb:27017/graylog
    ports: ["9000:9000", "12201:12201"]
```

Steps:

1. Create a global GELF TCP input on 12201.
2. Send events as null-terminated GELF JSON.
3. Probe with `GET /api/search/universal/relative` (hit counts), `POST /api/search/validate`, and the event-definition endpoints.

Every V-row in [Verified on Graylog 7.2.2](#verified-on-graylog-722) is one such probe. The same stack is the CI harness in [C.5](#c5-conformance-and-test-plan).
