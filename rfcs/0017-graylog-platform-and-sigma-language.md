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

A `graylog` block is one Graylog **event definition**. It holds exactly one of two kinds:

- `query`, a **native Graylog rule**: a Graylog search query, deployed as a Filter & Aggregation event definition (`aggregation-v1`). That type is in every Graylog edition, Open included.
- `sigma`, a **Graylog Sigma rule**: a Sigma detection that deploy delivers through **Graylog's own Sigma support**. opentide assembles a complete Sigma document from the block and the opentide rule's metadata. It uploads the document to Graylog Security's Sigma import (`/plugins/org.graylog.plugins.securityapp.sigma/sigma/import/bulk/upload`). **Graylog converts it** and creates a Sigma event definition (`sigma-v1`). opentide does not convert Sigma. Graylog's converter, field mapping, and Sigma semantics apply, as they do for a rule imported in Graylog's interface. This kind needs a Graylog Security licence and Graylog 7.2 or later.

After creation, both kinds are managed through the event-definition API, as Graylog 7.2 prescribes for Sigma: *"After a Sigma rule is imported as an event definition, all management is handled directly on the event definition."* Graylog assigns each definition a 24-hex ObjectId, which lives in [deployment state](../specs/deployment-state.md).

Graylog has a real check for each kind:

- `POST /api/search/validate` for a query;
- `POST …/sigma/import/validate` for a Sigma document.

Graylog therefore joins the `--live` allowlist. Offline, the engine checks native queries with a Graylog dialect of its Lucene parser. It checks Sigma against the new Sigma language and a `graylog` profile built from Graylog's documented Sigma support.

The native kind was tested end to end on a live **Graylog 7.2.2** (Enterprise build without a licence) on 2026-11-11 ([V-rows](#verified-on-graylog-722)). The Sigma kind is built from the 7.2.2 API surface: the server's OpenAPI document, class and field names in the enterprise plugin jar, and Graylog's documentation ([S-rows](#graylog-sigma-import-722)). It could not run end to end without a Security licence. Every S-row is marked for confirmation on a licensed tenant before this RFC is accepted.

The change is additive. It adds `configurations.graylog`, a `graylog` deployment-state platform, a language spec, and diagnostics. It changes no existing block.

## Motivation

Graylog is a widely deployed log management platform and SIEM. Graylog Open is free, and Graylog Security is its paid SIEM edition. opentide cannot reach it today. Teams keep Graylog event definitions and Sigma imports in the web interface, with no review, no objectives, and no lifecycle.

Sigma is the vendor-neutral detection format most detection engineers already write, and Graylog Security imports it natively. A detection-as-code workflow for Graylog therefore needs both:

- native event definitions, for Graylog-specific logic and every edition;
- Sigma rules, delivered the way Graylog itself supports them, so Graylog's converter, field mapping, Sigma views, and Threat Coverage treat them as Sigma rules.

opentide models Sigma today only as HarfangLab's decomposed `sigma` block. That block is never checked ("Sigma is not checked", [harfanglab-1.0](../specs/platforms/harfanglab-1.0.md)), and it cannot express keyword searches, lists of maps, or `1 of` conditions. A Sigma language spec gives both platforms one Sigma model and one checker.

## Research

Sources are labelled:

- **[live]** tested on Graylog 7.2.2, 2026-11-11;
- **[src]** read in `Graylog2/graylog2-server` (tag `7.2.2`, and `master` at `c4f3025`);
- **[doc]** Graylog documentation, upgrade notes, or changelog;
- **[jar]** a class, method, field, annotation, or string constant in the 7.2.2 `graylog-plugin-enterprise` jar, read with `javap` (names, signatures, and constants only, never decompiled logic);
- **[api]** the running server's OpenAPI document (`GET /api/openapi.json`, 1,018 paths);
- **[spec]** the Sigma specification v2.1.0 (`SigmaHQ/sigma-specification` at `ba9251a`).

### Verified on Graylog 7.2.2

The test stack was `graylog/graylog-enterprise:7.2.2`, `opensearchproject/opensearch:2.19.2`, and `mongo:7.0` in Docker, with no licence installed. Events came in through a GELF TCP input.

| # | Finding | Consequence for the design |
|---|---------|----------------------------|
| V1 | `POST /api/events/definitions` takes `{"entity": <dto>, "share_request": …}`. A bare DTO is refused: `entity cannot be null` (400). `PUT` takes the bare DTO. | The client wraps creates only. 7.0 is the minimum version for native rules. |
| V2 | The create response shows `state: DISABLED`, but a later `GET` shows `ENABLED` when `?schedule=true`. | Deploy never reads `state` from a create response. |
| V3 | `PUT` without `?schedule=false` **re-enables** a disabled definition. `PUT ?schedule=false`, `PUT /{id}/unschedule`, and `PUT /{id}/schedule` each set the state. | Every `PUT` carries an explicit `?schedule=`. |
| V4 | `GET` or `PUT` on a missing id returns 404. **`DELETE` on a missing id returns 204.** `DELETE` on an existing id returns 204, or 200 with the body. | A delete is idempotent. Update-on-404 recreates. |
| V5 | The query is **not parsed at save**. A create with `Image:(foo`, `Image:*cmd.exe` (leading wildcard), an unknown field, or an empty query returns 200. The definition then fails or matches nothing at run time. | Deploy MUST check a native query before it saves. |
| V6 | `POST /api/search/validate` returns `status` (`OK`, `INFO`, `WARNING`, `ERROR`) and `explanations` with `error_type`, a message, and line/column positions. It reports `QUERY_PARSING_ERROR` (ERROR) for syntax errors and for a leading wildcard, `UNKNOWN_FIELD`, `INVALID_OPERATOR` for lower-case `and`/`not`, and `INVALID_VALUE_TYPE` (`event_code:>=abc`, "Type of event_code is long"), all three WARNING. It needs no licence. | A real tenant check for native queries: Graylog joins `--live`. |
| V7 | Field names are case-sensitive (`image:` finds nothing). Values of ordinary string fields are case-sensitive keywords. `message` and `source` match case-insensitively. | Native queries match case-sensitively. Graylog's Sigma converter inherits this ([Graylog and Sigma](#graylog-and-sigma)). |
| V8 | `Image:*cmd.exe`, `CommandLine:*-enc*`, and `CommandLine:*urlcache*` fail: "'*' or '?' not allowed as first character" (`allow_leading_wildcard_searches` is false by default). `CommandLine:certutil*urlcache*` works. | A leading wildcard in a native query is an error unless the tenant allows it. |
| V9 | Regex works on keyword fields and is **anchored**: `Image:/.*\\cmd\.exe/` matches, and `Image:/C:.Windows.System32.cmd\.exe/` matches the whole value. Per-letter classes give case-insensitive matching: `Image:/.*\\[Cc][Mm][Dd]\.[Ee][Xx][Ee]/` matched `cmd.exe` and `CMD.EXE`. | The engine's hover and quick fixes offer this form for case-insensitive native matching. |
| V10 | In both terms and regex, `\\` in the query text is one literal backslash. `\\\\` matches nothing, with no error. | A diagnostic for doubled backslashes in native queries. |
| V11 | Lucene regex operators are on: unescaped `#`, `&`, `<…>`, and `~` change the meaning. `/.*f~g.*/` matched 2 documents, the escaped form 1. `/.*a#b.*/` matched 0, the escaped form 1. `/search/validate` returns OK for all but `<…>`. | `graylog_regex_operator` (warning) in native queries. |
| V12 | `(?i)` matches nothing. `\b` and lookahead `(?=…)` **silently match nothing**. `\d`, `\w`, `\s`, `{n,m}`, and lazy `*?` work. `.` matches a newline. | `graylog_regex_unsupported` (error) in native queries. |
| V13 | Numeric interval syntax works in regex: `DestinationIp:/172\.<16-31>\.<0-255>\.<0-255>/` matches `172.20.5.9`, and `<32-63>` does not. A bare CIDR (`source_ip:10.0.0.0/8`) is a parse error. A quoted CIDR matches nothing on a dynamically mapped (keyword) field. | Hover guidance for CIDR in native queries. |
| V14 | An empty string field (`OriginalFileName: ""`) is not stored by the GELF input: `_exists_` finds 0 documents, and `field:""` finds 0. | Agrees with Graylog's refusal of Sigma `''` ([S8](#graylog-sigma-import-722)). |
| V15 | `_exists_:f`, `NOT _exists_:f`, `f:4625`, `f:>=4625`, `f:[100 TO *]`, and unqualified phrases (`"sekurlsa::logonpasswords"`, which searches every field) all work. | Native syntax the dialect accepts. |
| V16 | Event-definition `tags` refuse `opentide:<uuid>` ("may only contain lowercase letters, digits, hyphens, underscores, and dots"). Upper case is accepted and lower-cased. | The audit tag is `opentide.<uuid>`. It is also a valid Sigma tag. |
| V17 | `tactics_techniques` refuses `FOO` ("Expected format: TA0000, T0000, or T0000.000") and accepts and upper-cases `t1059`. A fired alert carries the definition's `tactics_techniques`. | ATT&CK goes on the definition and reaches every alert. |
| V18 | `priority` is not range-checked (0 and 5 are stored). | opentide maps severity itself and sends 0–4 only. |
| V19 | Titles of native definitions are not unique: two definitions with one title are both created. An empty title is refused. | No name conflict for native rules. Sigma titles are unique ([S5](#graylog-sigma-import-722)). |
| V20 | `execute_every_ms` and `search_within_ms` must be greater than 0, with no minimum (1 s is stored). A 5-field cron is refused ("expect one of [6, 7]"). `key_spec` must name `field_spec` keys. Unknown JSON properties are refused (400, "Unable to map property"). | Static constraints mirror these. |
| V21 | `_scope` is taken from the create body. `ILLUMINATE` and `GRAYLOG_IMMUTABLE_SCOPE` definitions refuse `PUT` ("Immutable entity cannot be modified", HTTP 500). `GRAYLOG_IMMUTABLE_SCOPE` and `GRAYLOG_NONDELETEABLE_SCOPE` refuse `DELETE`. A client can create a definition it can never edit or delete again. | Deploy always sends `_scope: DEFAULT`. |
| V22 | **A client-supplied `id` on create is honoured** (`0123456789abcdef01234567` was stored). A second create with an id that exists returns 200, after which the definition is **gone (404)** and its scheduler trigger is in a permanent ERROR state. | Client-chosen ids are unsafe. Graylog is state-backed with server-assigned ids. |
| V23 | A filter definition fired one alert per matching message, with the definition's priority, `tactics_techniques`, and templated event fields. An aggregation definition (`group_by: [source_ip]`, `count() >= 5`) fired one alert per source, with the key. Overlapping windows (`search_within` > `execute_every`) and the first run after an update repeated alerts for the same messages. | The default window equals the interval. Overlap is a warning. |
| V24 | Sigma import and validation (`…/sigma/import/validate`, `…/sigma/import/bulk/upload`) return **402 "A valid Security license was not found."** | The `sigma` kind needs Graylog Security. Deploy checks for it per tenant. |
| V25 | `GET /api/events/entity_types` lists `aggregation-v1`, `correlation-v1`, `sigma-v1`, `sigma-correlation-v1`, `anomaly-v1`, and others, and the 12 aggregation functions `avg card count max min stddev sum sumofsquares variance percentage percentile latest`. | The aggregation grammar uses exactly these functions. |
| V26 | `POST /api/search/messages` (the scripting API) returns `schema` and `datarows` for a query, time range, and field list. A `POST` without `X-Requested-By` is refused (400, "CSRF protection header is missing"). | The `opentide query` runner, and a required header. |
| V27 | A `sigma-v1` config needs `parsed_rule`, Graylog's internal Sigma AST (`SigmaDetectionRule`: `logSource`, `detection.condition` as a list, `detection.searches`). Hand-written configs fail with Java deserialisation errors. | A `sigma-v1` definition is created only by Graylog's import, never by `POST /api/events/definitions`. |
| V28 | `GET /api/events/definitions/paginated?query=tags:opentide.<uuid>` returned exactly the definition with that tag, and not one tagged `opentide.<uuid'>` that differs in its last two characters. `tags:opentide` returned every definition with that tag. | The exact-tag query used to bind a Sigma import ([B.8](#b8-deploy)). |

### Event definitions

The resource is `org/graylog/events/rest/EventDefinitionsResource.java` [src]. It is annotated `@PublicCloudAPI`, so Graylog Cloud documents it too.

| Method and path | Use in opentide |
|-----------------|-----------------|
| `POST /api/events/definitions?schedule=<bool>` | create a native rule (V1, V2) |
| `PUT /api/events/definitions/{id}?schedule=<bool>` | update either kind; enable, disable (V3) |
| `PUT /api/events/definitions/{id}/schedule`, `/unschedule` | enable, disable without a body |
| `DELETE /api/events/definitions/{id}` | delete either kind (V4) |
| `GET /api/events/definitions/{id}` | read before a Sigma update ([B.8](#b8-deploy)) |
| `GET /api/events/definitions/paginated?query=tags:<tag>` | **only** to bind a Sigma import ([B.8](#b8-deploy), V28) |
| `POST /api/search/validate` | pre-save check and `validate query --live` for native rules (V5, V6) |
| `POST /api/search/messages` | `opentide query` (V26) |
| `GET /api/system`, `GET /api/events/entity_types` | version, and Sigma availability, once per tenant per run |
| `POST /api/events/definitions/{id}/execute` | **not used**: it creates real events and notifications [src] |

`EventDefinitionDto` fields (7.2) [src][live]:

- Required: `title` (non-empty), `description` (non-null), `priority` (int), `alert` (bool), `config`, `field_spec`, `key_spec`, `notification_settings` (`grace_period_ms`, `backlog_size`), and `notifications` (`[{notification_id}]`).
- Optional: `remediation_steps` (6.0+), `event_procedure` (6.2+, a Security feature), `event_summary_template` (7.1+), and `tags` and `tactics_techniques` (7.2+, at most 64 each).
- Read-only or set by the server: `id`, `_scope`, `_entity_source`, `state`, `updated_at`, `matched_at`, `scheduler`, and `storage`, which is forced to the "All events" stream.

`aggregation-v1` config [src][live]: `query`, `query_parameters`, `filters`, `streams` (empty means every stream the user may read), `stream_categories` (6.1+), `group_by`, `series` (`[{id, type, field?}]`), `conditions.expression` (a tree of `expr` nodes; a `number-ref` names a series `id`), `search_within_ms`, `execute_every_ms`, `use_cron_scheduling`, `cron_expression`, `cron_timezone` (6.1+), and `event_limit`. A filter-only definition needs `event_limit` from 1 to `event_definition_max_event_limit` (default 1,000).

Priority meanings come from the web interface's `EventDefinitionPriorityEnum` [src]:

- up to 6.1: 1 low, 2 normal, 3 high;
- 6.2 adds 4 critical;
- 7.1 adds 0 info.

Graylog 7.2 maps Sigma levels the same way: informational 0 … critical 4 [doc, UPGRADING-7.2.0].

Licensing [doc]:

- Open: filter and aggregation definitions, and notifications.
- Enterprise: correlation (`correlation-v1`), search filters, and parameters.
- Security: Sigma, anomaly detection, event procedures, and the Threat Coverage view.

The free Enterprise ("SMB") licence was retired on 31 December 2025.

### Graylog search syntax

The query goes unchanged to OpenSearch or Elasticsearch `query_string`, with only `allow_leading_wildcard` set from `allow_leading_wildcard_searches` [src: `OpenSearchBackend.translateQueryString`]. The default operator is OR, and the default field is all fields. `AND`, `OR`, and `NOT` must be upper case (V6).

Field types [src: `IndexMapping`; V7]:

- `message` and `full_message` are analysed text;
- `source` is a lower-cased keyword;
- every other dynamic string field is an exact, case-sensitive keyword.

Illuminate's index templates type some GIM fields differently (`loweronly` normaliser, `ip`) [doc]. The server's own syntax check is Lucene's classic `QueryParser`. Unknown-field and type checks need the tenant's streams and data (V6) [src].

### Graylog and Sigma

- **Edition.** Sigma rules need a Graylog Security licence [doc; V24].
- **7.2 model** [doc: upgrade to 7.2]:
  - "Sigma rules are now folded into event definitions, and the first-order Sigma rule entity no longer exists."
  - "You can create Sigma rule event definitions by either a file upload or a configured Git repository import."
  - "Manual modification of Sigma rule source YAML is no longer supported."
  - "After a Sigma rule is imported as an event definition, all management is handled directly on the event definition."
  - The `/sigma/rules/*` endpoints were deleted ("use the event definition API to manage").
  - Correlation rules "can no longer be directly imported". For `event_count` and `value_count`, Graylog's advice is to import the base rules and add aggregation to the resulting definitions.
  - The 7.2.0 changelog adds "view, edit, and delete Sigma-based event definitions directly from the Event Definitions page".
- **Converter.** Graylog's own Java code (`SigmaQueryBuilder`, `SigmaDetectionRuleParser`) [jar]. Its documented support [doc: *Create or Add a Sigma Rule*]:
  - Modifiers: `contains`, `all`, `endswith`, `startswith`, and `re`.
  - Not supported: `''` and `null` values; `base64`, `base64offset`, `utf16le`, `utf16be`, `utf16`, `wide`, and `windash`; `1/all of them`; pipes and aggregations; multi-document YAML; and `aliases`.

  The jar agrees: those encoding names appear as constants beside "Searches contain unsupported modifiers", "Empty field values are not supported", and "Conditions with aggregations are not supported". `cidr`, `exists`, `fieldref`, `expand`, `cased`, `neq`, the numeric modifiers, and the time modifiers have no constant at all [jar].
- **Field mapping.** An Illuminate lookup table, `core-sigma-field-map`, maps Sigma field names to GIM fields. A field it does not map is used as written [jar; doc]. The tenant owns this mapping. opentide does not change it.
- **Known gaps.**
  - graylog2-server#27742 is titled "Sigma import translates field values as case-sensitive exact terms (Sigma matching is case-insensitive)" [doc].
  - 7.0.13, 7.1.9, and 7.2.0 changed how plain values and regex values with quotes are generated [doc: changelog].

  These are Graylog's semantics. A `sigma` block gets them, as a rule imported in Graylog's interface does.

### Graylog Sigma import (7.2.2)

The resource is `SigmaRuleImportResource` at `/plugins/org.graylog.plugins.securityapp.sigma/sigma/import`, licence-gated [jar][api]. These rows were **not run end to end**: every call returned 402 without a licence (V24). Each one is to be confirmed on a licensed tenant ([Unresolved questions](#unresolved-questions)).

| # | Fact | Source | Consequence |
|---|------|--------|-------------|
| S1 | `POST …/import/bulk/upload` is `multipart/form-data` with parts `files` (one or more YAML files) and `request`: a JSON `CreateEntityRequest<BulkUploadEntity>`, i.e. `{"entity": {"file_overrides": {<file name>: <SharedOverrides>}}, "share_request": …}`. It needs `eventdefinitions:create`. Accepted media types are `application/yaml`, `application/x-yaml`, `application/yml`, `application/x-yml`, `text/yaml`, and `application/zip`. | [jar] annotations and constants; [api] | The deploy request ([B.8](#b8-deploy)). |
| S2 | `SharedOverrides`: `streams`, `stream_categories`, `notifications`, `search_within_ms`, `execute_every_ms`, `use_cron_scheduling`, `cron_expression`, `cron_timezone`, `filters`, `event_procedure_id`, `event_summary_template`, and `enabled`. | [api] schema; [jar] | The block fields an upload can set. The rest need a `PUT` after import. |
| S3 | Upload refuses: no stream selected ("At least one stream must have been selected."); an unknown stream or notification id; an interval ≤ 0; `execute_every` below `sigma_min_execution_interval`; `search_within` above `sigma_max_search_interval`. Streams need `streams:read` (403 otherwise). | [jar] constants | Static and deploy constraints for `sigma` blocks. |
| S4 | Per file, the import parses the YAML, reads the Sigma `id`, and looks up an existing definition by `config.sigma_rule_source_id`. If one exists, the result is `skipped` and **nothing is updated**. Otherwise it builds the definition, with `attack.*` tags going to `tactics_techniques` and other tags going to `tags`, and the Sigma `fields` becoming event fields. It then creates the definition scheduled if `enabled`, and unscheduled otherwise. | [jar] call sequence; [doc] for the tags | Sigma `id` = `metadata.uuid`: Graylog's key is opentide's key. A Sigma logic change cannot be a re-upload. |
| S5 | "A Sigma Rule already exists with id [%s] or title [%s]. Please specify different values." Lookups exist by `config.sigma_rule_source_id` and by `config.parsed_rule.title`. | [jar] | Sigma titles are unique per tenant: `graylog_sigma_title_conflict`. |
| S6 | The response is `{results: [{source_name, status: created\|skipped\|failed, event_definition_name, error}], success_count, failure_count}`. `SigmaImportResult` holds an `eventDefinitionId()`, but **it is not serialized** (no `@JsonProperty`, absent from the OpenAPI schema). | [jar]; [api] | The created id is not in the response. Deploy binds it with one exact-tag query (V28, [B.8](#b8-deploy)). |
| S7 | `POST …/import/validate` is multipart (`files`), "No data changed, simple validation endpoint before yaml upload." It returns `{results: [{file_name, errors: [..], is_temporal}]}`. It needs `eventdefinitions:create`. | [jar] annotations | The tenant check for `sigma` blocks: `validate query --live` and the pre-upload check. |
| S8 | Sigma parser messages: "Missing required field…", "Field '%s' must be a string between 1 and 256 characters long", "Unrecognized Sigma rule type", "Conditions with aggregations are not supported", "Searches contain unsupported modifiers: %s", "Empty field values are not supported", and a maximum rule length (`sigma_max_rule_length`). Dates use `yyyy-MM-dd`. Levels are `INFORMATIONAL` … `CRITICAL` (plus `UNKNOWN`). Statuses are `STABLE`, `TEST`, `EXPERIMENTAL`, `DEPRECATED`, and `UNSUPPORTED`. | [jar] | The `graylog` Sigma profile ([A.6](#a6-platform-profiles)). |
| S9 | A `sigma-v1` config carries `sigma_rule_id`, `sigma_rule_source_id`, `parsed_rule`, `query` (the generated query), `imported_at`, the stream and schedule fields, and `group_by`, `series`, `conditions`, and `event_limit`. Its validator requires a stream, and series and conditions together. | [api]; [jar] | Aggregation on a Sigma definition is a `PUT` of these fields, as Graylog's 7.2 notes advise for count correlations. |
| S10 | Git repositories: `…/sigma/repositories` (create `{uri, name, branch, directories, access_token}`; list; `PUT /refresh/{id}`; `PUT /import_all`; delete), with permissions `sigma_repository:*`. `SigmaImportService.updateRepoEventDefinition` refreshes a repo-imported definition from the repository's YAML. 7.2.0: "Drop unsupported Sigma rules when a Git repository is synced." | [jar]; [doc] | The only Graylog path that changes Sigma logic in place. An [alternative](#alternatives) delivery. |
| S11 | Before 7.2, Sigma rules were first-order entities with their own CRUD endpoints (`/sigma/rules/...`), deleted in 7.2. | [doc] | The `sigma` kind requires 7.2 or later. |

## Detailed design

### Decisions

1. **One platform, two kinds.** A `graylog` block deploys one event definition. `query` is a native rule (`aggregation-v1`). `sigma` is a Graylog Sigma rule (`sigma-v1`). Streams, schedule, notifications, and event fields are shared at the block root.
2. **Graylog converts Sigma.** A `sigma` block is delivered through Graylog Security's Sigma import, and Graylog's converter and field mapping apply. opentide never turns Sigma into a Graylog query, and never writes `sigma-v1` configs itself (V27).
3. **Sigma is a language, not a Graylog feature.** `specs/languages/sigma-1.0.md` defines the embedded `SigmaDetection`, how a complete Sigma document is assembled from it, its checks, and per-platform profiles. Graylog's profile is Graylog's documented support. HarfangLab is checked under its own profile.
4. **State-backed identity.** The server-assigned ObjectId goes in deployment state for both kinds. Client-assigned ids are rejected (V22). For Sigma, Graylog does not return the id (S6), so deploy binds it once, right after the import, with an exact-tag query. That is a narrow, specified exception to deployment state's no-rediscovery rule ([B.8](#b8-deploy)).
5. **Graylog checks before save.** Native queries go through `/api/search/validate` (V5). Sigma documents go through `…/sigma/import/validate` (S7). Neither is saved when Graylog reports an error.
6. **Versions.** Native rules need Graylog 7.0 or later (V1). Sigma rules need Graylog Security 7.2 or later (S11).

---

## Part A: Sigma language (`language-sigma` 1.0)

Proposed file: `specs/languages/sigma-1.0.md`, with front matter `spec: language-sigma`, `version: "1.0"`, `schema_id: null`, `status: normative`.

### A.1 Summary

Sigma is a detection language that several platforms deploy. This spec defines the Sigma **detection** that a platform block embeds, as a `SigmaDetection`: Sigma's `logsource` and `detection` sections, written as YAML in the block. The opentide rule supplies the metadata. Deploy [assembles](#a8-sigma-document-assembly) a complete Sigma document from the two and sends it to the platform, which runs it with its own Sigma engine. opentide checks the detection offline against the language and the platform's profile. It does not convert Sigma.

The contract is the Sigma specification **v2.1.0**, detection rules only. Correlation and filter rules are not part of 1.0 ([A.7](#a7-correlation-and-filter-rules)).

### A.2 Requirements

- A platform block that deploys Sigma MUST embed a `SigmaDetection` under the key `sigma`.
- `sigma` MUST be a YAML mapping written out in the block. A YAML alias at `sigma` or at `sigma.detection` MUST fail static validation with `sigma_alias`.
- `sigma` MUST NOT carry Sigma rule metadata (`sigma_metadata_key`, [A.3](#a3-sigmadetection)). Deploy derives it from the opentide rule ([A.8](#a8-sigma-document-assembly)).
- Deploy MUST send the assembled document. It MUST NOT rewrite the detection: search identifiers, field names, values, modifiers, and the condition reach the platform as written.
- Static validation MUST report every [error](#a51-errors) as a failure, and every [warning](#a52-warnings) without failing the rule.
- Static validation MUST apply the profile of the platform whose block holds the detection ([A.6](#a6-platform-profiles)). A profile MAY refuse constructs the language allows. It MUST NOT accept a construct the language refuses.

### A.3 `SigmaDetection`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `logsource` | mapping | yes | Sigma `logsource`: `category`, `product`, `service`, `definition`, all optional strings, at least one of the first three set. |
| `detection` | mapping | yes | Sigma `detection`: search identifiers and `condition`. |
| `taxonomy` | string | optional | Sigma `taxonomy`. Default `sigma`. |
| `fields` | list[string] | optional | Sigma `fields`. Graylog turns them into event fields (S4). |
| `falsepositives` | list[string] | optional | Sigma `falsepositives`. |

Every other Sigma top-level key is refused with `sigma_metadata_key`. Each one has an opentide home ([A.8](#a8-sigma-document-assembly)). A SigmaHQ rule is therefore pasted as its `logsource` and `detection`, and its metadata moves to the opentide rule. The language server offers that move as a quick fix ([C.3](#c3-sigma-in-the-engine)).

### A.4 Dialect

The language is Sigma v2.1.0 detection semantics:

- **Search identifiers.** A map ANDs its items. A list of maps ORs them. A list of scalars under no field is a **keyword** search. A key's list of values ORs the values, or ANDs them under `|all`. Identifiers match `[A-Za-z0-9_-]+`.
- **Values.** Strings are case-insensitive unless `|cased`. `*` and `?` are wildcards. `\` escapes `*`, `?`, and `\`, as the spec's escaping table defines. Integers and booleans are typed values. `null` matches a missing field. `''` matches an empty value.
- **Condition.** `and`, `or`, `not`, parentheses, and `1 of`/`any of`/`all of` an identifier, a `*` pattern, or `them` (`them` excludes identifiers that start with `_`). A list of conditions is ORed. Precedence, loosest first: `or`, `and`, `not`, `x of`, parentheses. Pipes (`| count() > 5`, `| near`) are **not** part of the language (`sigma_condition_pipe`).
- **Modifiers.** Every modifier of Sigma 2.1 (`all`, `startswith`, `endswith`, `contains`, `exists`, `cased`, `neq`, `windash`, `re` with `i`/`m`/`s`, `base64`, `base64offset`, `utf16le`, `utf16be`, `utf16`, `wide`, `lt`, `lte`, `gt`, `gte`, `minute` … `year`, `cidr`, `expand`, `fieldref`), plus pySigma's aliases `ignorecase`, `multiline`, and `dotall`. They chain left to right, and each one's input type must fit the output type of the one before (pySigma's type rules).
- **Regex** (`re`): the spec's PCRE subset. Anything outside it is `sigma_regex`.

Whether a platform supports a construct is its profile's business ([A.6](#a6-platform-profiles)), not the language's.

### A.5 Diagnostics

Codes are stable. The language server's `docs/SIGMA.md` maps each one to the clause of the Sigma specification, or to the pySigma check, that proves it.

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
| `sigma_modifier_chain` | a chain whose types do not fit (`\|re\|contains`, `\|i` without `re`, `\|gt` on a string), or a modifier repeated (except `base64`) |
| `sigma_all_single_value` | `\|all` on a single value |
| `sigma_null_in_list` | `null` inside a list of values |
| `sigma_value_type` | a value of the wrong type for its modifiers (`\|exists: "yes"`, `\|cidr: 10.0.0`, `\|gt: abc`) |
| `sigma_regex` | a `re` value that is not a valid regex in the spec's subset |
| `sigma_escape` | a trailing single `\` that escapes nothing at the end of a value |

#### A.5.2 Warnings

| Code | Condition | pySigma equivalent |
|------|-----------|--------------------|
| `sigma_unused_identifier` | a search identifier the condition never reaches | `dangling_detection` |
| `sigma_all_of_them` | `all of them` (the spec discourages it) | `all_of_them_condition` |
| `sigma_them_single` | `1 of them` or `all of them` with one identifier | `them_condition_with_single_detection` |
| `sigma_modifier_combination` | a field-bound `\|all` without `contains`; `base64offset` without `contains`; `windash` with `all` | `invalid_modifier_combinations` |
| `sigma_double_wildcard` | `**` in a value | `double_wildcard` |
| `sigma_wildcard_instead_of_modifier` | `*x*`, `x*`, `*x` where `contains`, `startswith`, or `endswith` says it | `wildcards_instead_of_modifiers` |
| `sigma_number_as_string` | a quoted integer on a field the taxonomy types as a number (`EventID: '4688'`) | `number_as_string` |
| `sigma_control_character` | a control character in a value | `control_character` |
| `sigma_logsource_unknown` | a `category`, `product`, or `service` not in the Sigma taxonomy appendix | — |
| `sigma_field_unknown` | a field name not in the taxonomy for the log source, where the catalogue covers that log source | `fieldname_logsource` |

pySigma 2.1 is the conformance oracle for the language. Every rule of the pinned SigmaHQ corpus that pySigma loads without error MUST produce no `sigma_*` error. Every broken twin ([C.5](#c5-conformance-and-test-plan)) MUST produce the error the twin targets.

### A.6 Platform profiles

| | `graylog` | `harfanglab` |
|---|---|---|
| Delivery | the assembled document, uploaded to Graylog Security's Sigma import; **Graylog converts it** | the assembled document, sent to HarfangLab's Sigma API |
| Block form | `SigmaDetection` | HarfangLab's decomposed `sigma` (unchanged), assembled into a `SigmaDetection` before checking |
| Supported modifiers | `contains`, `startswith`, `endswith`, `all`, `re` (Graylog's documented table) | not published; every language modifier |
| Refused by the platform (error) | `base64`, `base64offset`, `utf16le`, `utf16be`, `utf16`, `wide`, `windash`; `''` and `null` values; `1 of them` and `all of them` | none known |
| Undocumented (warning) | `exists`, `cased`, `neq`, `cidr`, `expand`, `fieldref`, `lt`/`lte`/`gt`/`gte`, time modifiers, `re` sub-modifiers | — |
| Correlation | no (7.2 import refuses it) | no |
| Field names | as written; the tenant's `core-sigma-field-map` maps them in Graylog | as written |
| Title | at most 256 characters, unique among the tenant's Sigma definitions | — |
| Profile codes | `graylog_sigma_unsupported` (error), `graylog_sigma_undocumented` (warning), `graylog_sigma_title` (error) | none in 1.0 |

The `graylog` profile mirrors Graylog's documentation and the 7.2.2 converter's constants (S8). An "undocumented" construct is neither listed as supported nor refused by Graylog. It is a warning offline. Graylog's own verdict comes from `validate query --live` ([B.9](#b9-validation-and-query)). Once a licensed tenant confirms one, it moves to the supported or refused row in a minor revision of the profile.

### A.7 Correlation and filter rules

Sigma correlation rules reference other rules by `id` or `name`. In opentide, that would be a reference from one rule object to others: a cross-object relation the object model does not have yet ([RFC 0011](0011-signal-reuse.md) is related). Graylog 7.2 does not import correlation rules either (S11). Sigma filter rules tune many rules at once, which is tenant configuration, not a detection.

Neither type is part of `language-sigma` 1.0. A `sigma` block with a `correlation` or `filter` key fails `sigma_metadata_key`. Count-style correlation over one rule is the block's [`aggregation`](#b2-block-fields), applied the way Graylog's 7.2 notes describe: on the imported definition (S9).

### A.8 Sigma document assembly

Deploy builds one Sigma YAML document per block. HarfangLab's existing builder follows the same rules once it adopts this spec.

| Sigma key | Value |
|-----------|-------|
| `title` | The block `name`, else the rule `name`. Whitespace collapsed. |
| `id` | `metadata.uuid` |
| `status` | `stable` for a block status whose strategy is `RELEASE` or `UNIVERSAL`; `test` for `PREVIEW`; `experimental` otherwise |
| `description` | The rule `description`, whitespace collapsed |
| `references` | The rule's references, when it has any |
| `author` | The rule's contributors, comma-separated, when it has any |
| `date`, `modified` | `metadata.created`, `metadata.modified`, as `YYYY-MM-DD` |
| `tags` | In order, de-duplicated: `attack.t<id>` for each technique (the rule's own and those inherited through `detection_model`, Enterprise only, lower case); `attack.<tactic-slug>` for each tactic of those techniques (the [Elastic ATT&CK table](../specs/platforms/elastic-1.0.md#attck), slugged as Sigma writes them: `defense-impairment`); the block `tags`; `opentide`; `opentide.<metadata.uuid>`; `opentide.rev.<revision>` |
| `level` | From the rule severity (`response.alert_severity` in `rule::1.0`, `severity` in `rule::1.1`), lower case |
| `logsource`, `detection`, `taxonomy`, `fields`, `falsepositives` | From the block, unchanged |

`<revision>` is the first 12 hex digits of the SHA-256 of the document's canonical JSON (sorted keys, no whitespace), computed without `date`, `modified`, and the revision tag itself. It changes when anything Graylog would store from the document changes. Deploy uses it to tell whether a Sigma definition must be replaced ([B.8](#b8-deploy)).

The document is UTF-8 with LF line endings. Values are quoted where YAML would otherwise retype them. Detection values are emitted exactly as parsed, so a value round-trips byte for byte. Block `tags` MUST match Sigma's tag pattern `^[a-z0-9_-]+\.[a-z0-9._-]+$` (`sigma_tag`).

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
    streams: [sysmon]                   # tenant aliases; required for sigma
    schedule:
      every: 5m
    notifications: [soc-slack]          # tenant aliases
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
          CommandLine|contains: ' -enc'
        condition: all of selection_*
      fields: [CommandLine, ParentImage]
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
    event_fields:
      source_ip: ${source.source_ip}
    event_key: [source_ip]
    query: event_code:4625 AND NOT user_name:/.*\$/
```

### B.2 Block fields

| Field | Type | Required | Default | `query` | `sigma` | Description |
|-------|------|----------|---------|---------|---------|-------------|
| `query` | string | conditional | — | ✓ | — | A Graylog search query ([B.7](#b7-graylog-query-dialect)). Non-blank. |
| `sigma` | [`SigmaDetection`](#a3-sigmadetection) | conditional | — | — | ✓ | A Sigma detection, delivered to Graylog's Sigma import |
| `priority` | string | optional | [derived](#b4-derived-fields) | create | PUT | `Informational`, `Low`, `Medium`, `High`, or `Critical` |
| `alert` | boolean | optional | `true` | create | PUT | `false` makes fired events plain events, not alerts |
| `tags` | list[string] | optional | `[]` | create | document | Added to the [derived tags](#b4-derived-fields). On `sigma`, Sigma tags (`sigma_tag`). |
| `streams` | list[string] | `sigma`: yes | tenant `streams` | create | upload | Aliases from the tenant's `stream_ids` table |
| `stream_categories` | list[string] | optional | `[]` | create | upload | Graylog stream categories (6.1+), as written |
| `schedule` | [Schedule](#schedule) | optional | `{every: 5m}` | create | upload | When the definition runs and what it searches |
| `event_limit` | integer | optional | `100` | create | PUT | Filter only: at most this many events per run, 1–1,000 |
| `aggregation` | [Aggregation](#aggregation) | optional | null | create | PUT | Turns the filter into an aggregation |
| `event_fields` | map | optional | `{}` | create | PUT | Event field name → template string, or `{lookup: {table, key_field}}`. On `sigma`, added to the fields Graylog derives from Sigma `fields`. |
| `event_key` | list[string] | optional | `[]` | create | PUT | Event fields that make up the event key |
| `notifications` | list[string] | optional | `[]` | create | upload | Aliases from the tenant's `notification_ids` table |
| `grace_period` | duration | optional | `0s` | create | PUT | Per event key |
| `backlog` | integer | optional | `0` | create | PUT | Messages attached to a notification (`backlog_size`), 0 or more |
| `summary` | string | optional | null | create | upload | Event summary template (7.1+) |
| `remediation` | string | optional | null | create | PUT | Remediation steps |

The kind columns say how each field reaches Graylog:

- **create**: in the native create body;
- **upload**: in the Sigma import's `file_overrides` (S2);
- **document**: in the assembled Sigma document ([A.8](#a8-sigma-document-assembly));
- **PUT**: in an event-definition `PUT` right after the import ([B.8](#b8-deploy)).

The shared `name` is the definition title (native) or the Sigma `title` (Sigma). `status` is required, as on `elastic`, `sysdig`, and `bitdefender`.

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

These are the 12 functions of V25. Deploy sends one series for each distinct call, with id `<function>-<field>` (`count-` for `count()`, the form V23 used). The expression becomes Graylog's `expr` tree: `&&`, `||`, `!`, the comparison operators, `number-ref`, and `number`.

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
| `graylog_event_key` | Each `event_key` entry is an event field (V20). On `sigma`, a Sigma `fields` entry also counts. |
| `graylog_priority` | `priority` is one of the five names |
| `graylog_field_name` | A field name in `query`, `group_by`, or a condition is a valid Graylog field name |
| `graylog_query_syntax` | `query` parses under the [Graylog dialect](#b7-graylog-query-dialect) |
| `graylog_leading_wildcard` | A term in `query` starts with `*` or `?`, and a targeted tenant does not set `allow_leading_wildcard` (V8) |
| `graylog_regex_unsupported` | A regex in `query` uses a construct Lucene RegExp silently fails on: `(?i)` or another inline flag, `\b`, `\B`, lookaround, or a backreference (V12) |
| `graylog_sigma_streams` | A `sigma` block has at least one stream, from the block or the tenant (S3) |
| `graylog_sigma_unsupported` | A construct the [`graylog` profile](#a6-platform-profiles) lists as refused by Graylog |
| `graylog_sigma_title` | The Sigma title is 1–256 characters (S8) |
| `graylog_sigma_title_duplicate` | Workspace check: two enabled `sigma` blocks resolve to one title. Graylog refuses the second (S5). |
| `sigma_tag` | A `sigma` block's `tags` entry does not match Sigma's tag pattern |

A `sigma` block is also checked against [Part A](#a5-diagnostics) under the `graylog` profile.

Advisories (warnings, [validation.md](../specs/validation.md#platform-advisories)):

| Code | When |
|------|------|
| `graylog_overlapping_window` | `window` is longer than `every` on a filter (no `aggregation`). Each message alerts once per overlapping run (V23). |
| `graylog_lowercase_operator` | `and`, `or`, or `not` as a bare term in `query`: Graylog searches the word (V6) |
| `graylog_regex_operator` | An unescaped `#`, `&`, `<`, `>`, or `~` inside a regex in `query`: Lucene reads it as an operator (V11) |
| `graylog_regex_quote` | An unescaped `"` inside a regex in `query` (it matches nothing) |
| `graylog_double_backslash` | `\\\\` in `query`, which matches two backslashes, where the value most likely has one (V10) |
| `graylog_analyzed_field` | A regex, wildcard, or range on `message` or `full_message`, which are tokenised (V7) |
| `graylog_case_sensitive` | A `query` term on a keyword field with letters, not written as a regex or a phrase. Graylog matches it case-sensitively (V7). Reported once per query. |
| `graylog_all_streams` | A native block with no `streams` and no `stream_categories`, on the block or the tenant: the definition searches every stream |
| `graylog_sigma_undocumented` | A construct the `graylog` profile lists as undocumented ([A.6](#a6-platform-profiles)) |
| `graylog_title_duplicate` | Workspace check: two enabled native blocks resolve to one title. Graylog allows it (V19), and the alert list cannot tell them apart. |
| `graylog_priority_collapsed` | `Informational` on a tenant older than 7.1, sent as Low (1) |

### B.4 Derived fields

| Graylog field | Native (`query`) | Sigma (`sigma`) |
|---------------|------------------|-----------------|
| title | shared `name`, else the rule `name` | Graylog, from Sigma `title` |
| description | the rule `description`, whitespace collapsed | Graylog, from Sigma `description` |
| `priority` | `priority`, else from the rule severity: Critical 4, High 3, Medium 2, Low 1, Informational 0 (1 before 7.1) | Graylog, from Sigma `level` (the same table); `priority` overrides it by PUT |
| `tags` (7.2+) | union, de-duplicated: block `tags`, `opentide`, `opentide.<uuid>`, tenant `tags`; each lower-cased, any character outside `[a-z0-9_.-]` replaced by `-`, cut at 128 characters, at most 64 | Graylog, from the non-ATT&CK Sigma tags (S4), which include `opentide`, `opentide.<uuid>`, and `opentide.rev.<revision>` |
| `tactics_techniques` (7.2+) | the rule's techniques and inherited techniques, Enterprise only ([Elastic ATT&CK rule](../specs/platforms/elastic-1.0.md#attck)), then their tactic ids; at most 64 | Graylog, from the `attack.*` Sigma tags |
| query | `query` | **Graylog's converter** |
| streams, schedule, notifications, summary | from the block | upload overrides (S2) |
| `field_spec`, `key_spec` | `event_fields`, `event_key` | Graylog's fields from Sigma `fields`, plus `event_fields` by PUT |
| `notification_settings` | `grace_period`, `backlog` | by PUT |
| `remediation_steps`, `alert`, `event_limit`, aggregation | from the block | by PUT |
| `_scope` | always `DEFAULT` (V21) | as Graylog's import sets it |

`opentide.<uuid>` is for analysts, for audits, and for the one bind after a Sigma import ([B.8](#b8-deploy)). Deploy never uses it to find a native definition.

### B.5 Sigma delivery

A `sigma` block is deployed in Graylog's own Sigma import format:

1. **Assemble** the Sigma document ([A.8](#a8-sigma-document-assembly)) as `<metadata.uuid>.yml`.
2. **Check** it with `POST …/sigma/import/validate` (S7). A non-empty `errors` list fails the rule with `graylog_sigma_invalid` and Graylog's messages. Nothing is uploaded.
3. **Upload** it with `POST …/sigma/import/bulk/upload` (S1):

   ```text
   POST /api/plugins/org.graylog.plugins.securityapp.sigma/sigma/import/bulk/upload
   X-Requested-By: opentide
   Content-Type: multipart/form-data; boundary=…

   files    (application/yaml; filename="00000000-0000-4000-8003-000000000040.yml")
            the assembled Sigma document
   request  (application/json)
            {"entity": {"file_overrides": {"00000000-0000-4000-8003-000000000040.yml": {
               "streams": ["65f0c0ffee0123456789abcd"], "stream_categories": [],
               "notifications": ["65f0c0ffee0123456789abcf"],
               "search_within_ms": 300000, "execute_every_ms": 300000,
               "use_cron_scheduling": false, "cron_expression": null, "cron_timezone": null,
               "filters": [], "event_procedure_id": null, "event_summary_template": null,
               "enabled": true}}},
             "share_request": null}
   ```

4. **Read the result** (S6). `created` continues. `skipped` means a Sigma definition with this `id` exists that opentide has no binding for: the rule fails with `graylog_sigma_unbound`, and deploy does not adopt it. `failed` fails the rule with Graylog's `error`. A duplicate title is `graylog_sigma_title_conflict` (S5).
5. **Bind** ([B.8](#b8-deploy)), then **PUT** the fields the upload cannot carry, if the block sets any: `priority`, `alert`, `event_limit`, `aggregation`, `event_fields`, `event_key`, `grace_period`, `backlog`, `remediation`. The PUT body is the definition as just read with `GET`, with only those fields changed. `config.type`, `parsed_rule`, `query`, `sigma_rule_id`, and `sigma_rule_source_id` are sent back as read.

Graylog stores the converted query in `config.query` (S9). `opentide deploy plan` and the status interfaces show it. Deploy then sends it once to `POST /api/search/validate`, with the definition's streams: `UNKNOWN_FIELD` there usually means a Sigma field that the tenant's field map does not map. It is reported as `graylog_sigma_unknown_field` (warning), with the field name.

### B.6 Tenant setup

```toml
[platform]
enabled = true
identifier = "graylog"
name = "Graylog"
description = "Graylog event definitions: native queries and Graylog Sigma rules."
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
windows-security = "65f0c0ffee0123456789abce"

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
| `tags` | list[string] | no | `[]` | Tags added to every native definition on this tenant |
| `ssl` | bool | yes | — | Shared tenant setup (TLS verification) |

Permissions:

- Native rules: the token's user needs `eventdefinitions:create`, `:read`, `:edit`, and `:delete`, plus `streams:read` on every stream a definition names.
- Sigma rules: the same, on a Graylog Security licence.

A stream or notification alias the tenant does not define fails that rule at deploy (`graylog_alias_unknown`).

The Sigma field mapping is Graylog's (the `core-sigma-field-map` lookup table, Illuminate's). opentide sends field names as written and never changes the tenant's mapping.

### B.7 Graylog query dialect

The engine adds `Dialect::Graylog` to its Lucene `query_string` parser (`opentide-lucene`, beside `Elastic` and `CarbonBlack`). The dialect differs from `Elastic` in four ways:

- A leading wildcard is `graylog_leading_wildcard` (error) unless the tenant allows it.
- A lower-case operator is `graylog_lowercase_operator` (warning), not parsed silently.
- Regex bodies are checked against Lucene RegExp syntax. They are also checked for the silent failures of V10–V12.
- Field names follow Graylog's `Message.validKey`, and a GIM catalogue supplies completion and hover.

`/api/search/validate` is the dialect's oracle: on the conformance corpus, the engine's syntax verdict MUST equal Graylog's `QUERY_PARSING_ERROR` verdict ([C.5](#c5-conformance-and-test-plan)).

### B.8 Deploy

Graylog is **state-backed** for both kinds, like Defender for Endpoint, SentinelOne, CrowdStrike, Sysdig, and Bitdefender:

- **Where.** `platforms.graylog.<tenant>` in `.opentide/states/deployment/<uuid>.json` (`deployment.state::1.0`), one binding per tenant. The tenant key is the configured tenant `name`, whitespace-stripped.
- **Shape.** A 24-hex id, lower-case, matching `^[0-9a-f]{24}$`. The shard schema's existing `objectIdTenants` covers it.
- **No client ids.** Deploy MUST NOT send `id` on a native create (V22).
- **No orphan creates.** As for Bitdefender: `deployment_state_ignored` and `deployment_state_unpersisted` refuse a create or an upload whose id cannot be kept.

Once per tenant per run, deploy reads `GET /api/system` and `GET /api/events/entity_types`:

- A version below 7.0 fails the tenant (`graylog_version_unsupported`).
- A `sigma` block on a tenant below 7.2, or without `sigma-v1` among the processor types, fails that rule (`graylog_sigma_unavailable`, naming the version or the missing licence).
- The version decides which optional fields are sent. A field the version cannot take is left out, with `graylog_field_unsupported_version` (warning).

#### Binding a Sigma import

Graylog creates the definition but does not return its id (S6). Right after an upload that reports `created`, deploy MUST bind the id, as follows:

1. `GET /api/events/definitions/paginated?query=tags:opentide.<metadata.uuid>` (V28).
2. The result MUST contain exactly one definition, with `config.type: sigma-v1` and `config.sigma_rule_source_id` equal to `metadata.uuid`. Deploy confirms both with `GET /api/events/definitions/{id}`.
3. That id is written to deployment state before any other call for the rule.

Zero or several matches fail the rule with `graylog_sigma_bind_failed`, naming the tag, and deploy writes no binding. Deploy MUST NOT use this query for any other purpose, at any other time. In particular, it MUST NOT use it to recover a lost binding, or to find a native definition.

This is an exception to [deployment-state](../specs/deployment-state.md)'s no-rediscovery rule. It is bounded to one call, made only because Graylog withholds an id it has just assigned, and keyed on an identifier opentide chose and Graylog stores. The specifications PR amends `deployment-state.md` to name it. If Graylog serialises `event_definition_id` in the import result, the query is dropped ([Unresolved questions](#unresolved-questions)).

#### Native rules (`query`)

Before each create or update, deploy MUST send the query to `POST /api/search/validate`, with the definition's streams, stream categories, and a relative time range of `window`:

- `ERROR` fails the rule with `graylog_query_invalid` and the explanations. The definition is not saved.
- `WARNING` explanations are reported as warnings: `UNKNOWN_FIELD` is `graylog_unknown_field`, and `INVALID_VALUE_TYPE` is `graylog_value_type`.

| Block status strategy | Binding | Graylog calls |
|-----------------------|---------|---------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | `POST /api/events/definitions?schedule=true` with `{"entity": <dto>, "share_request": null}`; the returned `id` is recorded |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present | `PUT /api/events/definitions/{id}?schedule=true` with the **whole** DTO |
| `DISABLEMENT` | present | `PUT /api/events/definitions/{id}?schedule=false` with the whole DTO |
| `DELETION` | present | `DELETE /api/events/definitions/{id}`; any 2xx (V4) removes the binding |
| `DISABLEMENT`, `DELETION` | none | `external_id_missing` (warning), no call |

The DTO never carries `state`, `storage`, `scheduler`, `updated_at`, `matched_at`, or `_entity_source`. It carries `_scope: DEFAULT`, and, on update, the bound `id`.

#### Sigma rules (`sigma`)

Graylog keeps the Sigma logic it imported and offers no way to change it ("Manual modification of Sigma rule source YAML is no longer supported"; a re-upload of the same `id` is `skipped`, S4). What deploy does with a bound definition therefore depends on the revision tag ([A.8](#a8-sigma-document-assembly)):

| Block status strategy | Binding | Graylog calls |
|-----------------------|---------|---------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | [Sigma delivery](#b5-sigma-delivery): validate, upload with `enabled: true`, bind, PUT |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present, revision unchanged | `GET`, then `PUT …/{id}?schedule=true` with the upload overrides (S2) and the PUT fields ([B.2](#b2-block-fields)) changed; Sigma config fields sent back as read |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present, revision changed | **replace**: validate the new document; `DELETE …/{id}`; remove the binding; then the create path. Reported as `graylog_sigma_replaced` (info). |
| `DISABLEMENT` | present | `PUT …/{id}/unschedule` |
| `DELETION` | present | `DELETE …/{id}`; any 2xx removes the binding |
| `DISABLEMENT`, `DELETION` | none | `external_id_missing` (warning), no call |

The revision is read from the definition's `tags` (`opentide.rev.<revision>`). A definition with no revision tag is treated as changed.

On replace, the new document is validated before the old definition is deleted, so an invalid change leaves the deployed rule in place. Between the `DELETE` and the upload, the rule does not run. If the upload fails after the `DELETE`, the binding is already gone. The rule is reported failed, and the next deploy creates it.

A replaced definition gets a new id. Events that the old one fired keep the old `event_definition_id`.

#### Failure handling (both kinds)

- **Definition gone.** A `PUT` or `GET` answered 404 runs the create path and replaces the binding, with `graylog_definition_recreated` (warning). Under `DISABLEMENT`, deploy creates nothing, removes the binding, and warns `graylog_definition_missing`.
- **Immutable.** "Immutable entity cannot be modified" or "Non-deletable entity cannot be deleted" (V21) fails the rule with `graylog_definition_immutable`. Deploy never changes a scope.
- **In use.** A `DELETE` refused because another definition (a correlation) depends on it fails with `graylog_definition_in_use`, with the dependants' ids. On a Sigma replace, the old definition stays in place.
- **Refused body.** A 400 with `{"errors": {field: [messages]}}`, or an upload `failed`, fails the rule with `graylog_definition_invalid` and the messages.
- **Licence.** 402 on any Sigma endpoint fails the rule with `graylog_sigma_unavailable`.
- **Authorisation.** 401 stops the tenant (`graylog_tenant_unauthorized`). 403 fails the rule (`graylog_forbidden`); it is most often a stream permission.
- **Unconfirmed create.** A native create or a Sigma upload with no answer MUST NOT be retried. For a native create, titles are not unique (V19), so a retry may create a second definition. For an upload, a retry would come back `skipped`. The rule fails with `graylog_create_unconfirmed`, which names the `opentide.<uuid>` tag, so the operator can find the definition in the web interface.

Deploy MUST NOT call `/execute`, MUST NOT write `sigma-v1` configs except by sending back what it read, MUST NOT list definitions outside the Sigma bind, and MUST NOT write to the rule file.

### B.9 Validation and query

| Check | `query` | `sigma` |
|-------|---------|---------|
| `opentide validate` (offline) | block constraints; the Graylog dialect | block constraints; the Sigma language under the `graylog` profile |
| `opentide validate query --live` | `POST /api/search/validate` per tenant, with the block's streams and `window`. `ERROR` is an error; `WARNING` and `INFO` are warnings, with Graylog's positions. | `POST …/sigma/import/validate` per tenant, with the assembled document: Graylog's own verdict on its Sigma support. Each `errors` entry is an error. A tenant without Sigma reports `supported: false`. |
| `opentide query` | `POST /api/search/messages` (5.0+), read-only, language `graylog` | for a bound rule, the deployed definition's `config.query` (Graylog's conversion), through the same endpoint. An unbound rule reports `supported: false`: only Graylog can convert it. |

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
- Hover guidance for the silent cases: case-insensitive matching as letter-class regex (V9), CIDR as interval regex (V13).
- Injection rows in `crates/opentide-tide/src/injection.rs` for `query` and `aggregation.condition`.

### C.3 Sigma in the engine

`opentide-sigma` holds:

- **Parser.** It works on the Tide YAML tree the engine already has, so every diagnostic has a position in the rule file. It covers search identifiers, values, modifier chains, and the condition (through the injected grammar).
- **Checks.** Every `sigma_*` code ([A.5](#a5-diagnostics)), and the profile codes of [A.6](#a6-platform-profiles) for `graylog` and `harfanglab`.
- **Catalogues.**
  - `catalogs/sigma/modifiers.toml`: name, input and output types, aliases, and documentation for each modifier.
  - `catalogs/sigma/taxonomy.toml`: log sources and their fields, from the specification's taxonomy appendix.
  - `catalogs/sigma/profiles.toml`: per platform, its supported, refused, and undocumented constructs.

  Each is generated by a sync script and pinned to a source commit.
- **Assembly.** `assemble_sigma(block, rule) -> str` builds the document of [A.8](#a8-sigma-document-assembly). It is exposed through PyO3 (`opentide._native`, `src/opentide/_native.pyi`), so deploy, `validate query`, and the editor's preview produce the same bytes.

Editor features:

| Feature | Detail |
|---------|--------|
| Diagnostics | `sigma_*` and the profile codes, positioned in the block |
| Completion | modifiers after `\|`, filtered by the chain's current type and marked when the platform's profile does not support them; log-source values from the taxonomy; field names for the log source; identifiers and `1 of`/`all of`/`them` in `condition` |
| Hover | a modifier's meaning, types, and support on the block's platform; a field's taxonomy entry |
| Code actions | "Move Sigma metadata to the rule" for `sigma_metadata_key`; "Show the Sigma document deploy sends" (the assembled YAML) |
| Highlighting | modifiers, identifiers, and condition keywords, through the HighlightSpec |

The engine does not convert Sigma for any platform. Parsing Sigma ourselves rather than depending on rsigma is deliberate. The detection is embedded in a Tide YAML document, and diagnostics need positions in that document. rsigma parses standalone files, and its MSRV (1.96) is above the engine's (1.95). rsigma is a second **differential oracle** in conformance testing.

### C.4 Tide catalogue

The new `GraylogConfig` model adds `configurations.graylog.*` to the generated Tide catalogue. The engine's bundled catalogue therefore goes stale, and `scripts/build/check_engine_catalog.py` fails until three things happen: language-server regenerates it (`scripts/sync_opentide_schemas.py` with the opentide checkout), releases, and opentide bumps the engine pin.

Order of work: specifications; opentide models; the language-server catalogue and engine; then the opentide pin bump and the deployer.

### C.5 Conformance and test plan

| Layer | Corpus | Oracle | Gate |
|-------|--------|--------|------|
| Sigma language | SigmaHQ `rules/`, `rules-emerging-threats/`, `rules-threat-hunting/` at a pinned commit (DRL 1.1, attribution in `SOURCES.md`), plus one broken twin per error code | pySigma 2.1 (load plus core validators); rsigma as a second opinion | 100% agreement on accept/reject; every twin raises its code |
| `graylog` Sigma profile | the same corpus | `POST …/sigma/import/validate` on a **licensed** Graylog Security 7.2 | every rule the profile accepts without a `graylog_sigma_undocumented` warning, Graylog accepts; every rule it refuses, Graylog refuses. Disagreements move constructs between the profile's rows. |
| Graylog dialect | the existing SigmaHQ Lucene corpus, `lucene-queryparser/cases.tsv`, plus hand cases for V8–V13 | `POST /api/search/validate` on Graylog 7.2 (Open) | syntax verdicts equal |
| Document assembly | fixture rules → expected Sigma documents (`fixtures/platforms/graylog/*.sigma.yml`) | review; pySigma loads each one | exact bytes; every document loads |
| Native deployer | create, update, disable, delete, recreate on 404, immutable, unconfirmed create | a fake Graylog (unit) and a live Graylog 7.2 Open (nightly, Docker, no licence) | the decision table in [B.8](#b8-deploy) |
| Sigma deployer | upload, bind, PUT, unchanged revision, replace, skipped, title conflict, 402 | a fake Graylog (unit, from the S-rows); a licensed Graylog Security 7.2 (nightly, when a licence secret is configured) | the Sigma decision table in [B.8](#b8-deploy) |

The native path runs in CI with no licence: the same Docker stack this RFC was verified on. The Sigma path needs a Graylog Security licence for its live jobs. Without one, it is covered by the fake server built from S1–S11.

---

## Engineering plan

| # | Work package | Repo | Person-days |
|---|--------------|------|-------------|
| S1 | `specs/languages/sigma-1.0.md` and `specs/platforms/graylog-1.0.md`; `platforms/index.md` 1.8 (eleven platforms, Graylog in `--live`); the `validation.md` codes; `deployment-state.md` (`graylog`, and the Sigma bind exception); the `rule-1.x` block table; `SPECS.md`, `llms.txt`, `CHANGELOG.md`; fixtures (`fixtures/platforms/graylog-query.yaml`, `graylog-sigma.yaml`, `graylog/*.api.json`, `graylog/*.sigma.yml`, invalid twins); fixture checkers (`validate_graylog_block`, `scripts/test_platform_graylog.py`, `test_language_sigma.py`); the three "ten platforms" assertions | specifications | 4–5 |
| L1 | `Dialect::Graylog`, the Graylog field catalogue and its sync script, injection, hover and completion | language-server | 3–4 |
| L2 | `graylog-condition` parser, checks, completion | language-server | 1–2 |
| L3 | `opentide-sigma`: parser on the Tide YAML tree, condition grammar, modifier and taxonomy catalogues, every `sigma_*` check | language-server | 7–9 |
| L4 | Profiles (`graylog`, `harfanglab`), document assembly and its PyO3 binding, editor features | language-server | 3–4 |
| L5 | Conformance: pySigma and rsigma oracles over SigmaHQ, broken twins, the Graylog `search/validate` oracle; the Graylog Sigma-validate oracle, gated on a licence | language-server | 3–4 |
| O1 | Models: `GraylogConfig`, schedule, aggregation, `SigmaDetection`; tenant setup | opentide | 2 |
| O2 | REST client on `TenantSession`: auth, CSRF header, version and capability probe, error mapping, multipart upload | opentide | 2 |
| O3 | Native compile (derived fields, ATT&CK, tag normalisation, version gating) and Sigma upload overrides; `api_body` goldens against the fixtures | opentide | 2–3 |
| O4 | Deployer on deployment state (`graylog` in `STATE_PLATFORMS` and `OBJECT_ID_PLATFORMS`): native pre-save check and decision table; Sigma validate, upload, bind, PUT, revision check, replace | opentide | 4–5 |
| O5 | Live validator (`search/validate` and Sigma `import/validate`) and the `opentide query` runner | opentide | 2 |
| O6 | Wiring (about 38 registration sites), bundled TOML, template, diagnostics pages, docs (usage, CLI, MCP, SDK), MCP default language | opentide | 3 |
| O7 | Tests: model, compile, deployer (fake Graylog for both kinds), live validator, runner, CLI E2E, MCP; nightly live jobs (Open always, Security when licensed) | opentide | 4–5 |

About 40–50 person-days. The Sigma language (L3, L4, and part of L5) is about a third of it, and HarfangLab reuses it.

Delivery order:

1. **S1** specifications.
2. **L1–L2**, with **O1–O2**: native `query` blocks are checked offline.
3. **O3–O7** for the native kind, then a release: Graylog native rules work end to end on every edition.
4. **L3–L5**, then the `sigma` kind in opentide: Graylog Sigma rules on Graylog Security 7.2+, and HarfangLab Sigma checking, ship in the release after. The licensed confirmations ([Unresolved questions](#unresolved-questions)) come before this step.

## Drawbacks

- **Graylog's Sigma semantics apply.** Graylog converts the rule, so its documented limits apply, and so do its open issues: values matched case-sensitively (graylog2-server#27742), and changes in how plain values are quoted. A Sigma rule can therefore match differently on Graylog than on another Sigma backend. opentide reports what Graylog refuses, offline and through `--live`, but cannot change how Graylog matches.
- **Graylog Security only.** The `sigma` kind needs a Security licence and 7.2+. Graylog Open and Enterprise tenants can deploy native rules only.
- **A Sigma logic change is a replace.** Graylog keeps the imported logic and has no update for it (S4, S11). Deploy deletes and re-imports. The definition gets a new id, the rule does not run for the seconds between the two calls, and events fired before keep the old id. Changes to streams, schedule, notifications, priority, and fields are in-place PUTs.
- **One query to bind an import.** Graylog withholds the id of a definition its import created (S6). The exact-tag bind is narrow and specified, but it is still an exception to deployment state's rule, until Graylog returns the id.
- **Fewer supported Sigma constructs.** Graylog refuses `windash`, `null`, `''`, and the encoding modifiers: at least 233 file-level uses in the SigmaHQ corpus. Those rules need rewriting before they deploy to Graylog.
- **The Sigma path is not live-tested yet.** It rests on Graylog's documentation and the 7.2.2 API surface. A licensed tenant must confirm S1–S11 before this RFC is accepted.

## Alternatives

- **Convert Sigma in opentide and deploy `aggregation-v1`.** The first draft of this RFC. It works on every edition and fixes case-insensitivity, but the Sigma rule is not a Graylog Sigma rule: Graylog's converter, field map, and Sigma views are bypassed, and opentide owns a converter. Rejected: the requirement is Sigma as Graylog supports it. It could return as an opt-in for tenants without Graylog Security.
- **Git repository delivery** (S10). Deploy commits the assembled documents to a Git repository that Graylog pulls, registers it as a Sigma repository, and calls `refresh` and `import_all`. Graylog's repository refresh is the only Graylog path that changes Sigma logic in place, which would avoid replace-on-change. It is not the 1.0 delivery, for three reasons:
  - Graylog must reach the Git host, and keeps a token for it.
  - The deploy depends on a push landing before the refresh.
  - What a refresh does to existing definitions is not documented; it is inferred from `updateRepoEventDefinition`, and is unverified.

  It is the leading candidate for a `delivery: repository` option once a licensed tenant confirms in-place refresh ([Unresolved questions](#unresolved-questions)).
- **Write `sigma-v1` definitions through the event-definition API.** Rejected: `parsed_rule` is Graylog's internal Java model (V27), with no public contract.
- **Deterministic client-assigned ids** (an ObjectId derived from `metadata.uuid`). Graylog accepts a client `id` (V22), but a create with an id that exists destroys the definition. Rejected.
- **Bind Sigma imports by listing and title.** Rejected for the exact tag: a title can change, and the tag carries `metadata.uuid`.
- **Content packs.** Rejected as the deploy path. A change means uninstall and reinstall, which gives every definition a new id; in-place upgrades are reachable only from closed-source Illuminate code [src].
- **Sigma metadata in the block.** Rejected: title, level, and ATT&CK would be written twice and could drift. The quick fix makes moving a SigmaHQ rule in a one-step edit.

## Unresolved questions

- **Confirm S1–S11 on a licensed Graylog Security 7.2.** Each of these needs a licensed tenant:
  - the upload request and response bodies;
  - that non-ATT&CK Sigma tags reach `tags`, so the bind query finds `opentide.<uuid>`;
  - that `sigma_rule_source_id` holds the Sigma `id`;
  - that `skipped` is returned for an existing `id`;
  - that a `PUT` of a `sigma-v1` definition, sending back what was read, keeps `parsed_rule` and `query`, and which fields it may change (aggregation included);
  - that `DELETE` and `/unschedule` behave as for native definitions;
  - the defaults of `sigma_min_execution_interval`, `sigma_max_search_interval`, and `sigma_max_rule_length`;
  - whether `stream_categories` alone satisfies "at least one stream".
- **Ask Graylog to return the id.** `SigmaImportResult` holds `eventDefinitionId()` without serialising it (S6). A one-line change upstream would remove the bind query. A request to Graylog, with this RFC's evidence, is a follow-up.
- **Git repository delivery.** Does `refresh` (or `import_all`) update already-imported definitions in place from changed YAML, keeping their ids (S10)? If it does, a `delivery: repository` tenant option avoids replace-on-change.
- **Undocumented constructs.** `exists`, `cased`, `neq`, `cidr`, `expand`, `fieldref`, numeric, time, and `re` sub-modifiers: which ones does Graylog's 7.2 converter accept? The licensed oracle run ([C.5](#c5-conformance-and-test-plan)) settles each one.
- **Security's ATT&CK checks.** Does Security's `TacticsTechniquesValidator` refuse technique or tactic ids that are missing from its own MITRE data (TA0112 *Defense Impairment* is recent)?
- **Graylog 6.x for native rules.** 6.x takes a bare create body (6.3: a bare body plus a top-level `share_request`) and has no `tags` or `tactics_techniques`. Supporting it is a small client branch. Is it in scope?
- **HarfangLab Sigma form.** Move `platform::harfanglab` to the `SigmaDetection` form (a new key beside the decomposed `sigma`), or keep only checking the assembled form?
- **Cross-rule Sigma correlation.** The cross-object model in [A.7](#a7-correlation-and-filter-rules), and whether Graylog's Event Correlation (`correlation-v1`, Enterprise) would carry temporal correlations over bound Sigma definitions.
- **Scheduling defaults.** Is `5m`, with `window` equal to `every`, the right default?

## References

- Graylog documentation:
  - [Event definitions](https://go2docs.graylog.org/current/interacting_with_your_log_data/event_definitions.html)
  - [Search syntax](https://go2docs.graylog.org/current/making_sense_of_your_log_data/search_syntax_reference.htm)
  - [Access tokens](https://go2docs.graylog.org/current/setting_up_graylog/rest_api_access_tokens.htm)
  - [Upgrade to 7.2](https://go2docs.graylog.org/current/upgrading_graylog/upgrade_to_graylog_7.2.htm)
  - [Enterprise changelog](https://go2docs.graylog.org/current/changelogs/operations_changelog.html)
  - [Manage Sigma rules](https://go2docs.graylog.org/current/what_more_can_graylog_do_for_me/manage_sigma_rules.htm)
  - [Create or add a Sigma rule](https://go2docs.graylog.org/current/what_more_can_graylog_do_for_me/create_or_add_a_sigma_rule.htm)
  - [Pricing](https://www.graylog.org/pricing)
  - [SMB licence retirement](https://community.graylog.org/t/smb-license-program-retiring-dec-31-2025-updated/36402)
- graylog2-server (tag `7.2.2`): `org/graylog/events/rest/EventDefinitionsResource.java`, `org/graylog/events/processor/EventDefinitionDto.java`, `org/graylog/events/processor/aggregation/AggregationEventProcessorConfig.java`, `org/graylog/plugins/views/search/rest/QueryValidationResource.java`, `org/graylog2/indexer/template/IndexMapping.java`, `org/graylog/schema/*Fields.java`, `UPGRADING.md`
- Graylog Enterprise 7.2.2 jar (`graylog-plugin-enterprise-7.2.2.jar`, names and signatures only), package `org.graylog.plugins.securityapp.sigma`:
  - `rest.SigmaRuleImportResource`, `rest.GitRepositoryResource`, `rest.SigmaRuleZipValidationResponse`
  - `imports.SigmaImportService`, `imports.SigmaImportResult`, `imports.SharedOverrides`, `imports.BulkUploadEntity`
  - `SigmaEventDefinitionLookup`, `DuplicateRuleException`, `processor.SigmaEventProcessorConfig`, `rules.SigmaRuleParser`, `query.SigmaQueryBuilder`
- Sigma: [sigma-specification](https://github.com/SigmaHQ/sigma-specification) v2.1.0; [pySigma](https://github.com/SigmaHQ/pySigma) 2.1.0; [SigmaHQ rules](https://github.com/SigmaHQ/sigma) (DRL 1.1); [rsigma](https://github.com/timescale/rsigma)
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
    image: graylog/graylog-enterprise:7.2.2   # graylog/graylog:7.2.2 for Open only
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

Every V-row is one such probe. To confirm the S-rows, install a Graylog Security licence (`POST /api/plugins/org.graylog.plugins.license/licenses`) on the same stack, then run the [Sigma delivery](#b5-sigma-delivery) steps for one document.
