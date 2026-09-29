# RFC 0006: Elastic Security detection platform

- **RFC:** 0006
- **Title:** Elastic Security detection platform
- **Author:** OpenTide maintainers
- **Status:** draft
- **Created:** 2026-09-25
- **Issue:** [OpenTideHQ/specifications#17](https://github.com/OpenTideHQ/specifications/issues/17)
- **PR:** [OpenTideHQ/specifications#18](https://github.com/OpenTideHQ/specifications/pull/18)

## Summary

Add a detection platform, `elastic` (display name **Elastic Security**, schema `platform::elastic::1.0`), that deploys OpenTide rules as Elastic Security detection rules through the Kibana detection engine API (`/api/detection_engine/rules`, public API version `2023-10-31`).

Decisions:

1. **One platform for every Elastic deployment type.** Self-managed, Elastic Cloud Hosted, and Elastic Cloud Serverless Security expose the same rule API with the same request schemas. The deployment type only changes the tenant URL, credentials, and which features a licence enables. There is no `edition` switch.
2. **Target the Security detection engine, not generic Kibana alerting.** Detection rules are the only Elastic rules that land in the Security app, write to `.alerts-security.alerts-*`, carry ATT&CK mappings, and support exceptions.
3. **Every rule type the Security UI can create, except a saved query:** `query`, `eql`, `esql`, `threshold`, `new_terms`, `threat_match`, and `machine_learning`. A saved query is a Kibana object loaded by id on each run, so the detection text would not live in the rule file.
4. **Identity is the MDR UUID.** Kibana's user-settable `rule_id` is set to `metadata.uuid`. It is unique per space, so one UUID serves every tenant, and alerts carry it as `kibana.alert.rule.rule_id`. Kibana's internal `id` is never stored, and nothing is written back to the rule file.
5. **Validation:** offline syntax checks per query language, plus live validation through the rule preview API. Two Elasticsearch checks also run before every deploy, because Kibana accepts a mistyped ES\|QL command or aggregation field and the rule then fails silently ([Elasticsearch checks](#elasticsearch-checks)).
6. **Kibana's own names, grouped where the UI groups them.** Durations are written `5m`, `1h`, `14d`. `required_fields` is a list of `{name, type}` objects, and a package name may stand for a related integration. `index` and `threat.index` are lists of pattern strings, including a rule with one pattern (`[logs-*]`). Keys that exist for only one rule type sit in a conditional object (`eql`, `threshold`, `new_terms`, `threat`, `machine_learning`). The Schedule step sits in `scheduling` (`interval`, `from`). The compiler flattens those objects to Kibana's fields. Every other key is the Kibana field the create-rule UI writes. `overrides` is only for a field that UI does not show.

The change is additive: it adds a `configurations.elastic` key and a new platform schema. `rule::1.0` keeps its identifier and every existing rule stays valid.

## Motivation

Elastic Security is a common SIEM, and its detection engine is in the free Basic tier on self-managed clusters, so many OpenTide users already run it. Those users cannot deploy OpenTide rules to it today. They either rebuild rules by hand in Kibana or keep a second catalogue in Elastic's own [`detection-rules`](https://github.com/elastic/detection-rules) TOML format, which drops OpenTide's objectives, threats, and lifecycle.

Elastic also exposes several rule surfaces (Security detection rules, Kibana Stack alerting rules, Watcher, Elastic Defend) and three deployment types. Without a spec, each implementer would pick a different surface and a different identity model.

## Research

### Which Elastic surface

| Surface | API | Verdict |
|---------|-----|---------|
| Security detection rules | Kibana `/api/detection_engine/rules` | **Target.** Security app rule management, alert schema, ATT&CK `threat`, exceptions, and a preview endpoint. |
| Kibana Stack alerting rules (`.es-query`, …) | Kibana `/api/alerting/rule` | Rejected. Alerts land outside the Security alert index, and there is no ATT&CK mapping or exceptions. |
| Watcher | Elasticsearch `_watcher` | Rejected. Legacy, and it does not produce Security alerts. |
| Elastic Defend endpoint rules | none (Elastic ships them; users add exceptions and trusted apps) | Out of scope. Users cannot author them. |
| `_import` / `_export` (ndjson) | Kibana `/api/detection_engine/rules/_import` | Not the primary path (see [Alternatives](#alternatives)). |

Prior art wraps the same API. The Terraform resource [`elasticstack_kibana_security_detection_rule`](https://github.com/elastic/terraform-provider-elasticstack/blob/main/docs/resources/kibana_security_detection_rule.md) calls per-rule CRUD. Elastic's `detection-rules` CLI (`kibana import-rules` / `export-rules`) uses `_import` and `_export`.

### Do different Elastic deployment types need separate platforms?

No. A diff of Kibana's published OpenAPI bundles for self-managed/Hosted and for Serverless (`x-pack/solutions/security/plugins/security_solution/docs/openapi/{ess,serverless}`, `main`, API version `2023-10-31`) shows:

- All ten rule-management operations are present in both: `GET`/`POST`/`PUT`/`PATCH`/`DELETE /api/detection_engine/rules`, plus `_find`, `_bulk_action`, `_import`, `_export`, and `preview`.
- The create schemas for the five v1 types (`QueryRuleCreateProps`, `EqlRuleCreateProps`, `EsqlRuleCreateProps`, `ThresholdRuleCreateProps`, `NewTermsRuleCreateProps`) are byte-identical.
- The only self-managed-only endpoints are alerts-index management (`/api/detection_engine/index`), the legacy signals migration, and prepackaged-rule install. The deployer uses none of them.

| | Self-managed | Elastic Cloud Hosted | Serverless Security |
|-|--------------|----------------------|---------------------|
| Tenant `url` | operator Kibana URL | Kibana endpoint from the Cloud console | `https://<project>.kb.<region>.<csp>.elastic.cloud` |
| Tenant `elasticsearch_url` | operator Elasticsearch URL | Elasticsearch endpoint from the Cloud console | `https://<project>.es.<region>.<csp>.elastic.cloud` |
| Auth | API key | API key | API key |
| Spaces (`/s/<space>/api/...`) | yes | yes | yes |
| Kibana version | operator-chosen; see [Versions](#versions-and-licensing) | operator-chosen | continuously upgraded |
| Feature gating | licence tier | licence tier | project feature tier |

Spaces isolate rules, alerts, and exceptions, but not source data. A rule in space `a` can query any index its API key can read. Tenancy by space is therefore about where rules and alerts live, not a data boundary.

### Rule types

| Type | UI name | Query language | Conditional object |
|------|---------|----------------|--------------------|
| `query` | Custom query | KQL (`kuery`) or Lucene | — |
| `eql` | Event correlation | EQL | `eql` (optional settings) |
| `esql` | ES\|QL | ES\|QL | — (the `FROM` clause selects data; no `index`) |
| `threshold` | Threshold | KQL or Lucene | `threshold` |
| `new_terms` | New terms | KQL or Lucene | `new_terms` |
| `threat_match` | Indicator match | KQL or Lucene | `threat` (the indicator side; the event query stays flat) |
| `machine_learning` | Machine learning | — | `machine_learning` |

**New terms** alerts when a value, or a combination of up to three values, shows up that the rule has not seen in the history window. A rule with `new_terms.fields: [host.name, user.name]` and `new_terms.history_window_start: 14d` alerts when that host and user appear together in the current run and did not appear together in the previous 14 days. It does not count events. That is what a threshold rule does.

`threat.index` and `machine_learning.job_id` are names that exist in one tenant. The block carries them as written; nothing rewrites them into a shared identifier.

A saved query (`saved_id`) is out of scope. Kibana loads that object on every run, the id differs per space, and an edit in Discover changes the rule with no diff in the file. The same detection is `type: query` with the text in `query`.

The common required set on create is `name`, `description`, `type`, `severity`, and `risk_score`.

### Versions and licensing

- `elastic-api-version: 2023-10-31` is the only public version of the detection engine API. Kibana uses it when the header is absent and rejects an unknown version with 400. The deployer MUST send it.
- Kibana 9.0 removed `_bulk_create`, `_bulk_update`, and `_bulk_delete`. The deployer MUST NOT use them.
- ES\|QL rules are GA from 8.14. The supported floor is **Kibana 8.19** (final 8.x minor) and **9.x**. Older versions MAY work for `query`, `eql`, `threshold`, and `new_terms`, but they are not supported. [Appendix A](#appendix-a-reference-test) lists the versions tested.
- The detection engine and all five v1 types work on the free Basic licence. Alert suppression needs Platinum or higher on self-managed and Hosted, and a project tier that includes it on Serverless.
- **Suppression fails silently.** On a Basic licence, Kibana accepts and stores `alert_suppression`, previews it, and runs the rule with status `succeeded`, but it writes one alert per match and reports no error or warning. A least-privilege key cannot read the licence on 9.x: Kibana's `/api/licensing/info` is internal-only there (8.19 still serves it), and Elasticsearch `GET _license` needs the `monitor` cluster privilege. The tenant therefore declares it (`setup.suppression`, [§1](#1-platform-configuration-platformselastictoml)).
- Kibana's `version` field on custom rules stays `1`. `revision` increments only when an update changes rule content, so an identical `PUT` leaves it unchanged. OpenTide does not send `version`.

## Detailed design

### 1. Platform configuration (`platforms/elastic.toml`)

<!-- rfc0006:platform-toml -->
```toml
[platform]
enabled = true
identifier = "elastic"
name = "Elastic Security"
subschema = "Elastic Security"
description = "Elastic Security detection rules via the Kibana detection engine API."
flags = []

[[tenants]]
name = "elastic-staging"
description = "Serverless Security project, staging space"
deployment = "STAGING"
[tenants.setup]
proxy = false
ssl = true
url = "https://soc-staging.kb.eu-west-1.aws.elastic.cloud"
elasticsearch_url = "https://soc-staging.es.eu-west-1.aws.elastic.cloud"
space = "staging"
api_key = "$ELASTIC_STAGING_API_KEY"

[[tenants]]
name = "elastic-prod"
description = "Self-managed cluster on a Basic licence, default space"
deployment = "PRODUCTION"
[tenants.setup]
proxy = true
ssl = true
url = "https://kibana.soc.example.internal:5601"
elasticsearch_url = "https://es.soc.example.internal:9200"
api_key = "$ELASTIC_PROD_API_KEY"
index = ["logs-*", "winlogbeat-*"]
tags = ["soc-prod"]
suppression = false
```

Bundled defaults ship with `enabled = false` and no tenants, as for every platform. `[[modifiers]]` work unchanged on block dot-keys, for example `alert.severity = "Low"` for `STAGING`.

<!-- rfc0006:setup-table -->
| `tenants.setup` field | Type | Required | Default | Meaning |
|-----------------------|------|----------|---------|---------|
| `url` | string | yes | — | Kibana base URL, without `/s/<space>` |
| `api_key` | string | yes | — | Encoded API key (the `encoded` value from `POST /_security/api_key`). MUST be a `$ENV` reference. |
| `elasticsearch_url` | string | yes | — | Elasticsearch base URL of the same deployment, for the [Elasticsearch checks](#elasticsearch-checks) |
| `space` | string | no | `default` | Kibana space ID. `default` uses the unprefixed path. |
| `index` | list[string] | no | null | Index patterns for blocks that set neither `index` nor `data_view_id`. When null, Kibana applies the space's `securitySolution:defaultIndex`. |
| `tags` | list[string] | no | `[]` | Tags added to every rule deployed to this tenant |
| `suppression` | bool | no | `true` | Whether the tenant's licence or project tier applies alert suppression. When `false`, the deployer omits `alert_suppression` and warns once per affected rule. |
| `proxy`, `ssl` | bool | yes | — | Shared tenant setup (proxy use, TLS verification) |

```python
@dataclass
class Elastic(SystemConfig):
    @dataclass
    class Tenant(SystemConfig.Tenant):
        @dataclass
        class Setup(SystemConfig.Tenant.Setup):
            url: str
            elasticsearch_url: str
            api_key: str
            space: str = "default"
            index: Sequence[str] | None = None
            tags: Sequence[str] | None = None
            suppression: bool = True

        setup: Setup

    tenants: Sequence[Tenant] | None = None
```

**API key.** One Elasticsearch API key serves both Kibana and the Elasticsearch checks. Rules run with the privileges of the key that last created or updated them, and revoking that key stops them. Each tenant SHOULD therefore use a dedicated, non-personal key that holds:

- Kibana: Security rules management `All` in the tenant's space. This is the `feature_securitySolutionRulesV4.all` application privilege on 9.5, and `feature_siemV2.all` on 8.19. On 9.5, `feature_siemV5.all` alone returns 403 on rule create.
- Elasticsearch: `read` and `view_index_metadata` on every source index pattern the rules query. The Elasticsearch checks need nothing more, and no cluster privilege is needed.
- Live validation only: `read` on `.preview.alerts-security.alerts-<space>` and `.internal.preview.alerts-security.alerts-<space>-*`.

Kibana renames feature privileges between versions (`siemV2` on 8.19; `siemV5` and `securitySolutionRulesV4` on 9.5), so `platforms.md` will not pin them. [Appendix A](#appendix-a-reference-test) shows the tested key.

### 2. Rule block (`platform::elastic::1.0`)

```python
Duration = str    # "<n>s|m|h|d": 90s, 5m, 1h, 14d. ISO 8601 (PT1H) is also accepted.

FieldType = Literal[                      # Elasticsearch mapping types
    "keyword", "constant_keyword", "wildcard", "text", "match_only_text",
    "long", "integer", "short", "byte", "unsigned_long",
    "double", "float", "half_float", "scaled_float",
    "date", "date_nanos", "boolean", "ip", "version", "binary",
    "geo_point", "geo_shape", "object", "flattened", "nested",
]

class ElasticConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::elastic::1.0"
    type: Literal["query", "eql", "esql", "threshold", "new_terms", "threat_match", "machine_learning"]
    query: QueryText | None = None
    language: Literal["kuery", "lucene"] | None = None   # event query; absent for eql, esql, machine_learning
    index: list[str] | None = None                       # always a list; one pattern is [logs-*]
    data_view_id: str | None = None                      # one data view; replaces index
    filters: list[dict[str, Any]] | None = None          # event filters the UI saves
    scheduling: ElasticScheduling | None = None          # Runs every and the whole window
    severity: str | None = None                          # alert_severity vocabulary
    risk_score: int | None = None                        # 0–100
    severity_mapping: list[ElasticSeverityMapping] | None = None
    risk_score_mapping: list[ElasticRiskScoreMapping] | None = None
    alert_suppression: ElasticSuppression | None = None
    investigation_fields: list[str] | None = None        # Custom highlighted fields
    threshold: ElasticThreshold | None = None            # iff type threshold
    new_terms: ElasticNewTerms | None = None             # iff type new_terms
    eql: ElasticEql | None = None                        # only for type eql
    threat: ElasticThreatMatch | None = None             # iff type threat_match; not the ATT&CK array
    machine_learning: ElasticMachineLearning | None = None
    rule_name_override: str | None = None
    timestamp_override: str | None = None
    timestamp_override_fallback_disabled: bool | None = None
    max_signals: int | None = None                       # Max alerts per run
    license: str | None = None
    tags: list[str] | None = None
    note: str | None = None                              # Investigation guide
    setup: str | None = None                             # Setup guide
    false_positives: list[str] | None = None
    required_fields: list[ElasticRequiredField] | None = None
    related_integrations: list[str | ElasticIntegration] | None = None
    endpoint_exceptions: bool = False                    # Elastic endpoint exceptions checkbox
    exceptions_list: list[dict[str, str]] | None = None
    building_block: bool = False
    actions: list[dict[str, Any]] | None = None
    response_actions: list[dict[str, Any]] | None = None
    timeline_id: str | None = None
    timeline_title: str | None = None
    meta: dict[str, Any] | None = None                   # API only
    overrides: dict[str, Any] | None = None              # a Kibana field the UI does not show

class ElasticSuppression(TideModel):
    group_by: list[str] | None = None         # 1–3 field names; absent for threshold
    duration: Duration | None = None          # required for threshold
    missing_fields_strategy: Literal["suppress", "doNotSuppress"] = "suppress"

class ElasticThreshold(TideModel):
    field: list[str] = []                     # Group by, 0–5; [] counts all matches
    value: int                                # Threshold, >= 1
    cardinality: ElasticCardinality | None = None   # Count: {field, value}

class ElasticRequiredField(TideModel):
    name: str
    type: FieldType

class ElasticIntegration(TideModel):
    package: str                              # Fleet package, e.g. windows, endpoint, aws
    integration: str | None = None            # policy template, e.g. cloudtrail
    version: str = "*"                        # semver range, e.g. "^2.0.0"

class ElasticSeverityMapping(TideModel):
    field: str
    value: str
    operator: Literal["equals"] = "equals"
    severity: Literal["low", "medium", "high", "critical"]

class ElasticRiskScoreMapping(TideModel):
    field: str
    operator: Literal["equals"] = "equals"
    value: str = ""

class ElasticThreatGroup(TideModel):
    entries: list[ElasticThreatEntry]         # entries in one group are AND; groups are OR

class ElasticThreatEntry(TideModel):
    field: str                                # event field
    value: str                                # indicator field
    type: Literal["mapping"] = "mapping"
    negate: bool | None = None                # true is the UI's DOES NOT MATCH

class ElasticScheduling(TideModel):
    interval: Duration = "5m"                 # data_key none; Kibana interval. UI: Runs every
    from_: Duration = "6m"                    # data_key "from": whole window, sent as now-<from>

class ElasticEql(TideModel):
    timestamp_field: str | None = None
    event_category_override: str | None = None
    tiebreaker_field: str | None = None

class ElasticNewTerms(TideModel):
    fields: list[str]                         # 1–3; Kibana new_terms_fields
    history_window_start: Duration            # sent as now-<duration>

class ElasticThreatMatch(TideModel):
    index: list[str]                          # Kibana threat_index; always a list
    query: str                                # Kibana threat_query
    language: Literal["kuery", "lucene"] | None = None
    mapping: list[ElasticThreatGroup]         # Kibana threat_mapping
    filters: list[dict[str, Any]] | None = None
    indicator_path: str | None = None         # Kibana threat_indicator_path
    concurrent_searches: int | None = None    # API only; Kibana concurrent_searches
    items_per_search: int | None = None       # API only; Kibana items_per_search

class ElasticMachineLearning(TideModel):
    job_id: str | list[str]                   # Kibana machine_learning_job_id; either shape
    anomaly_threshold: int                    # 0–100
```

**Model constraints.** Validation MUST reject a block that breaks any of these:

<!-- rfc0006:constraints-table -->
| Code | Constraint |
|------|------------|
| `type_block` | `threshold` iff `type: threshold`. `new_terms` iff `type: new_terms`, and it has `fields` and `history_window_start`. `eql` only for `type: eql`. `threat` iff `type: threat_match`, and it has `index`, `query`, and `mapping`. `machine_learning` iff `type: machine_learning`, and it has `job_id` and `anomaly_threshold`. `query` is required except for `machine_learning`. Flat `interval`, `from`, `saved_id`, `timestamp_field`, `event_category_override`, `tiebreaker_field`, `new_terms_fields`, `history_window_start`, `threat_index`, `threat_query`, `threat_language`, `threat_mapping`, `threat_filters`, `threat_indicator_path`, `concurrent_searches`, `items_per_search`, `machine_learning_job_id`, and `anomaly_threshold` are invalid. |
| `language` | `language` MUST NOT be set for `eql`, `esql`, or `machine_learning` |
| `esql_source` | `esql` and `machine_learning` MUST NOT set `index`, `data_view_id`, or `filters` |
| `index_xor_data_view` | `index` and `data_view_id` are mutually exclusive |
| `index_list` | `index` and `threat.index`, when set, are lists of one or more pattern strings. A single pattern is a one-item list. A string is invalid. |
| `suppression_shape` | For `threshold`: `alert_suppression.duration` is required and `group_by` is forbidden. For other types: `group_by` is required, with 1–3 distinct, non-empty field names. |
| `new_terms_fields` | `new_terms.fields` has 1–3 entries |
| `threshold_fields` | `threshold.field` has 0–5 entries; `threshold.value` >= 1 |
| `risk_score` | `risk_score` is an integer in 0–100 |
| `duration` | Every duration is a positive integer followed by `s`, `m`, `h`, or `d`, or ISO 8601 `P[nD][T[nH][nM][nS]]` with whole seconds, and is > 0 |
| `override_key` | `overrides` MUST NOT contain a key from the [field mapping](#3-field-mapping) or [preserved fields](#5-deployment) tables |

Validation SHOULD warn when `scheduling.from` < `scheduling.interval` (the next run starts after the window ends), and when a non-aggregating ES\|QL query (no `STATS`) lacks `METADATA _id` (alerts are not deduplicated).

**Field names are open-ended.** `alert_suppression.group_by`, `threshold.field`, `new_terms.fields`, `investigation_fields`, and `required_fields[].name` name fields in the tenant's data: ECS, integration-specific, or custom. They cannot be an enum, and Kibana accepts any string for them. The deployer therefore checks aggregation fields against the tenant ([Aggregation field check](#aggregation-field-check)). `type` is closed. Of the 2,617 fields in ECS, 75% are `keyword`; the other types are `long`, `date`, `boolean`, `object`, `flattened`, `float`, `nested`, `wildcard`, `ip`, `geo_point`, `double`, `scaled_float`, `constant_keyword`, and `match_only_text`. `FieldType` lists those plus the other common Elasticsearch mapping types. Kibana sets `required_fields[].ecs` only when both the name and the type match ECS.

### 3. Field mapping

The deployer compiles each MDR into a Kibana create or update body:

<!-- rfc0006:mapping-table -->
| Kibana field | Source | Rule |
|--------------|--------|------|
| `rule_id` | `metadata.uuid` | verbatim |
| `type` | `type` | verbatim |
| `name` | block `name`, else rule `name` | |
| `description` | rule `description` | trailing whitespace stripped |
| `enabled` | block `status` | `false` iff that status's strategy is `DISABLEMENT`. The rule's own `status` is not read. An omitted block status is `STAGING`. Always sent, because a `PUT` without it keeps the remote value. |
| `severity`, `risk_score` | block `severity`, else `response.alert_severity`, else `Informational` | [Severity](#severity); block `risk_score` overrides the score |
| `severity_mapping`, `risk_score_mapping` | same-named block field | verbatim. These are the UI's Severity override and Risk score override. |
| `interval` | `scheduling.interval` | [Durations](#durations). UI Runs every. Default `5m`. |
| `from` | `scheduling.from` | `now-<duration>`. The whole window Kibana stores. Additional look-back is `from` minus `interval` and has no field. Default `6m`, which is one extra minute. Authors write `6m`, not `now-6m`. |
| `to` | — | `now`. The UI does not expose it. |
| `language` | `type`, `language` | `eql` → `eql`, `esql` → `esql`; omitted for `machine_learning`; else `language` or `kuery`. Flat `language` is the event query. |
| `query` | `query` | trailing whitespace stripped; omitted for `machine_learning`. This is the event query. |
| `index` | block `index`, else tenant `setup.index` | a list of one or more pattern strings. Omitted for `esql` and `machine_learning`, when `data_view_id` is set, or when both sources are empty |
| `data_view_id`, `filters` | same-named block field | verbatim. `filters` is the event side, and is omitted for `esql` and `machine_learning` |
| `threshold` | `threshold` | sent as Kibana's `threshold` object, not flattened. `cardinality` is one `{field, value}` and is sent as a one-item list |
| `new_terms_fields` | `new_terms.fields` | verbatim |
| `history_window_start` | `new_terms.history_window_start` | `now-<duration>`. UI label: History window size. |
| `timestamp_field`, `event_category_override`, `tiebreaker_field` | `eql.timestamp_field`, `eql.event_category_override`, `eql.tiebreaker_field` | verbatim. There is no `eql_` prefix on the Kibana fields. |
| `threat_index` | `threat.index` | a list of pattern strings. YAML `threat` is the indicator-match group. It is not copied onto Kibana `threat`. |
| `threat_query`, `threat_language`, `threat_filters`, `threat_indicator_path` | `threat.query`, `threat.language`, `threat.filters`, `threat.indicator_path` | verbatim |
| `threat_mapping` | `threat.mapping` | an entry with no `type` is sent as `type: mapping` |
| `concurrent_searches`, `items_per_search` | `threat.concurrent_searches`, `threat.items_per_search` | verbatim, under those Kibana names (no `threat_` prefix). Not in the create UI. On update, an omitted value is kept from the remote rule. |
| `machine_learning_job_id` | `machine_learning.job_id` | verbatim. A string or a list; the compiler does not wrap or unwrap it. |
| `anomaly_threshold` | `machine_learning.anomaly_threshold` | verbatim |
| `alert_suppression` | `alert_suppression` | `{group_by, duration?, missing_fields_strategy}`; for threshold `{duration}` only. `duration` is `{value, unit}`. Omitted when tenant `setup.suppression` is `false`. |
| `investigation_fields` | `investigation_fields` | `{field_names: [...]}` |
| `required_fields` | `required_fields` | one `{name, type}` per entry, sorted by name |
| `related_integrations` | `related_integrations` | a string `p` becomes `{package: p, version: "*"}`; objects keep `integration`, and `version` defaults to `"*"` (Kibana requires a non-empty version) |
| `false_positives`, `setup`, `license` | same-named block field | verbatim |
| `max_signals` | `max_signals` | verbatim. This is Max alerts per run. Omitted means Kibana's default of 100. |
| `rule_name_override`, `timestamp_override`, `timestamp_override_fallback_disabled` | same-named block field | verbatim |
| `exceptions_list` | `exceptions_list`, `endpoint_exceptions` | `endpoint_exceptions: true` adds `{id: endpoint_list, list_id: endpoint_list, namespace_type: agnostic, type: endpoint}`. Omitted keeps the remote list. |
| `building_block_type` | `building_block: true` | `"default"` |
| `actions`, `response_actions`, `timeline_id`, `timeline_title` | same-named block field | verbatim when set. Omitted keeps the remote value, because connectors and Timeline templates belong to the tenant. |
| `meta` | `meta` | verbatim. Not in the create UI. On update, an omitted value is kept. |
| `tags` | `"OpenTide"`, tenant `setup.tags`, block `tags` | in that order, de-duplicated |
| `author` | `metadata.author`, `metadata.contributors` | de-duplicated; omitted if empty |
| `references` | `references.public` | values in ascending key order |
| `note` | block `note`, else `response.procedure.analysis` | trailing whitespace stripped |
| `threat` | resolved techniques | [Threat](#threat) |
| anything else | `overrides` | merged last. Only a Kibana field the create UI does not show. |

Absent optional sources produce no key. The deployer MUST NOT send `id` or `version`.

#### Severity

<!-- rfc0006:severity-table -->
| `alert_severity` | `severity` | `risk_score` |
|------------------|------------|--------------|
| Informational | low | 1 |
| Low | low | 21 |
| Medium | medium | 47 |
| High | high | 73 |
| Critical | critical | 99 |

The scores follow Elastic's prebuilt-rule convention and sit inside Kibana's risk bands (0–21 low, 22–47 medium, 48–73 high, 74–100 critical). An `alert.risk_score` override SHOULD stay inside its severity's band.

#### Durations

Durations use Kibana's own notation: a whole number followed by `s`, `m`, `h`, or `d`. Kibana rejects ISO 8601 (`PT5M`) and weeks (`1w`) in `interval`. ISO 8601 is still accepted on input, for parity with other platform blocks. The deployer converts every duration to the largest unit that divides it exactly. `alert_suppression.duration` has no `d` unit, so days become hours there.

<!-- rfc0006:duration-table -->
| Written | `interval` / `from` | `alert_suppression.duration` | `history_window_start` |
|---------|---------------------|------------------------------|------------------------|
| `5m` | `5m` / `now-5m` | `{value: 5, unit: m}` | `now-5m` |
| `90s` | `90s` / `now-90s` | `{value: 90, unit: s}` | `now-90s` |
| `60m` | `1h` / `now-1h` | `{value: 1, unit: h}` | `now-1h` |
| `1d` | `1d` / `now-1d` | `{value: 24, unit: h}` | `now-1d` |
| `14d` | `14d` / `now-14d` | `{value: 336, unit: h}` | `now-14d` |
| `PT1H` | `1h` / `now-1h` | `{value: 1, unit: h}` | `now-1h` |

#### Threat

Kibana `threat` is the ATT&CK array below. It is derived from the resolved technique set. The YAML key `threat` on a `threat_match` block is a different object: the indicator-match group, flattened to `threat_index`, `threat_query`, `threat_mapping`, and the other indicator fields. The compiler MUST NOT assign that YAML object to the body key `threat`.

The ATT&CK array is derived from the resolved technique set: the rule's `techniques`, plus techniques inherited through `detection_model` (objective, then threats, using the same resolver as Sentinel), de-duplicated. The Sentinel deployer uses only the inherited set. Elastic deliberately takes the union, so a rule's own `techniques` are never dropped.

1. Keep **Enterprise** techniques only. In `att&ck.vocab.toml`, Mobile and ICS entries are marked only by a `Mobile : ` or `Industrial : ` name prefix, and they reuse Enterprise tactic names under different tactic IDs. The deployer MUST skip them with a warning.
2. Map each technique's vocab `tide.vocab.stages` to tactics using the table below. A sub-technique uses its own stages.
3. Emit one `threat` entry per tactic, in table order, with `framework: "MITRE ATT&CK"`. Techniques are sorted by ID. A sub-technique appears under its parent technique; its name is the vocab name minus the `<parent name>: ` prefix. Empty `subtechnique` arrays are omitted.
4. `reference` values are the vocab `link` for techniques and `https://attack.mitre.org/tactics/<id>/` for tactics.

<!-- rfc0006:tactic-table -->
| Stage | Tactic ID |
|-------|-----------|
| Reconnaissance | TA0043 |
| Resource Development | TA0042 |
| Initial Access | TA0001 |
| Execution | TA0002 |
| Persistence | TA0003 |
| Privilege Escalation | TA0004 |
| Defense Evasion | TA0005 |
| Credential Access | TA0006 |
| Discovery | TA0007 |
| Lateral Movement | TA0008 |
| Collection | TA0009 |
| Command and Control | TA0011 |
| Exfiltration | TA0010 |
| Impact | TA0040 |

### 4. Examples

Each example is a complete MDR. Deployment status is `configurations.elastic.status`. The rule's own `status` is omitted. `data_view_id` is a single string and replaces `index`; the examples set `index`, so they do not also set `data_view_id`. `meta` and `overrides` stay out of these rules: they are not create-rule fields. `building_block: false` is the checkbox off and is not sent.

**Example A: `query`.** Custom query, every shared field set.

<!-- rfc0006:rule-query -->
```yaml
name: Certutil downloading a file
metadata:
  uuid: 6b2e9c14-7a31-4f58-9d0c-1e8a4b7c2d90
  schema: rule::1.0
  version: 1
  created: "2026-09-29"
  modified: "2026-09-29"
  tlp: clear
  author: Detection Engineering
description: |
  Detects certutil.exe started with -urlcache or -verifyctl. Windows uses
  those switches to pull a remote file, and intrusions use the same path
  to land a payload.
techniques: [T1105]
references:
  public:
    1: https://attack.mitre.org/techniques/T1105/
    2: https://lolbas-project.github.io/lolbas/Binaries/Certutil/
response:
  alert_severity: High
  procedure:
    analysis: |
      Confirm the certutil command line and the file it wrote.
    containment: |
      Isolate the host if the downloaded file is unsigned.
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    status: STAGING
    type: query
    language: kuery
    query: |
      event.category : "process" and event.type : "start" and
      process.name : "certutil.exe" and
      process.command_line : (*urlcache* or *verifyctl*)
    index: [logs-endpoint.events.process-*, logs-windows.sysmon_operational-*]
    filters:
      - meta:
          key: process.parent.name
          negate: true
          disabled: false
          type: phrase
          params:
            query: msiexec.exe
        query:
          match_phrase:
            process.parent.name: msiexec.exe
    scheduling:
      interval: 5m
      from: 6m
    severity: High
    risk_score: 68
    severity_mapping:
      - field: user.name
        operator: equals
        value: SYSTEM
        severity: critical
    risk_score_mapping:
      - field: host.risk.calculated_score_norm
        operator: equals
        value: ""
    alert_suppression:
      group_by: [host.name, user.name]
      duration: 1h
      missing_fields_strategy: suppress
    investigation_fields: [process.command_line, process.parent.name, process.parent.command_line, file.path]
    required_fields:
      - {name: process.command_line, type: wildcard}
      - {name: process.name, type: keyword}
      - {name: process.parent.name, type: keyword}
    related_integrations:
      - endpoint
      - package: windows
        integration: sysmon
        version: "^2.0.0"
    max_signals: 200
    timestamp_override: event.ingested
    timestamp_override_fallback_disabled: true
    rule_name_override: process.command_line
    license: Elastic License v2
    tags: [Windows, LOLBAS]
    note: |
      Read process.command_line and the URL in -urlcache or -verifyctl.
      Hash the file certutil wrote.
    setup: |
      Requires Elastic Defend process events or Sysmon process creation
      (Event ID 1) with command-line auditing.
    false_positives:
      - Certificate enrollment and Windows installer repair launching certutil.
      - Software-distribution scripts that download vendor CRLs with certutil.
    endpoint_exceptions: true
    exceptions_list:
      - id: 4a8e1c20-7b55-4d19-9e30-2f6c8a1b5d74
        list_id: certutil-software-distribution
        namespace_type: single
        type: detection
    building_block: false
    actions:
      - id: c4e8a1b2-6d30-4f57-9a18-3b7e5c0d2f64
        action_type_id: .slack
        group: default
        params:
          message: "Certutil download on {{host.name}} by {{user.name}}"
        frequency:
          summary: true
          notifyWhen: onActiveAlert
          throttle: null
    response_actions:
      - action_type_id: .endpoint
        params:
          command: isolate
          comment: Isolate the host that ran certutil -urlcache or -verifyctl.
    timeline_id: 3d6f8a20-1c54-4b79-8e02-5a9c7d1e4b36
    timeline_title: Windows process investigation
```

Compiled for tenant `elastic-staging` and sent as `POST https://soc-staging.kb.eu-west-1.aws.elastic.cloud/s/staging/api/detection_engine/rules`:

<!-- rfc0006:body-query -->
```json
{
  "rule_id": "6b2e9c14-7a31-4f58-9d0c-1e8a4b7c2d90",
  "type": "query",
  "name": "Certutil downloading a file",
  "description": "Detects certutil.exe started with -urlcache or -verifyctl. Windows uses\nthose switches to pull a remote file, and intrusions use the same path\nto land a payload.",
  "enabled": true,
  "severity": "high",
  "risk_score": 68,
  "interval": "5m",
  "from": "now-6m",
  "to": "now",
  "language": "kuery",
  "query": "event.category : \"process\" and event.type : \"start\" and\nprocess.name : \"certutil.exe\" and\nprocess.command_line : (*urlcache* or *verifyctl*)",
  "index": [
    "logs-endpoint.events.process-*",
    "logs-windows.sysmon_operational-*"
  ],
  "filters": [
    {
      "meta": {
        "key": "process.parent.name",
        "negate": true,
        "disabled": false,
        "type": "phrase",
        "params": {
          "query": "msiexec.exe"
        }
      },
      "query": {
        "match_phrase": {
          "process.parent.name": "msiexec.exe"
        }
      }
    }
  ],
  "severity_mapping": [
    {
      "field": "user.name",
      "operator": "equals",
      "value": "SYSTEM",
      "severity": "critical"
    }
  ],
  "risk_score_mapping": [
    {
      "field": "host.risk.calculated_score_norm",
      "operator": "equals",
      "value": ""
    }
  ],
  "rule_name_override": "process.command_line",
  "timestamp_override": "event.ingested",
  "timestamp_override_fallback_disabled": true,
  "max_signals": 200,
  "license": "Elastic License v2",
  "actions": [
    {
      "id": "c4e8a1b2-6d30-4f57-9a18-3b7e5c0d2f64",
      "action_type_id": ".slack",
      "group": "default",
      "params": {
        "message": "Certutil download on {{host.name}} by {{user.name}}"
      },
      "frequency": {
        "summary": true,
        "notifyWhen": "onActiveAlert",
        "throttle": null
      }
    }
  ],
  "response_actions": [
    {
      "action_type_id": ".endpoint",
      "params": {
        "command": "isolate",
        "comment": "Isolate the host that ran certutil -urlcache or -verifyctl."
      }
    }
  ],
  "timeline_id": "3d6f8a20-1c54-4b79-8e02-5a9c7d1e4b36",
  "timeline_title": "Windows process investigation",
  "alert_suppression": {
    "group_by": [
      "host.name",
      "user.name"
    ],
    "duration": {
      "value": 1,
      "unit": "h"
    },
    "missing_fields_strategy": "suppress"
  },
  "investigation_fields": {
    "field_names": [
      "process.command_line",
      "process.parent.name",
      "process.parent.command_line",
      "file.path"
    ]
  },
  "required_fields": [
    {
      "name": "process.command_line",
      "type": "wildcard"
    },
    {
      "name": "process.name",
      "type": "keyword"
    },
    {
      "name": "process.parent.name",
      "type": "keyword"
    }
  ],
  "related_integrations": [
    {
      "package": "endpoint",
      "version": "*"
    },
    {
      "package": "windows",
      "integration": "sysmon",
      "version": "^2.0.0"
    }
  ],
  "false_positives": [
    "Certificate enrollment and Windows installer repair launching certutil.",
    "Software-distribution scripts that download vendor CRLs with certutil."
  ],
  "setup": "Requires Elastic Defend process events or Sysmon process creation\n(Event ID 1) with command-line auditing.\n",
  "exceptions_list": [
    {
      "id": "4a8e1c20-7b55-4d19-9e30-2f6c8a1b5d74",
      "list_id": "certutil-software-distribution",
      "namespace_type": "single",
      "type": "detection"
    },
    {
      "id": "endpoint_list",
      "list_id": "endpoint_list",
      "namespace_type": "agnostic",
      "type": "endpoint"
    }
  ],
  "tags": [
    "OpenTide",
    "Windows",
    "LOLBAS"
  ],
  "author": [
    "Detection Engineering"
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1105/",
    "https://lolbas-project.github.io/lolbas/Binaries/Certutil/"
  ],
  "note": "Read process.command_line and the URL in -urlcache or -verifyctl.\nHash the file certutil wrote.",
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0011",
        "name": "Command and Control",
        "reference": "https://attack.mitre.org/tactics/TA0011/"
      },
      "technique": [
        {
          "id": "T1105",
          "name": "Ingress Tool Transfer",
          "reference": "https://attack.mitre.org/techniques/T1105"
        }
      ]
    }
  ]
}
```

**Example B: `eql`.** No `language` key. The sequence settings that belong only to EQL sit under `eql`. `from: 10m` with `interval: 5m` is five extra minutes of look-back.

<!-- rfc0006:rule-eql -->
```yaml
name: Word spawning cmd.exe and PowerShell
metadata:
  uuid: a4c8e1d2-5b67-4e90-8f13-2c6d9a0b4e71
  schema: rule::1.0
  version: 1
  created: "2026-09-29"
  modified: "2026-09-29"
  tlp: clear
  author: Detection Engineering
description: |
  Correlates WINWORD.EXE starting cmd.exe and that cmd.exe starting
  powershell.exe on the same host within two minutes.
techniques: [T1566.001, T1059.001]
references:
  public:
    1: https://attack.mitre.org/techniques/T1566/001/
    2: https://attack.mitre.org/techniques/T1059/001/
response:
  alert_severity: High
  procedure:
    analysis: |
      Confirm WINWORD.EXE is the ancestor of powershell.exe and collect
      the document path.
    containment: |
      Kill the PowerShell process and quarantine the document.
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    status: STAGING
    type: eql
    query: |
      sequence by host.id with maxspan=2m
        [process where event.type == "start" and process.name == "WINWORD.EXE"]
        [process where event.type == "start" and process.parent.name == "WINWORD.EXE" and process.name == "cmd.exe"]
        [process where event.type == "start" and process.parent.name == "cmd.exe" and process.name in ("powershell.exe", "pwsh.exe")]
    index: [logs-endpoint.events.process-*]
    filters:
      - meta:
          key: host.os.type
          negate: false
          disabled: false
          type: phrase
          params:
            query: windows
        query:
          match_phrase:
            host.os.type: windows
    scheduling:
      interval: 5m
      from: 10m
    severity: High
    risk_score: 70
    severity_mapping:
      - field: user.name
        operator: equals
        value: svc-mail
        severity: critical
    risk_score_mapping:
      - field: host.risk.calculated_score_norm
        operator: equals
        value: ""
    alert_suppression:
      group_by: [host.id]
      duration: 30m
      missing_fields_strategy: suppress
    investigation_fields: [process.name, process.parent.name, process.command_line, process.parent.executable]
    required_fields:
      - {name: host.id, type: keyword}
      - {name: process.name, type: keyword}
      - {name: process.parent.name, type: keyword}
    related_integrations: [endpoint]
    max_signals: 100
    timestamp_override: event.ingested
    timestamp_override_fallback_disabled: false
    rule_name_override: process.command_line
    license: Elastic License v2
    tags: [Windows, Phishing]
    note: |
      Confirm the three events share host.id and fall inside maxspan=2m.
    setup: |
      Requires Elastic Defend or an equivalent process data stream with
      parent process name populated.
    false_positives:
      - Office add-in installers that legitimately shell out to cmd.exe.
    endpoint_exceptions: true
    exceptions_list:
      - id: b7c2e190-4a68-4d35-8f02-1c9e6a3b5d80
        list_id: office-addin-installers
        namespace_type: single
        type: detection
    building_block: false
    eql:
      timestamp_field: "@timestamp"
      event_category_override: event.category
      tiebreaker_field: event.sequence
    actions:
      - id: c4e8a1b2-6d30-4f57-9a18-3b7e5c0d2f64
        action_type_id: .slack
        group: default
        params:
          message: "Word spawned PowerShell via cmd on {{host.name}}"
        frequency:
          summary: true
          notifyWhen: onActiveAlert
          throttle: null
    response_actions:
      - action_type_id: .endpoint
        params:
          command: kill-process
          comment: Kill the PowerShell process started from the Word chain.
          config:
            field: process.entity_id
            overwrite: false
    timeline_id: 3d6f8a20-1c54-4b79-8e02-5a9c7d1e4b36
    timeline_title: Windows process investigation
```

**Example C: `esql`.** No `index`, `data_view_id`, `language`, or `filters`. `FROM` selects the data. Suppression groups on `source.ip`, which the `STATS` keeps as a column. `from: 20m` with `interval: 15m` is five extra minutes.

<!-- rfc0006:rule-esql -->
```yaml
name: Password spray from one source address
metadata:
  uuid: d19f3a60-2c84-4b17-a5e8-7f0c3d6b8a24
  schema: rule::1.0
  version: 1
  created: "2026-09-29"
  modified: "2026-09-29"
  tlp: clear
  author: Detection Engineering
description: |
  Alerts when one source address produces at least 20 Windows logon
  failures with status 0xC000006A across 8 or more accounts.
techniques: [T1110.003]
references:
  public:
    1: https://attack.mitre.org/techniques/T1110/003/
response:
  alert_severity: High
  procedure:
    analysis: |
      Review the source address and whether the failures are 4625 with
      substatus 0xC000006A.
    containment: |
      Block the source at the VPN or firewall if it is not a known
      identity provider.
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    status: STAGING
    type: esql
    query: |
      FROM logs-system.security-*, logs-windows.forwarded-*
      | WHERE event.code == "4625" AND winlog.event_data.SubStatus == "0xC000006A"
      | STATS failures = COUNT(*), accounts = COUNT_DISTINCT(user.name) BY source.ip
      | WHERE accounts >= 8 AND failures >= 20
    scheduling:
      interval: 15m
      from: 20m
    severity: High
    risk_score: 73
    severity_mapping:
      - field: source.ip
        operator: equals
        value: 10.0.0.5
        severity: medium
    risk_score_mapping:
      - field: user.risk.calculated_score_norm
        operator: equals
        value: ""
    alert_suppression:
      group_by: [source.ip]
      duration: 1h
      missing_fields_strategy: suppress
    investigation_fields: [source.ip, accounts, failures]
    required_fields:
      - {name: event.code, type: keyword}
      - {name: source.ip, type: ip}
      - {name: user.name, type: keyword}
    related_integrations:
      - package: system
        integration: security
        version: "^1.0.0"
      - windows
    max_signals: 50
    timestamp_override: event.ingested
    timestamp_override_fallback_disabled: false
    rule_name_override: source.ip
    license: Elastic License v2
    tags: [Windows, Identity]
    note: |
      source.ip is the spray source. 0xC000006A is a wrong password for
      a real account.
    setup: |
      Windows Security auditing must log 4625 with SubStatus. The ES|QL
      FROM clause selects the data streams.
    false_positives:
      - A password manager retrying one stale password across a small set of accounts.
      - Terminal servers where many users fail from the same NAT address.
    endpoint_exceptions: false
    exceptions_list:
      - id: e1d4a860-2c79-4b15-9a30-7f6c2b8e1d45
        list_id: known-nats-password-spray
        namespace_type: single
        type: detection
    building_block: false
    actions:
      - id: c4e8a1b2-6d30-4f57-9a18-3b7e5c0d2f64
        action_type_id: .slack
        group: default
        params:
          message: "Password spray from {{source.ip}}"
        frequency:
          summary: true
          notifyWhen: onThrottleInterval
          throttle: 1h
    response_actions:
      - action_type_id: .osquery
        params:
          query: SELECT user, host, time FROM logged_in_users;
          timeout: 60
          ecs_mapping: {}
    timeline_id: 9b1e4c70-2a85-4d63-b0f7-6c8a3e5d1f24
    timeline_title: Windows logon investigation
```

**Example D: `threshold`.** Suppression is a duration, with no `group_by`. `language: lucene` is the other legal event language. `threshold.cardinality` is one object here and a one-item list in the body.

<!-- rfc0006:rule-threshold -->
```yaml
name: Many failed logons for one account
metadata:
  uuid: 2e7b5c91-8d40-4a63-b1f5-9c3e6a8d0f17
  schema: rule::1.0
  version: 1
  created: "2026-09-29"
  modified: "2026-09-29"
  tlp: clear
  author: Detection Engineering
description: |
  Alerts when one account accumulates 50 failed logons and those failures
  come from at least 8 distinct source addresses.
techniques: [T1110]
references:
  public:
    1: https://attack.mitre.org/techniques/T1110/
response:
  alert_severity: Medium
  procedure:
    analysis: |
      Identify user.name and whether the account is privileged.
    containment: |
      Reset the account if the sources are off-network.
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    status: PRODUCTION
    type: threshold
    language: lucene
    query: 'event.code:"4625" AND event.outcome:"failure"'
    index: [logs-system.security-*]
    filters:
      - meta:
          key: winlog.channel
          negate: false
          disabled: false
          type: phrase
          params:
            query: Security
        query:
          match_phrase:
            winlog.channel: Security
    scheduling:
      interval: 5m
      from: 6m
    severity: Medium
    risk_score: 40
    severity_mapping:
      - field: user.name
        operator: equals
        value: Administrator
        severity: high
    risk_score_mapping:
      - field: user.risk.calculated_score_norm
        operator: equals
        value: ""
    alert_suppression:
      duration: 30m
    threshold:
      field: [user.name]
      value: 50
      cardinality:
        field: source.ip
        value: 8
    investigation_fields: [user.name, source.ip, host.name, winlog.event_data.SubStatus]
    required_fields:
      - {name: event.code, type: keyword}
      - {name: source.ip, type: ip}
      - {name: user.name, type: keyword}
    related_integrations:
      - package: system
        integration: security
        version: "^1.0.0"
    max_signals: 100
    timestamp_override: event.ingested
    timestamp_override_fallback_disabled: false
    rule_name_override: user.name
    license: Elastic License v2
    tags: [Windows, Identity]
    note: |
      threshold.field groups by user.name. cardinality requires 8 distinct
      source.ip values. Suppression on a threshold rule is a duration only.
    setup: |
      Windows Security log 4625 via the System integration. user.name and
      source.ip must be aggregatable.
    false_positives:
      - A user with a stale laptop password plus a phone and a second workstation.
    endpoint_exceptions: false
    exceptions_list:
      - id: 0c5e8a31-6b47-4d92-a1f0-8e3c7b2d6a59
        list_id: scanner-test-accounts
        namespace_type: single
        type: detection
    building_block: false
    actions:
      - id: c4e8a1b2-6d30-4f57-9a18-3b7e5c0d2f64
        action_type_id: .slack
        group: default
        params:
          message: "Account {{user.name}} failed logon from many source addresses."
        frequency:
          summary: true
          notifyWhen: onActiveAlert
          throttle: null
    response_actions:
      - action_type_id: .osquery
        params:
          query: SELECT user, host, time FROM logged_in_users;
          timeout: 60
          ecs_mapping: {}
    timeline_id: 9b1e4c70-2a85-4d63-b0f7-6c8a3e5d1f24
    timeline_title: Windows logon investigation
```

**Example E: `new_terms`.** `new_terms.history_window_start` is the history window, separate from `scheduling`. `from: 65m` with `interval: 1h` is five extra minutes. A suppression duration of `1d` is sent as 24 hours.

<!-- rfc0006:rule-new-terms -->
```yaml
name: IAM user creates an access key for the first time
metadata:
  uuid: f3a1c8e4-6d29-4b70-9e15-8a2c4f7b1d63
  schema: rule::1.0
  version: 1
  created: "2026-09-29"
  modified: "2026-09-29"
  tlp: clear
  author: Detection Engineering
description: |
  Alerts when an IAM user successfully calls CreateAccessKey in an AWS
  account, and that user plus account pair has not done so in the past
  14 days.
techniques: [T1098.001]
references:
  public:
    1: https://attack.mitre.org/techniques/T1098/001/
response:
  alert_severity: Medium
  procedure:
    analysis: |
      Confirm who called CreateAccessKey and which account it landed in.
    containment: |
      Deactivate the new access key if the caller is not break-glass automation.
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    status: STAGING
    type: new_terms
    language: kuery
    query: 'event.dataset : "aws.cloudtrail" and event.action : "CreateAccessKey" and event.outcome : "success"'
    index: [logs-aws.cloudtrail-*]
    filters:
      - meta:
          key: cloud.provider
          negate: false
          disabled: false
          type: phrase
          params:
            query: aws
        query:
          match_phrase:
            cloud.provider: aws
    scheduling:
      interval: 1h
      from: 65m
    severity: Medium
    risk_score: 47
    severity_mapping:
      - field: user.name
        operator: equals
        value: OrganizationAccountAccessRole
        severity: critical
    risk_score_mapping:
      - field: user.risk.calculated_score_norm
        operator: equals
        value: ""
    alert_suppression:
      group_by: [user.name, cloud.account.id]
      duration: 1d
      missing_fields_strategy: suppress
    new_terms:
      fields: [user.name, cloud.account.id]
      history_window_start: 14d
    investigation_fields: [user.name, cloud.account.id, event.action, aws.cloudtrail.user_identity.arn, source.ip]
    required_fields:
      - {name: cloud.account.id, type: keyword}
      - {name: event.action, type: keyword}
      - {name: user.name, type: keyword}
    related_integrations:
      - package: aws
        integration: cloudtrail
        version: "^2.0.0"
    max_signals: 100
    timestamp_override: event.ingested
    timestamp_override_fallback_disabled: false
    rule_name_override: aws.cloudtrail.user_identity.arn
    license: Elastic License v2
    tags: [AWS, Identity]
    note: |
      The new value is the pair user.name plus cloud.account.id.
      history_window_start 14d is sent as now-14d.
    setup: |
      AWS CloudTrail via the AWS integration. user.name and cloud.account.id
      must be aggregatable.
    false_positives:
      - A new engineer creating their first CLI key during onboarding.
    endpoint_exceptions: false
    exceptions_list:
      - id: 7d3b6e12-9c40-4a85-b2f1-0e8a5c4d7b69
        list_id: iam-break-glass-key-creators
        namespace_type: single
        type: detection
    building_block: false
    actions:
      - id: c4e8a1b2-6d30-4f57-9a18-3b7e5c0d2f64
        action_type_id: .slack
        group: default
        params:
          message: "First CreateAccessKey in 14d for {{user.name}} in {{cloud.account.id}}"
        frequency:
          summary: true
          notifyWhen: onActiveAlert
          throttle: null
    response_actions:
      - action_type_id: .osquery
        params:
          query: SELECT * FROM users;
          timeout: 60
          ecs_mapping: {}
    timeline_id: 5e2a7c90-8b14-4f36-a1d8-0c6b9e3f7a52
    timeline_title: AWS CloudTrail investigation
```

**Example F: `threat_match`.** The event query, index, language, and filters stay flat. The indicator side is the `threat` object. That object is not Kibana's ATT&CK `threat` array; the compiler copies `threat.index` to `threat_index` and fills ATT&CK from `techniques`. Groups are OR. Entries in a group are AND. `negate: true` is DOES NOT MATCH. An entry with no `type` is sent as `type: mapping`.

<!-- rfc0006:rule-threat -->
```yaml
name: Created file matches a malware hash
metadata:
  uuid: 8c5d2f70-1a94-4e36-b8c2-5d7e9a1b3f48
  schema: rule::1.0
  version: 1
  created: "2026-09-29"
  modified: "2026-09-29"
  tlp: clear
  author: Detection Engineering
description: |
  Alerts when a created file's SHA256 matches a file indicator, or when
  its MD5 matches a file indicator and its path does not match the path
  carried on that indicator.
techniques: [T1204.002]
references:
  public:
    1: https://attack.mitre.org/techniques/T1204/002/
response:
  alert_severity: Critical
  procedure:
    analysis: |
      Open the matched indicator and the file path. Confirm the hash
      equality and whether the file was executed after it was written.
    containment: |
      Isolate the host and collect the file.
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    status: PRODUCTION
    type: threat_match
    language: kuery
    query: 'event.category : "file" and event.type : "creation"'
    index: [logs-endpoint.events.file-*]
    filters:
      - meta:
          key: event.dataset
          negate: false
          disabled: false
          type: phrase
          params:
            query: endpoint.events.file
        query:
          match_phrase:
            event.dataset: endpoint.events.file
    scheduling:
      interval: 1h
      from: 70m
    severity: Critical
    risk_score: 90
    severity_mapping:
      - field: file.extension
        operator: equals
        value: exe
        severity: critical
    risk_score_mapping:
      - field: host.risk.calculated_score_norm
        operator: equals
        value: ""
    alert_suppression:
      group_by: [host.name, file.hash.sha256]
      duration: 6h
      missing_fields_strategy: doNotSuppress
    investigation_fields: [file.hash.sha256, file.hash.md5, file.path, file.name, process.name]
    required_fields:
      - {name: file.hash.md5, type: keyword}
      - {name: file.hash.sha256, type: keyword}
      - {name: file.path, type: keyword}
    related_integrations:
      - endpoint
      - package: ti_abusech
        version: "*"
    max_signals: 500
    timestamp_override: event.ingested
    timestamp_override_fallback_disabled: false
    rule_name_override: file.hash.sha256
    license: Elastic License v2
    tags: [Windows, ThreatIntel]
    note: |
      The event query is file creation. The indicator query is under threat.
      The second mapping group is OR, and file.path DOES NOT MATCH.
    setup: |
      Elastic Defend file events plus a file-indicator index. Hashes must
      be keyword.
    false_positives:
      - A red-team hash left in the indicator index after an exercise.
    endpoint_exceptions: true
    exceptions_list:
      - id: 2b9f4d60-8e13-4c57-a0b6-5d7c1e8a3f24
        list_id: approved-software-hashes
        namespace_type: single
        type: detection
    building_block: false
    threat:
      index: [logs-ti_abusech.malware-*, logs-ti_misp.indicator-*]
      query: '@timestamp >= "now-30d/d" and threat.indicator.type : "file"'
      language: kuery
      indicator_path: threat.indicator
      filters:
        - meta:
            key: threat.indicator.marking.tlp
            negate: true
            disabled: false
            type: phrase
            params:
              query: red
          query:
            match_phrase:
              threat.indicator.marking.tlp: red
      mapping:
        - entries:
            - field: file.hash.sha256
              value: threat.indicator.file.hash.sha256
        - entries:
            - field: file.hash.md5
              value: threat.indicator.file.hash.md5
            - field: file.path
              value: threat.indicator.file.path
              negate: true
      concurrent_searches: 5
      items_per_search: 10000
    actions:
      - id: c4e8a1b2-6d30-4f57-9a18-3b7e5c0d2f64
        action_type_id: .slack
        group: default
        params:
          message: "Malware hash written on {{host.name}}: {{file.hash.sha256}}"
        frequency:
          summary: true
          notifyWhen: onActiveAlert
          throttle: null
    response_actions:
      - action_type_id: .endpoint
        params:
          command: isolate
          comment: Isolate the host that wrote a file matching a malware indicator.
    timeline_id: 6a4c1e80-3d25-4b97-9f10-7e2b8c5a1d63
    timeline_title: File hash investigation
```

**Example G: `machine_learning`.** No `query`, `index`, or `language`. `job_id` is a list here; a single job may be a string (`job_id: high_count_network_events`) and is sent unchanged.

<!-- rfc0006:rule-ml -->
```yaml
name: Anomalous network volume for a host
metadata:
  uuid: 1f6a9e23-4c80-4d57-a2b9-6e8c0d3f5a71
  schema: rule::1.0
  version: 1
  created: "2026-09-29"
  modified: "2026-09-29"
  tlp: clear
  author: Detection Engineering
description: |
  Raises an alert when the packetbeat anomaly jobs score a host at 75
  or above. The jobs already exist in the tenant; this rule only points
  at them.
techniques: [T1071]
references:
  public:
    1: https://attack.mitre.org/techniques/T1071/
response:
  alert_severity: Medium
  procedure:
    analysis: |
      Open the anomaly in the ML app for the job named on the alert.
    containment: |
      Isolate the workstation if the score stays high.
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    status: STAGING
    type: machine_learning
    scheduling:
      interval: 15m
      from: 16m
    severity: Medium
    risk_score: 42
    severity_mapping:
      - field: host.name
        operator: equals
        value: dc01
        severity: high
    risk_score_mapping:
      - field: host.risk.calculated_score_norm
        operator: equals
        value: ""
    alert_suppression:
      group_by: [host.name]
      duration: 3h
      missing_fields_strategy: suppress
    machine_learning:
      job_id:
        - high_count_network_events
        - high_count_network_denies
      anomaly_threshold: 75
    investigation_fields: [host.name, source.ip, destination.ip, network.transport]
    required_fields:
      - {name: destination.ip, type: ip}
      - {name: host.name, type: keyword}
      - {name: source.ip, type: ip}
    related_integrations: [packetbeat]
    max_signals: 100
    timestamp_override: event.ingested
    timestamp_override_fallback_disabled: false
    rule_name_override: host.name
    license: Elastic License v2
    tags: [Network, MachineLearning]
    note: |
      anomaly_threshold 75 is the Kibana anomaly score cutoff. The job's
      datafeed selects events. This block does not create the job.
    setup: |
      The named anomaly jobs must already be running in this tenant.
    false_positives:
      - Backup windows that the job has not baselined yet.
    endpoint_exceptions: false
    exceptions_list:
      - id: a6c1e840-5b27-4d90-8f13-2e9b7c4a1d58
        list_id: backup-network-hosts
        namespace_type: single
        type: detection
    building_block: false
    actions:
      - id: c4e8a1b2-6d30-4f57-9a18-3b7e5c0d2f64
        action_type_id: .slack
        group: default
        params:
          message: "Network anomaly score >= 75 for {{host.name}}"
        frequency:
          summary: true
          notifyWhen: onActiveAlert
          throttle: null
    response_actions:
      - action_type_id: .osquery
        params:
          query: SELECT pid, name, path, cmdline FROM processes;
          timeout: 60
          ecs_mapping: {}
    timeline_id: 2f7b9e40-5c18-4a62-8d30-1a6e4c8b0f75
    timeline_title: Network anomaly investigation
```

### Templates

OpenTide generates one rule template, `rule.1.0.template.yaml` ([workspace layout](../specs/workspace.md)). The Elastic block in it is a custom query, the create-rule UI's starting point. Each other rule type keeps this MDR and replaces the Elastic keys shown under it. The template leaves out the rule's own `status`: deployment reads `configurations.elastic.status`.

<!-- rfc0006:rule-template -->
```yaml
name: Rule name
metadata:
  uuid: 00000000-0000-4000-8000-000000000000
  schema: rule::1.0
  version: 1
  created: "2026-09-29"
  modified: "2026-09-29"
  tlp: clear
  author: Detection Engineering
description: |
  What this rule detects.
techniques: []
response:
  alert_severity: Medium
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
      from: 6m
```

`index: [logs-*]` is one pattern. `scheduling.from` is the whole window (Runs every plus one extra minute). `data_view_id` replaces `index`.

The keys that change with the rule type:

```yaml
# eql — no language
type: eql
query: |
  sequence by host.id with maxspan=1m
    [process where event.type == "start" and process.name == "x.exe"]
index: [logs-endpoint.events.process-*]
eql:
  timestamp_field: "@timestamp"
  event_category_override: event.category
  tiebreaker_field: event.sequence

# esql — no index and no language; FROM selects the data
type: esql
query: |
  FROM logs-*
  | STATS count = COUNT(*) BY host.name
  | WHERE count > 10

# threshold — suppression is a duration, with no group_by
type: threshold
query: 'event.category : "authentication" and event.outcome : "failure"'
index: [logs-*]
threshold:
  field: [source.ip]
  value: 20
  cardinality:
    field: user.name
    value: 5
alert_suppression:
  duration: 1h

# new_terms
type: new_terms
query: 'event.category : "iam"'
index: [logs-*]
new_terms:
  fields: [user.name]
  history_window_start: 14d

# threat_match — event query stays flat; indicator side is threat
type: threat_match
query: 'event.category : "file"'
index: [logs-*]
threat:
  index: [logs-ti_*]
  query: '@timestamp >= "now-30d/d"'
  mapping:
    - entries:
        - field: file.hash.sha256
          value: threat.indicator.file.hash.sha256

# machine_learning — no query and no index; a job id may be a string
type: machine_learning
machine_learning:
  job_id: rare_process_by_host
  anomaly_threshold: 50
```

**Invalid block.** It violates the constraints named in the comments.

<!-- rfc0006:invalid -->
```yaml
# expect: esql_source, language, suppression_shape, override_key
elastic:
  enabled: true
  schema: platform::elastic::1.0
  type: esql
  language: kuery
  query: FROM logs-* | LIMIT 10
  index: [logs-*]
  alert_suppression: {duration: 1h}
  overrides: {rule_id: my-own-id}
```


### 5. Deployment

Base path: `<url>/api/detection_engine/rules` for space `default`, otherwise `<url>/s/<space>/api/detection_engine/rules`.

Headers: `Authorization: ApiKey <api_key>`, `elastic-api-version: 2023-10-31`, `Content-Type: application/json`, and `kbn-xsrf: true` on non-GET requests.

| Strategy | Calls | Result |
|----------|-------|--------|
| `PREVIEW`, `RELEASE` | The [Elasticsearch checks](#elasticsearch-checks) first. Then `GET ?rule_id=<uuid>`. A 404 leads to `POST` with the compiled body. A 200 leads to `PUT` with the compiled body plus preserved fields, or to `DELETE` then `POST` when the remote `type` differs. | rule created or replaced, `enabled: true` |
| `DISABLEMENT` | same as above | rule kept, `enabled: false` |
| `DELETION` | `DELETE ?rule_id=<uuid>` | 200 or 404 both mean success |
| `INERT` | none | not deployed (planner) |

**Type changes.** `PUT` cannot change `type`; Kibana returns 400. When the remote `type` differs from the compiled one, the deployer MUST `DELETE` the rule and `POST` the compiled body plus the preserved fields. The `rule_id` stays the same. Kibana assigns a new internal `id`, so execution history starts again.

`PUT` replaces the whole rule. A field the block sets is sent as written. A field the block omits goes back to Kibana's default, except the fields below, which the deployer copies from the `GET` response when the block does not set them:

<!-- rfc0006:preserved-table -->
| Preserved field | Why |
|-----------------|-----|
| `actions` | connectors and notifications configured in Kibana |
| `exceptions_list` | exception lists attached in Kibana |
| `response_actions` | Elastic Defend and Osquery response actions |
| `timeline_id`, `timeline_title` | investigation Timeline template |
| `concurrent_searches`, `items_per_search`, `meta` | API-only fields the create UI does not show |
| `output_index`, `namespace`, `throttle` | legacy fields the create UI does not show |

The deployer MUST NOT modify an Elastic prebuilt rule. A prebuilt rule has `rule_source.type: external` (customised prebuilt rules included), or `immutable: true` on versions without `rule_source`. The deployer reports an error instead.

**Drift.** `GET` also returns server-side fields: `id`, `revision`, `created_at`, `updated_at`, `execution_summary`, `rule_source`, `immutable`, and defaults such as `max_signals` and `risk_score_mapping`. Kibana also adds `ecs` to each `required_fields` entry. A deployer that compares remote and compiled rules MUST compare only the compiled keys, and MUST ignore `required_fields[].ecs`.

Errors:

- 400 or 409 on one rule, or a failed Elasticsearch check: that rule fails with the server's `message`, and the batch continues.
- 401 or 403: that tenant fails, and the deployer moves to the next tenant.
- 429 and 5xx: retry up to three times with exponential backoff.

A deployer MAY list managed rules with a single `GET _find?filter=alert.attributes.tags:"OpenTide"` instead of one `GET` per rule. It MUST NOT delete a managed rule that has no MDR (orphan pruning is deferred).

### 6. Query validation

`elastic` joins the query-validation allowlist (`can_validate: true`). The language comes from each rule's block, not from the platform:

| Mode | Behaviour |
|------|-----------|
| Offline (`validate query`, default) | Structural checks per language. `kuery`: string, bracket, and `and`/`or`/`not` balance. `lucene`: the existing Lucene checker. `eql`: bracket and string balance, and a `where` or `sequence` form. `esql`: bracket and string balance, first command `FROM`, and no dangling `\|`. |
| Live (`validate query --live`) | `POST <base>/preview` with the compiled body plus `{"invocationCount": 1, "timeframeEnd": "<now>"}`. `timeframeEnd` MUST be UTC with a `Z` suffix (`2026-09-25T11:10:00.000Z`); Kibana rejects `+00:00` offsets with 400. The [Elasticsearch checks](#elasticsearch-checks) also run. |

Preview outcomes:

| Response | Result |
|----------|--------|
| HTTP 200, every `logs[].errors` empty | valid. `logs[].warnings` (for example a missing index) are reported as warnings. |
| HTTP 200 with `logs[].errors` | invalid, with the errors. A missing preview-index privilege error is a tenant configuration error, not a query error. |
| HTTP 400 | invalid: a rule-level schema error (for example `threshold.value: 0`, four `new_terms` fields) |
| `isAborted: true` | inconclusive |

Preview executes the rule once against live data and writes only to the preview alerts index. It catches KQL, Lucene, and EQL syntax errors, unknown EQL fields, ES\|QL syntax errors inside a command, unknown ES\|QL columns, and rule-level schema errors. Elasticsearch-only checks (`_validate/query`, `_eql/search`) cannot see the rule-level fields. Preview does not check licence-gated behaviour, on 9.x it does not catch an unknown ES\|QL command, and it cannot tell a misspelt aggregation field from one with no matches.

#### Elasticsearch checks

Kibana accepts some mistakes that make a rule fail silently. Before every `POST` or `PUT`, and during live validation, the deployer MUST run the two checks below against `elasticsearch_url` with the tenant's API key. HTTP 401, 403, 429, and 5xx follow the [deployment error rules](#5-deployment).

##### ES\|QL pre-flight

Kibana does not parse ES\|QL on create. `FROM logs-* METADATA _id | WHER process.name == "nope.exe"` creates with 200 on both 8.19.22 and 9.5.4, and what happens next depends on the version:

- **8.19.22:** preview reports the parse error, but every scheduled run fails, so the deployed rule never alerts.
- **9.5.4:** Kibana drops the unknown command. Preview reports no errors, and scheduled runs succeed and raise an alert for every document in the look-back window, as if the `WHERE` were absent.

A one-letter typo therefore becomes a dead rule on 8.19, or a rule that matches everything on 9.5.

Elasticsearch's own parser rejects the query, so the deployer sends every `esql` query to Elasticsearch with `LIMIT 0` appended:

<!-- rfc0006:esql-preflight -->
```json
{
  "query": "FROM logs-system.security-*, logs-windows.forwarded-*\n| WHERE event.code == \"4625\" AND winlog.event_data.SubStatus == \"0xC000006A\"\n| STATS failures = COUNT(*), accounts = COUNT_DISTINCT(user.name) BY source.ip\n| WHERE accounts >= 8 AND failures >= 20\n| LIMIT 0"
}
```

This is `POST <elasticsearch_url>/_query` for Example C. HTTP 200 means the query parses and resolves. Elasticsearch plans it but reads no documents (`documents_found: 0`). HTTP 400 fails the rule with the Elasticsearch `reason`, for example `mismatched input 'WHER'` or `Unknown column`.

**Sources not onboarded yet.** Elasticsearch parses before it resolves indices, so a mistyped command returns a `parsing_exception` even when no source index exists. Resolution then fails: a missing concrete index returns `Unknown index`, and a wildcard that matches nothing makes every referenced field an `Unknown column` (both `verification_exception`). Kibana deploys such a rule and warns `Unable to find matching indices` on each run until data arrives. To match that:

- A `parsing_exception` always fails the rule.
- On a `verification_exception`, the deployer MUST call `GET <elasticsearch_url>/_resolve/index/<FROM sources>?ignore_unavailable=true&allow_no_indices=true`. If `indices`, `aliases`, and `data_streams` are all empty, it deploys the rule with a warning. Otherwise the rule fails.

##### Aggregation field check

Kibana accepts any string as a field name. On 9.5.4, a field that does not exist fails silently, and a text field fails only when the rule runs:

| Field | Absent (for example misspelt) | `text` or `match_only_text` |
|-------|-------------------------------|------------------------------|
| `alert_suppression.group_by` | every alert collapses into one per window (`missing_fields_strategy: suppress`) | run error |
| `threshold.field`, `threshold.cardinality.field` | no alerts | run error |
| `new_terms_fields` | no alerts | run error |

The deployer checks these fields with `GET <elasticsearch_url>/<sources>/_field_caps?fields=<fields>&ignore_unavailable=true&allow_no_indices=true`. `<sources>` is the compiled `index`, or the `title` of the data view from `GET /api/data_views/data_view/<data_view_id>` in the tenant's space. Every field MUST be present with `aggregatable: true`; otherwise the rule fails. For `esql`, the `group_by` fields MUST instead be among the `columns` the pre-flight returns, because ES\|QL suppression groups on result columns.

`_field_caps` reads mappings, not documents, so a field that an integration's index template maps passes before any event carries it. If the response's `indices` list is empty, the sources are not onboarded yet, and the deployer deploys with a warning, as for ES\|QL. A rule with no explicit source (no `index`, `data_view_id`, or tenant `index`) uses the space's default index setting. The deployer skips the check for it with a warning.

### 7. Spec changes after acceptance

| File | Change |
|------|--------|
| `specs/platforms.md` → 1.1 | Add the `elastic` capability row (query languages KQL, Lucene, EQL, and ES\|QL), the required fields (`type`, `query`, plus the type block), and an Elastic block section. Add it to the query-validation allowlist. Raise the platform count by one (seven to eight, or eight to nine if [RFC 0004](https://github.com/OpenTideHQ/specifications/issues/8) lands first). |
| `specs/objects/rule-1.0.md` | Add `elastic` / `ElasticConfig` / `platform::elastic::1.0` to the `configurations` table (additive; `rule::1.0` unchanged) |
| `specs/validation.md` | Add `elastic` to the query-validation table, with offline and live modes as in §6 |
| `fixtures/valid/rule-elastic-1.0.yaml`, `fixtures/invalid/rule-elastic-esql-index.yaml` | New conformance fixtures from Examples A and "Invalid block" |
| `SPECS.md`, `CHANGELOG.md` | Index and history entries |

No vocabulary changes are required. A follow-up SHOULD add an explicit `domain` (enterprise, mobile, ics) to `att&ck.vocab.toml` so step 1 of [Threat](#threat) stops relying on name prefixes.

opentide adds an `opentide/platforms/elastic/` package with `client`, `deployer`, and `validator` modules, the entry point `elastic = "opentide.platforms.elastic:declare"`, bundled `elastic.toml`, `ElasticConfig`, the `Elastic` tenant model, and offline checkers for `kuery`, `eql`, and `esql`. It uses `requests`, which is already a core dependency, so no new extra is needed.

## Drawbacks

- **Four query languages on one platform.** Offline validation becomes per-rule rather than per-platform, and it is structural only. Semantic errors (unknown fields, type mismatches) surface only in live mode.
- **Preview costs a real query.** Live validation runs each rule once against production-sized data. CI SHOULD point `--live` at a staging tenant.
- **API key coupling.** Rules keep running with the deploying key's privileges. Rotating or revoking that key needs a full redeploy, or the rules stop.
- **Two calls per rule** (`GET` plus `POST` or `PUT`). This is acceptable for hundreds of rules. `_find` pre-fetch halves it. Bulk import is deferred.
- **Suppression depends on operator configuration.** Kibana ignores suppression on a Basic licence without reporting it, and a least-privilege key cannot read the licence. If a tenant's `suppression` flag is wrong, rules deploy cleanly but alert on every match.
- **Two endpoints per tenant.** The deployer needs Elasticsearch (`elasticsearch_url`) as well as Kibana, for checks that Kibana does not do.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| One platform per deployment type (`elastic_cloud`, `elastic_serverless`, …) | The API and schemas are identical, so this would triple configuration for no behavioural difference. |
| `_import` ndjson with `overwrite=true` as the only path | One call per batch, but `overwrite` replaces `actions` and `exceptions_list` unless the deployer round-trips them. Per-rule errors come back in an aggregate response, and multipart upload complicates proxies. Kept as a future fast path. |
| `PATCH` instead of `PUT` | It cannot remove a field the author deleted from YAML (for example `alert_suppression`), so remote state would drift from the MDR. |
| Emit `detection-rules` TOML or Terraform HCL | Adds an external toolchain and state file; both wrap the same API. |
| Raw passthrough block (`body: {...}`) | Loses typed validation and ATT&CK derivation. A field the create UI shows is a key on the block. |
| `saved_query` / `saved_id` | The query text lives in a Kibana saved object. The id differs in every space, and a Discover edit changes the rule with no diff. The same detection is `type: query` with `query`, `language`, and `filters`. |
| Leave type-specific keys flat (`threat_index`, `machine_learning_job_id`, …) | The create UI already groups them. A conditional object keeps the indicator side, the EQL settings, and the job next to each other. The compiler still sends Kibana's flat names. |
| Validate only through Elasticsearch (`_validate/query`, `_eql/search`, `_query`) | Cannot check the rule-level fields (threshold, new terms, suppression shape) that preview checks. It is used for ES\|QL only, because Kibana does not parse ES\|QL on create. |
| Detect the licence instead of a `suppression` flag | Needs the `monitor` cluster privilege (`GET _license`) or Kibana's `/api/licensing/info`, which is internal-only on 9.x. Neither fits a least-privilege deploy key, and Serverless tiers are not licences. |
| Strip `alert_suppression` from every tenant, never send it | Loses a core noise control on Platinum, Enterprise, and Serverless tenants that support it. |
| ISO 8601 durations only, as in the Sentinel block | Kibana itself rejects `PT5M`, and authors copy durations from Kibana. ISO 8601 stays accepted on input. |
| An enum of `group_by` field names | Fields come from each tenant's data, including custom fields. The aggregation field check verifies them against the tenant instead. |

## Unresolved questions

| Question | Proposed direction |
|----------|--------------------|
| Exceptions as code | Separate RFC mapping per-tenant exclusions (as in Sentinel and Defender) to `/api/exception_lists` and rule `exceptions_list`. Until then, exceptions are Kibana-managed and preserved. |
| Orphan pruning | Report rules tagged `OpenTide` that have no MDR. Deletion stays opt-in in a later revision. |
| Bulk path for large catalogues | `_import` fast path behind a tenant flag, after per-rule semantics are proven |
| Deriving `required_fields` and `related_integrations` | Elastic's `detection-rules` builds both at release time from the query AST, bundled ECS and integration schemas, and a package list (`integration = ["windows"]`). A later revision MAY fill `required_fields` from the query and `_field_caps`, leaving the block optional. |
| Kibana not parsing ES\|QL on create | Report it upstream. A later revision MAY make the pre-flight optional on Kibana versions that reject invalid ES\|QL on create. |

## Appendix A: reference test

The design was checked against local single-node self-managed clusters: Kibana and Elasticsearch 8.19.22 on Basic, and 9.5.4 on Basic and then trial. A throwaway harness compiled Examples A–E with the reference compiler in `scripts/test_rfc_0006.py` and deployed them to space `staging` with the key below. The harness needs a live cluster, so it is not committed.

```json
{
  "name": "opentide-deployer-staging",
  "role_descriptors": {
    "opentide_deployer": {
      "indices": [
        {"names": ["logs-*", "winlogbeat-*"], "privileges": ["read", "view_index_metadata"]},
        {"names": [".preview.alerts-security.alerts-staging", ".internal.preview.alerts-security.alerts-staging-*"], "privileges": ["read"]}
      ],
      "applications": [
        {"application": "kibana-.kibana", "privileges": ["feature_securitySolutionRulesV4.all"], "resources": ["space:staging"]}
      ]
    }
  }
}
```

This is the `POST /_security/api_key` body for 9.5.4. On 8.19.22 the application privilege is `feature_siemV2.all`.

| Check | 8.19.22 | 9.5.4 |
|-------|---------|-------|
| Create Examples A–E, then `GET` | every sent field returned; Kibana adds `required_fields[].ecs` | same |
| Duplicate `POST` | 409 | 409 |
| Identical `PUT` | 200, `revision` unchanged | same |
| `PUT` without preserved fields, then with them copied | `exceptions_list` and Timeline dropped, then kept | same |
| `PUT` omitting `enabled` | remote value kept | same |
| `PUT` changing `type`, then `DELETE` + `POST` | 400, then 200 with the same `rule_id` and preserved fields | same |
| No `kbn-xsrf`; unknown `elastic-api-version`; no version header | 400; 400; default version used | same |
| Preview of Examples A–E | 200, no errors | same |
| Preview of broken KQL, EQL, or ES\|QL syntax, or an unknown ES\|QL column | 200 with `logs[].errors` | same |
| Preview with `threshold.value: 0` or four `new_terms` fields | 400 | same |
| ES\|QL `… \| WHER …` | create 200; preview error; scheduled runs `failed` | create 200; preview clean; scheduled run `succeeded`, 3 alerts for 3 documents |
| `_query` pre-flight with `\| LIMIT 0` | 400 for the typo, 200 for Example C | same |
| Pre-flight on sources with no index | not run | typo: `parsing_exception`; field reference: `Unknown column`; `_resolve/index` empty; Kibana preview warns only |
| `interval` values | not run | `90s`, `2h`, `1d` accepted; `1w` and `PT5M` rejected (400) |
| `from` / `history_window_start` values | not run | `now-150m`, `now-1d`, `now-8d`, `now-2w` accepted |
| Suppression duration unit `d` | not run | 400 (only `s`, `m`, `h`) |
| `required_fields` without `type`; unknown type; wrong type for an ECS field | not run | 400; accepted with `ecs: false`; accepted with `ecs: false` |
| `related_integrations` without `version`; `version: ""`; `version: "*"` | not run | 400; 400; accepted |
| `group_by` absent field, text field, duplicate, `""` | not run | all accepted on create; preview: absent field collapses 8 alerts into 1, text field is a run error |
| `threshold.field` or `new_terms.fields` absent | not run | no alerts, no error |
| `_field_caps` with the deploy key | not run | absent field missing; `message` `aggregatable: false`; a mapped field with no documents present and aggregatable; data view readable |
| Examples A–E after the notation change (short durations, `required_fields` as `{name, type}` objects, `related_integrations: [endpoint]`) | not run | Elasticsearch checks pass; create 200; `GET` matches; preview clean |
| Same `rule_id` in spaces `staging` and `prod`; twice in one space | not run | 200 and 200 with different internal `id`s; 409 |
| Alert document | not run | `kibana.alert.rule.rule_id` is the MDR UUID |
| Suppression by `host.name`, `user.name` over events from one entity (Basic) | stored; scheduled run `succeeded`, 12 alerts for 12 events | same |
| The same suppression (trial) | — | preview: 1 alert for 6 events |
| `DELETE` twice | 200, then 404 | same |

## References

- Issue: [OpenTideHQ/specifications#17](https://github.com/OpenTideHQ/specifications/issues/17)
- Kibana detection engine OpenAPI (`2023-10-31`): [elastic/kibana `security_solution/docs/openapi`](https://github.com/elastic/kibana/tree/main/x-pack/solutions/security/plugins/security_solution/docs/openapi)
- [Kibana API: Security detections](https://www.elastic.co/docs/api/doc/kibana/group/endpoint-security-detections-api) · [Serverless](https://www.elastic.co/docs/api/doc/serverless/group/endpoint-security-detections-api)
- [Spaces and Elastic Security](https://www.elastic.co/docs/solutions/security/get-started/spaces-elastic-security)
- [elastic/detection-rules](https://github.com/elastic/detection-rules) · [terraform-provider-elasticstack](https://github.com/elastic/terraform-provider-elasticstack)
- [platforms.md](../specs/platforms.md) · [rule-1.0.md](../specs/objects/rule-1.0.md) · [deployment.md](../specs/deployment.md) · [validation.md](../specs/validation.md)
