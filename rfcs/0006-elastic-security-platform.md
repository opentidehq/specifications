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
3. **Every rule type the Security UI can create:** `query`, `saved_query`, `eql`, `esql`, `threshold`, `new_terms`, `threat_match`, and `machine_learning`.
4. **Identity is the MDR UUID.** Kibana's user-settable `rule_id` is set to `metadata.uuid`. It is unique per space, so one UUID serves every tenant, and alerts carry it as `kibana.alert.rule.rule_id`. Kibana's internal `id` is never stored, and nothing is written back to the rule file.
5. **Validation:** offline syntax checks per query language, plus live validation through the rule preview API. Two Elasticsearch checks also run before every deploy, because Kibana accepts a mistyped ES\|QL command or aggregation field and the rule then fails silently ([Elasticsearch checks](#elasticsearch-checks)).
6. **Kibana's own names.** Durations are written `5m`, `1h`, `14d`. `required_fields` is a list of `{name, type}` objects, and a package name may stand for a related integration. Every other key is the Kibana field the create-rule UI writes. `overrides` is only for a field that UI does not show.

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

| Type | UI name | Query language | Required beyond the common set |
|------|---------|----------------|------------------------------|
| `query` | Custom query | KQL (`kuery`) or Lucene | — |
| `saved_query` | Custom query, saved query loaded on every run | the saved query's | `saved_id` |
| `eql` | Event correlation | EQL | `query` |
| `esql` | ES\|QL | ES\|QL | `query`; no `index` (the `FROM` clause selects data) |
| `threshold` | Threshold | KQL or Lucene | `query`, `threshold.field`, `threshold.value` |
| `new_terms` | New terms | KQL or Lucene | `query`, `new_terms_fields` (1–3), `history_window_start` |
| `threat_match` | Indicator match | KQL or Lucene | `query`, `threat_index`, `threat_query`, `threat_mapping` |
| `machine_learning` | Machine learning | — | `machine_learning_job_id`, `anomaly_threshold` |

**New terms** alerts when a value, or a combination of up to three values, shows up that the rule has not seen in the history window. A rule with `new_terms_fields: [host.name, user.name]` and `history_window_start: 14d` alerts when that host and user appear together in the current run and did not appear together in the previous 14 days. It does not count events. That is what a threshold rule does.

`saved_id`, `threat_index`, and `machine_learning_job_id` are names that exist in one tenant. The block carries them as written; nothing rewrites them into a shared identifier.

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
    type: Literal["query", "saved_query", "eql", "esql", "threshold", "new_terms", "threat_match", "machine_learning"]
    query: QueryText | None = None
    language: Literal["kuery", "lucene"] | None = None
    saved_id: str | None = None
    index: list[str] | None = None
    data_view_id: str | None = None
    filters: list[dict[str, Any]] | None = None          # the filter objects the UI saves
    interval: Duration = "5m"                            # Runs every
    from_: Duration = "6m"                               # data_key "from": total window, sent as now-<from>
    severity: str | None = None                          # alert_severity vocabulary
    risk_score: int | None = None                        # 0–100
    severity_mapping: list[ElasticSeverityMapping] | None = None
    risk_score_mapping: list[ElasticRiskScoreMapping] | None = None
    alert_suppression: ElasticSuppression | None = None
    investigation_fields: list[str] | None = None        # Custom highlighted fields
    threshold: ElasticThreshold | None = None
    new_terms_fields: list[str] | None = None
    history_window_start: Duration | None = None
    timestamp_field: str | None = None                   # EQL settings
    event_category_override: str | None = None
    tiebreaker_field: str | None = None
    threat_index: list[str] | None = None
    threat_query: str | None = None
    threat_language: Literal["kuery", "lucene"] | None = None
    threat_mapping: list[ElasticThreatGroup] | None = None
    threat_filters: list[dict[str, Any]] | None = None
    threat_indicator_path: str | None = None             # Indicator prefix override
    concurrent_searches: int | None = None               # API only; not in the create UI
    items_per_search: int | None = None
    machine_learning_job_id: str | list[str] | None = None
    anomaly_threshold: int | None = None
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
```

**Model constraints.** Validation MUST reject a block that breaks any of these:

<!-- rfc0006:constraints-table -->
| Code | Constraint |
|------|------------|
| `type_block` | `threshold` iff `type: threshold`. `new_terms_fields` and `history_window_start` iff `type: new_terms`. `timestamp_field`, `event_category_override`, and `tiebreaker_field` only for `eql`. `threat_index`, `threat_query`, and `threat_mapping` iff `type: threat_match`. `machine_learning_job_id` and `anomaly_threshold` iff `type: machine_learning`. `saved_id` iff `type: saved_query`. `query` is required except for `machine_learning` and `saved_query`. |
| `language` | `language` MUST NOT be set for `eql`, `esql`, or `machine_learning` |
| `esql_source` | `esql` and `machine_learning` MUST NOT set `index` or `data_view_id` |
| `index_xor_data_view` | `index` and `data_view_id` are mutually exclusive |
| `suppression_shape` | For `threshold`: `alert_suppression.duration` is required and `group_by` is forbidden. For other types: `group_by` is required, with 1–3 distinct, non-empty field names. |
| `new_terms_fields` | `new_terms_fields` has 1–3 entries |
| `threshold_fields` | `threshold.field` has 0–5 entries; `threshold.value` >= 1 |
| `risk_score` | `risk_score` is an integer in 0–100 |
| `duration` | Every duration is a positive integer followed by `s`, `m`, `h`, or `d`, or ISO 8601 `P[nD][T[nH][nM][nS]]` with whole seconds, and is > 0 |
| `override_key` | `overrides` MUST NOT contain a key from the [field mapping](#3-field-mapping) or [preserved fields](#5-deployment) tables |

Validation SHOULD warn when `from` < `interval` (the next run starts after the window ends), and when a non-aggregating ES\|QL query (no `STATS`) lacks `METADATA _id` (alerts are not deduplicated).

**Field names are open-ended.** `alert_suppression.group_by`, `threshold.field`, `new_terms_fields`, `investigation_fields`, and `required_fields[].name` name fields in the tenant's data: ECS, integration-specific, or custom. They cannot be an enum, and Kibana accepts any string for them. The deployer therefore checks aggregation fields against the tenant ([Aggregation field check](#aggregation-field-check)). `type` is closed. Of the 2,617 fields in ECS, 75% are `keyword`; the other types are `long`, `date`, `boolean`, `object`, `flattened`, `float`, `nested`, `wildcard`, `ip`, `geo_point`, `double`, `scaled_float`, `constant_keyword`, and `match_only_text`. `FieldType` lists those plus the other common Elasticsearch mapping types. Kibana sets `required_fields[].ecs` only when both the name and the type match ECS.

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
| `interval` | `interval` | [Durations](#durations). This is the UI's Runs every. Default `5m`. |
| `from` | `from` | `now-<duration>`. This is the whole window Kibana queries, not the UI's Additional look-back time. Additional look-back is `from` minus `interval`. Default `6m`, which is one extra minute. |
| `to` | — | `now`. The UI does not expose it. |
| `language` | `type`, `language` | `eql` → `eql`, `esql` → `esql`; omitted for `machine_learning`; else `language` or `kuery` |
| `query` | `query` | trailing whitespace stripped; omitted for `machine_learning` and when `saved_query` has no query |
| `saved_id` | `saved_id` | verbatim |
| `index` | block `index`, else tenant `setup.index` | omitted for `esql` and `machine_learning`, when `data_view_id` is set, or when both sources are empty |
| `data_view_id`, `filters` | same-named block field | verbatim |
| `threshold` | `threshold` | `cardinality` is one `{field, value}` and is sent as a one-item list |
| `new_terms_fields` | `new_terms_fields` | verbatim |
| `history_window_start` | `history_window_start` | `now-<duration>` |
| `timestamp_field`, `event_category_override`, `tiebreaker_field` | same-named block field | verbatim |
| `threat_index`, `threat_query`, `threat_language`, `threat_filters`, `threat_indicator_path` | same-named block field | verbatim |
| `threat_mapping` | `threat_mapping` | an entry with no `type` is sent as `type: mapping` |
| `concurrent_searches`, `items_per_search` | same-named block field | verbatim. Not in the create UI. On update, an omitted value is kept from the remote rule. |
| `machine_learning_job_id`, `anomaly_threshold` | same-named block field | verbatim |
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

`threat` is derived from the resolved technique set: the rule's `techniques`, plus techniques inherited through `detection_model` (objective, then threats, using the same resolver as Sentinel), de-duplicated. The Sentinel deployer uses only the inherited set. Elastic deliberately takes the union, so a rule's own `techniques` are never dropped.

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

**Example A: `query` rule.** This is a complete MDR.

<!-- rfc0006:rule-query -->
```yaml
name: Encoded PowerShell command line
metadata:
  uuid: 3f6c2a1e-8b4d-4c1a-9e2f-5a7b8c9d0e11
  schema: rule::1.0
  version: 1
  created: "2026-09-25"
  modified: "2026-09-25"
  tlp: clear
  author: SOC Detection Engineering
description: |
  Detects PowerShell started with an encoded command argument.
techniques: [T1059.001]
references:
  public:
    1: https://attack.mitre.org/techniques/T1059/001
response:
  alert_severity: High
  procedure:
    analysis: |
      Decode the -EncodedCommand payload and review the parent process.
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    status: STAGING
    type: query
    language: kuery
    query: |
      event.category : "process" and event.type : "start" and
      process.name : ("powershell.exe" or "pwsh.exe") and
      process.args : ("-enc" or "-EncodedCommand")
    index: [logs-endpoint.events.process-*, winlogbeat-*]
    interval: 5m
    from: 9m
    alert_suppression:
      group_by: [host.name, user.name]
      duration: 1h
    investigation_fields: [process.command_line, process.parent.name]
    tags: [Windows]
    required_fields:
      - {name: process.args, type: keyword}
      - {name: process.name, type: keyword}
    related_integrations: [endpoint]
```

This is the compiled body for tenant `elastic-staging`. It is sent as `POST https://soc-staging.kb.eu-west-1.aws.elastic.cloud/s/staging/api/detection_engine/rules`:

<!-- rfc0006:body-query -->
```json
{
  "rule_id": "3f6c2a1e-8b4d-4c1a-9e2f-5a7b8c9d0e11",
  "type": "query",
  "name": "Encoded PowerShell command line",
  "description": "Detects PowerShell started with an encoded command argument.",
  "enabled": true,
  "severity": "high",
  "risk_score": 73,
  "interval": "5m",
  "from": "now-9m",
  "to": "now",
  "language": "kuery",
  "query": "event.category : \"process\" and event.type : \"start\" and\nprocess.name : (\"powershell.exe\" or \"pwsh.exe\") and\nprocess.args : (\"-enc\" or \"-EncodedCommand\")",
  "index": ["logs-endpoint.events.process-*", "winlogbeat-*"],
  "alert_suppression": {
    "group_by": ["host.name", "user.name"],
    "duration": {"value": 1, "unit": "h"},
    "missing_fields_strategy": "suppress"
  },
  "investigation_fields": {"field_names": ["process.command_line", "process.parent.name"]},
  "required_fields": [
    {"name": "process.args", "type": "keyword"},
    {"name": "process.name", "type": "keyword"}
  ],
  "related_integrations": [{"package": "endpoint", "version": "*"}],
  "tags": ["OpenTide", "Windows"],
  "author": ["SOC Detection Engineering"],
  "references": ["https://attack.mitre.org/techniques/T1059/001"],
  "note": "Decode the -EncodedCommand payload and review the parent process.",
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {"id": "TA0002", "name": "Execution", "reference": "https://attack.mitre.org/tactics/TA0002/"},
      "technique": [
        {
          "id": "T1059",
          "name": "Command and Scripting Interpreter",
          "reference": "https://attack.mitre.org/techniques/T1059",
          "subtechnique": [
            {"id": "T1059.001", "name": "PowerShell", "reference": "https://attack.mitre.org/techniques/T1059/001"}
          ]
        }
      ]
    }
  ]
}
```

Examples B–E list only the rule keys they need. Every other key (`description`, metadata dates, `references`) comes from Example A, and a listed top-level key replaces Example A's key whole. Each JSON block is a subset of the compiled body for tenant `elastic-staging`.

**Example B: `eql` sequence, one technique with two tactics.**

<!-- rfc0006:rule-eql -->
```yaml
name: Service created with sc.exe then started
metadata: {uuid: 7a1d4e2b-3c5f-4b6a-8d9e-0f1a2b3c4d5e}
techniques: [T1543.003]
response: {alert_severity: Medium}
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    type: eql
    query: |
      sequence by host.id with maxspan=1m
        [process where event.type == "start" and process.name == "sc.exe" and process.args == "create"]
        [process where event.type == "start" and process.parent.name == "services.exe"]
    index: [logs-endpoint.events.process-*]
    tiebreaker_field: event.sequence
```

<!-- rfc0006:fragment-eql -->
```json
{
  "type": "eql",
  "language": "eql",
  "severity": "medium",
  "risk_score": 47,
  "interval": "5m",
  "from": "now-6m",
  "tiebreaker_field": "event.sequence",
  "tags": ["OpenTide"],
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {"id": "TA0003", "name": "Persistence", "reference": "https://attack.mitre.org/tactics/TA0003/"},
      "technique": [
        {"id": "T1543", "name": "Create or Modify System Process", "reference": "https://attack.mitre.org/techniques/T1543",
         "subtechnique": [{"id": "T1543.003", "name": "Windows Service", "reference": "https://attack.mitre.org/techniques/T1543/003"}]}
      ]
    },
    {
      "framework": "MITRE ATT&CK",
      "tactic": {"id": "TA0004", "name": "Privilege Escalation", "reference": "https://attack.mitre.org/tactics/TA0004/"},
      "technique": [
        {"id": "T1543", "name": "Create or Modify System Process", "reference": "https://attack.mitre.org/techniques/T1543",
         "subtechnique": [{"id": "T1543.003", "name": "Windows Service", "reference": "https://attack.mitre.org/techniques/T1543/003"}]}
      ]
    }
  ]
}
```

**Example C: aggregating `esql`.** No `index` is sent.

<!-- rfc0006:rule-esql -->
```yaml
name: Password spraying from one source
metadata: {uuid: 9c2e5f1a-6b7d-4e8f-a1b2-c3d4e5f6a7b8}
techniques: [T1110.003]
response: {alert_severity: High}
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    type: esql
    query: |
      FROM logs-system.auth-*, logs-windows.forwarded-*
      | WHERE event.category == "authentication" AND event.outcome == "failure"
      | STATS failures = COUNT(*), users = COUNT_DISTINCT(user.name) BY source.ip
      | WHERE users >= 10
    interval: 15m
    from: 15m
```

<!-- rfc0006:fragment-esql -->
```json
{
  "type": "esql",
  "language": "esql",
  "interval": "15m",
  "from": "now-15m",
  "tags": ["OpenTide"],
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {"id": "TA0006", "name": "Credential Access", "reference": "https://attack.mitre.org/tactics/TA0006/"},
      "technique": [
        {"id": "T1110", "name": "Brute Force", "reference": "https://attack.mitre.org/techniques/T1110",
         "subtechnique": [{"id": "T1110.003", "name": "Password Spraying", "reference": "https://attack.mitre.org/techniques/T1110/003"}]}
      ]
    }
  ]
}
```

**Example D: `threshold` with suppression.** The tenant's `index` is not used here because the block sets its own.

<!-- rfc0006:rule-threshold -->
```yaml
name: Brute force against one account
metadata: {uuid: 1b3d5f7a-9c2e-4a6b-8d0f-2e4a6c8e0a1b}
techniques: [T1110]
response: {alert_severity: Medium}
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    type: threshold
    query: 'event.category : "authentication" and event.outcome : "failure"'
    index: [logs-*]
    threshold:
      field: [user.name, source.ip]
      value: 25
    alert_suppression: {duration: 30m}
```

<!-- rfc0006:fragment-threshold -->
```json
{
  "type": "threshold",
  "language": "kuery",
  "query": "event.category : \"authentication\" and event.outcome : \"failure\"",
  "index": ["logs-*"],
  "threshold": {"field": ["user.name", "source.ip"], "value": 25},
  "alert_suppression": {"duration": {"value": 30, "unit": "m"}}
}
```

**Example E: `new_terms`, disabled.** The block's `status: DISABLED` maps to the `DISABLEMENT` strategy, so the rule stays in Kibana with `enabled: false`.

<!-- rfc0006:rule-new-terms -->
```yaml
name: First local account creation on a host
metadata: {uuid: 5e7a9c1b-2d4f-4a6c-8e0a-1b3d5f7a9c2e}
techniques: [T1136.001]
response: {alert_severity: Low}
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    status: DISABLED
    type: new_terms
    query: 'event.category : "iam" and event.action : "added-user-account"'
    index: [logs-system.security-*]
    new_terms_fields: [host.name, user.name]
    history_window_start: 14d
```

<!-- rfc0006:fragment-new-terms -->
```json
{
  "type": "new_terms",
  "enabled": false,
  "severity": "low",
  "risk_score": 21,
  "new_terms_fields": ["host.name", "user.name"],
  "history_window_start": "now-14d"
}
```

**Example F: indicator match.** Entries in one group are AND. A second group would be OR. `type: mapping` is filled in when the entry omits it.

<!-- rfc0006:rule-threat -->
```yaml
name: Known malware hash written to disk
metadata: {uuid: 4e8b1c2d-6f7a-4b9e-8c0d-1a2b3c4d5e6f}
description: A created file matches a malware hash from the threat index.
techniques: [T1204.002]
response: {alert_severity: Critical}
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    type: threat_match
    query: 'event.category : "file" and event.type : "creation"'
    index: [logs-endpoint.events.file-*]
    threat_index: [logs-ti_*]
    threat_query: '@timestamp >= "now-30d/d"'
    threat_mapping:
      - entries:
          - {field: file.hash.sha256, value: threat.indicator.file.hash.sha256}
    threat_indicator_path: threat.indicator
```

**Example G: machine learning.** The job id is the name of a job that already exists in that tenant.

<!-- rfc0006:rule-ml -->
```yaml
name: Anomalous network volume
metadata: {uuid: 8a0c2e4f-1b3d-4e5f-9a6b-7c8d9e0f1a2b}
description: The network-event anomaly job scored this entity at 75 or above.
response: {alert_severity: Medium}
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    type: machine_learning
    machine_learning_job_id: [high_count_network_events]
    anomaly_threshold: 75
```

**Advanced settings, on any of the rules above.** Each key is the Kibana field the UI writes.

<!-- rfc0006:gui-fields -->
```yaml
max_signals: 200
timestamp_override: event.ingested
timestamp_override_fallback_disabled: true
rule_name_override: event.action
license: Elastic License v2
severity_mapping:
  - {field: host.name, operator: equals, severity: high, value: dc1}
risk_score_mapping:
  - {field: event.risk_score, operator: equals, value: ""}
endpoint_exceptions: true
filters:
  - {meta: {negate: true}, query: {match_all: {}}}
```

**Invalid block.** It violates the constraints named in the comments.

<!-- rfc0006:invalid -->
```yaml
# expect: esql_source, language, suppression_shape, override_key
elastic:
  enabled: true
  schema: platform::elastic::1.0
  type: esql
  language: kuery                       # language
  query: FROM logs-* | LIMIT 10
  index: [logs-*]                       # esql_source
  alert_suppression: {duration: 1h}       # suppression_shape: group_by required
  overrides: {rule_id: my-own-id}       # override_key
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
  "query": "FROM logs-system.auth-*, logs-windows.forwarded-*\n| WHERE event.category == \"authentication\" AND event.outcome == \"failure\"\n| STATS failures = COUNT(*), users = COUNT_DISTINCT(user.name) BY source.ip\n| WHERE users >= 10\n| LIMIT 0"
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
