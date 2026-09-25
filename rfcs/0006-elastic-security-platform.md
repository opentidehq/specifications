# RFC 0006: Elastic Security detection platform

- **RFC:** 0006
- **Title:** Elastic Security detection platform
- **Author:** OpenTide maintainers
- **Status:** draft
- **Created:** 2026-09-25
- **Issue:** [OpenTideHQ/specifications#17](https://github.com/OpenTideHQ/specifications/issues/17)
- **PR:** (pending)

## Summary

Add a detection platform, `elastic` (display name **Elastic Security**, schema `platform::elastic::1.0`), that deploys OpenTide rules as Elastic Security detection rules through the Kibana detection engine API (`/api/detection_engine/rules`, public API version `2023-10-31`).

Decisions:

1. **One platform for every Elastic deployment type.** Self-managed, Elastic Cloud Hosted, and Elastic Cloud Serverless Security expose the same rule API with the same request schemas. The deployment type only changes the tenant URL, credentials, and which features a licence enables. There is no `edition` switch.
2. **Target the Security detection engine, not generic Kibana alerting.** Detection rules are the only Elastic rules that land in the Security app, write to `.alerts-security.alerts-*`, carry ATT&CK mappings, and support exceptions.
3. **Five rule types in v1:** `query`, `eql`, `esql`, `threshold`, `new_terms`. `threat_match` and `machine_learning` are deferred. `saved_query` is excluded.
4. **Identity is the MDR UUID.** Kibana's user-settable `rule_id` is set to `metadata.uuid`, so no platform ID is written back to the rule file.
5. **Validation:** offline syntax checks per query language, plus live validation through the rule preview API. ES\|QL rules also get a mandatory Elasticsearch parse check before every deploy, because Kibana accepts and runs ES\|QL with a mistyped command ([ES\|QL pre-flight](#esql-pre-flight)).

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

| Type | Query language | v1 | Kibana fields required beyond the common set |
|------|----------------|----|-----------------------------------------------|
| `query` | KQL (`kuery`) or Lucene | yes | — |
| `eql` | EQL | yes | `language: eql`, `query` |
| `esql` | ES\|QL | yes | `language: esql`, `query`; no `index` (the `FROM` clause selects data) |
| `threshold` | KQL or Lucene | yes | `query`, `threshold.field`, `threshold.value` |
| `new_terms` | KQL or Lucene | yes | `query`, `new_terms_fields` (1–3), `history_window_start` |
| `threat_match` | KQL | deferred | `threat_index`, `threat_query`, `threat_mapping`: indicator indices are tenant state |
| `machine_learning` | — | deferred | `machine_learning_job_id`, `anomaly_threshold`: ML jobs are tenant state and need a paid licence |
| `saved_query` | — | excluded | references a Kibana saved object, so it is not portable |

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
| `elasticsearch_url` | string | no | null | Elasticsearch base URL of the same deployment. Required for tenants that receive `esql` rules ([ES\|QL pre-flight](#esql-pre-flight)). |
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
            api_key: str
            elasticsearch_url: str | None = None
            space: str = "default"
            index: Sequence[str] | None = None
            tags: Sequence[str] | None = None
            suppression: bool = True

        setup: Setup

    tenants: Sequence[Tenant] | None = None
```

**API key.** One Elasticsearch API key serves both Kibana and the Elasticsearch pre-flight. Rules run with the privileges of the key that last created or updated them, and revoking that key stops them. Each tenant SHOULD therefore use a dedicated, non-personal key that holds:

- Kibana: Security rules management `All` in the tenant's space. This is the `feature_securitySolutionRulesV4.all` application privilege on 9.5, and `feature_siemV2.all` on 8.19. On 9.5, `feature_siemV5.all` alone returns 403 on rule create.
- Elasticsearch: `read` and `view_index_metadata` on every source index pattern the rules query. The ES\|QL pre-flight needs nothing more, and no cluster privilege is needed.
- Live validation only: `read` on `.preview.alerts-security.alerts-<space>` and `.internal.preview.alerts-security.alerts-<space>-*`.

Kibana renames feature privileges between versions (`siemV2` on 8.19; `siemV5` and `securitySolutionRulesV4` on 9.5), so `platforms.md` will not pin them. [Appendix A](#appendix-a-reference-test) shows the tested key.

### 2. Rule block (`platform::elastic::1.0`)

```python
class ElasticConfig(PlatformConfigBase):
    __schema_identifier__: ClassVar[str] = "platform::elastic::1.0"
    type: Literal["query", "eql", "esql", "threshold", "new_terms"]
    query: QueryText
    language: Literal["kuery", "lucene"] | None = None   # query / threshold / new_terms
    index: list[str] | None = None
    data_view_id: str | None = None
    scheduling: ElasticScheduling = ElasticScheduling()
    alert: ElasticAlert = ElasticAlert()
    threshold: ElasticThreshold | None = None             # type: threshold
    new_terms: ElasticNewTerms | None = None              # type: new_terms
    eql: ElasticEql | None = None                         # type: eql
    tags: list[str] | None = None
    note: str | None = None                               # investigation guide (markdown)
    setup: str | None = None                              # setup guide (markdown)
    false_positives: list[str] | None = None
    required_fields: list[ElasticRequiredField] | None = None
    related_integrations: list[ElasticIntegration] | None = None
    building_block: bool = False
    overrides: dict[str, Any] | None = None               # unmodelled Kibana fields

class ElasticScheduling(TideModel):
    frequency: str = "PT5M"      # ISO 8601 -> interval
    lookback: str = "PT6M"       # ISO 8601 total window -> from: now-<lookback>

class ElasticAlert(TideModel):
    severity: str | None = None               # alert_severity vocabulary
    risk_score: int | None = None             # 0–100, overrides the severity default
    suppression: ElasticSuppression | None = None
    investigation_fields: list[str] | None = None

class ElasticSuppression(TideModel):
    group_by: list[str] | None = None         # 1–3 fields; not for threshold
    duration: str | None = None               # ISO 8601; required for threshold
    missing_fields: Literal["suppress", "doNotSuppress"] = "suppress"

class ElasticThreshold(TideModel):
    field: list[str] = []                     # 0–5 fields; [] counts all matches
    value: int                                # >= 1
    cardinality: ElasticCardinality | None = None   # {field: str, value: int >= 0}

class ElasticNewTerms(TideModel):
    fields: list[str]                         # 1–3
    history_window: str                       # ISO 8601 -> history_window_start

class ElasticEql(TideModel):
    timestamp_field: str | None = None
    event_category_override: str | None = None
    tiebreaker_field: str | None = None

class ElasticRequiredField(TideModel):
    name: str
    type: str

class ElasticIntegration(TideModel):
    package: str
    version: str
    integration: str | None = None
```

**Model constraints.** Validation MUST reject a block that breaks any of these:

<!-- rfc0006:constraints-table -->
| Code | Constraint |
|------|------------|
| `type_block` | `threshold` is required iff `type: threshold`, `new_terms` iff `type: new_terms`; `eql` is allowed only for `type: eql` |
| `language` | `language` MUST NOT be set for `eql` or `esql` |
| `esql_source` | `esql` MUST NOT set `index` or `data_view_id` |
| `index_xor_data_view` | `index` and `data_view_id` are mutually exclusive |
| `suppression_shape` | For `threshold`: `suppression.duration` is required and `group_by` is forbidden. For other types: `group_by` is required, with 1–3 fields. |
| `new_terms_fields` | `new_terms.fields` has 1–3 entries |
| `threshold_fields` | `threshold.field` has 0–5 entries; `threshold.value` >= 1 |
| `risk_score` | `alert.risk_score` is an integer in 0–100 |
| `duration` | Every duration is ISO 8601 `P[nD][T[nH][nM][nS]]` with whole seconds, > 0 |
| `override_key` | `overrides` MUST NOT contain a key from the [field mapping](#3-field-mapping) or [preserved fields](#5-deployment) tables |

Validation SHOULD warn when `scheduling.lookback` < `scheduling.frequency` (gaps between runs), and when a non-aggregating ES\|QL query (no `STATS`) lacks `METADATA _id` (alerts are not deduplicated).

### 3. Field mapping

The deployer compiles each MDR into a Kibana create or update body:

<!-- rfc0006:mapping-table -->
| Kibana field | Source | Rule |
|--------------|--------|------|
| `rule_id` | `metadata.uuid` | verbatim |
| `type` | `type` | verbatim |
| `name` | block `name`, else rule `name` | |
| `description` | rule `description` | trailing whitespace stripped |
| `enabled` | block `status` | `false` iff status strategy is `DISABLEMENT`. Always sent, because a `PUT` without it keeps the remote value. |
| `severity`, `risk_score` | `alert.severity`, else `response.alert_severity`, else `Informational` | [Severity](#severity); `alert.risk_score` overrides the score |
| `interval` | `scheduling.frequency` | [Durations](#durations) |
| `from` | `scheduling.lookback` | `now-<duration>` |
| `to` | — | `now` |
| `language` | `type`, `language` | `eql` → `eql`, `esql` → `esql`, else `language` or `kuery` |
| `query` | `query` | trailing whitespace stripped |
| `index` | block `index`, else tenant `setup.index` | omitted for `esql`, when `data_view_id` is set, or when both sources are empty |
| `data_view_id` | `data_view_id` | verbatim |
| `threshold` | `threshold` | `cardinality` becomes a one-item list |
| `new_terms_fields`, `history_window_start` | `new_terms.fields`, `new_terms.history_window` | `now-<duration>` |
| `timestamp_field`, `event_category_override`, `tiebreaker_field` | `eql.*` | verbatim |
| `alert_suppression` | `alert.suppression` | `{group_by, duration?, missing_fields_strategy}`; for threshold `{duration}` only. Omitted when tenant `setup.suppression` is `false`. |
| `investigation_fields` | `alert.investigation_fields` | `{field_names: [...]}` |
| `required_fields`, `related_integrations`, `false_positives`, `setup` | same-named block field | verbatim |
| `building_block_type` | `building_block: true` | `"default"` |
| `tags` | `"OpenTide"`, tenant `setup.tags`, block `tags` | in that order, de-duplicated |
| `author` | `metadata.author`, `metadata.contributors` | de-duplicated; omitted if empty |
| `references` | `references.public` | values in ascending key order |
| `note` | block `note`, else `response.procedure.analysis` | trailing whitespace stripped |
| `threat` | resolved techniques | [Threat](#threat) |
| anything else | `overrides` | merged last (for example `max_signals`, `timestamp_override`, `rule_name_override`, `severity_mapping`, `filters`) |

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

ISO 8601 durations convert to the largest unit that divides the value exactly. `interval`, `from`, and suppression use `h`, `m`, or `s`. `history_window_start` also uses `d`.

<!-- rfc0006:duration-table -->
| ISO 8601 | `interval` / `from` | `alert_suppression.duration` | `history_window_start` |
|----------|---------------------|------------------------------|------------------------|
| `PT5M` | `5m` / `now-5m` | `{value: 5, unit: m}` | `now-5m` |
| `PT90S` | `90s` / `now-90s` | `{value: 90, unit: s}` | `now-90s` |
| `PT1H` | `1h` / `now-1h` | `{value: 1, unit: h}` | `now-1h` |
| `P1D` | `24h` / `now-24h` | `{value: 24, unit: h}` | `now-1d` |
| `P14D` | `336h` / `now-336h` | `{value: 336, unit: h}` | `now-14d` |

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
status: STAGING
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
    type: query
    language: kuery
    query: |
      event.category : "process" and event.type : "start" and
      process.name : ("powershell.exe" or "pwsh.exe") and
      process.args : ("-enc" or "-EncodedCommand")
    index: [logs-endpoint.events.process-*, winlogbeat-*]
    scheduling:
      frequency: PT5M
      lookback: PT9M
    alert:
      suppression:
        group_by: [host.name, user.name]
        duration: PT1H
      investigation_fields: [process.command_line, process.parent.name]
    tags: [Windows]
    required_fields:
      - {name: process.args, type: keyword}
      - {name: process.name, type: keyword}
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
    eql: {tiebreaker_field: event.sequence}
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
    scheduling: {frequency: PT15M, lookback: PT15M}
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
    alert:
      suppression: {duration: PT30M}
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
    new_terms:
      fields: [host.name, user.name]
      history_window: P14D
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
  alert:
    suppression: {duration: PT1H}       # suppression_shape: group_by required
  overrides: {rule_id: my-own-id}       # override_key
```

### 5. Deployment

Base path: `<url>/api/detection_engine/rules` for space `default`, otherwise `<url>/s/<space>/api/detection_engine/rules`.

Headers: `Authorization: ApiKey <api_key>`, `elastic-api-version: 2023-10-31`, `Content-Type: application/json`, and `kbn-xsrf: true` on non-GET requests.

| Strategy | Calls | Result |
|----------|-------|--------|
| `PREVIEW`, `RELEASE` | For `esql`, the [pre-flight](#esql-pre-flight) first. Then `GET ?rule_id=<uuid>`. A 404 leads to `POST` with the compiled body. A 200 leads to `PUT` with the compiled body plus preserved fields, or to `DELETE` then `POST` when the remote `type` differs. | rule created or replaced, `enabled: true` |
| `DISABLEMENT` | same as above | rule kept, `enabled: false` |
| `DELETION` | `DELETE ?rule_id=<uuid>` | 200 or 404 both mean success |
| `INERT` | none | not deployed (planner) |

**Type changes.** `PUT` cannot change `type`; Kibana returns 400. When the remote `type` differs from the compiled one, the deployer MUST `DELETE` the rule and `POST` the compiled body plus the preserved fields. The `rule_id` stays the same. Kibana assigns a new internal `id`, so execution history starts again.

`PUT` replaces the whole rule and deletes unspecified fields. On update the deployer MUST copy these fields from the `GET` response, so analyst work done in Kibana survives redeploys:

<!-- rfc0006:preserved-table -->
| Preserved field | Why |
|-----------------|-----|
| `actions` | connectors and notifications configured in Kibana |
| `exceptions_list` | exception lists attached in Kibana |
| `response_actions` | Elastic Defend and Osquery response actions |
| `timeline_id`, `timeline_title` | investigation Timeline template |

The deployer MUST NOT modify an Elastic prebuilt rule. A prebuilt rule has `rule_source.type: external` (customised prebuilt rules included), or `immutable: true` on versions without `rule_source`. The deployer reports an error instead.

**Drift.** `GET` also returns server-side fields: `id`, `revision`, `created_at`, `updated_at`, `execution_summary`, `rule_source`, `immutable`, and defaults such as `max_signals` and `risk_score_mapping`. Kibana also adds `ecs` to each `required_fields` entry. A deployer that compares remote and compiled rules MUST compare only the compiled keys, and MUST ignore `required_fields[].ecs`.

Errors:

- 400 or 409 on one rule, or a failed ES\|QL pre-flight: that rule fails with the server's `message`, and the batch continues.
- 401 or 403: that tenant fails, and the deployer moves to the next tenant.
- 429 and 5xx: retry up to three times with exponential backoff.

A deployer MAY list managed rules with a single `GET _find?filter=alert.attributes.tags:"OpenTide"` instead of one `GET` per rule. It MUST NOT delete a managed rule that has no MDR (orphan pruning is deferred).

### 6. Query validation

`elastic` joins the query-validation allowlist (`can_validate: true`). The language comes from each rule's block, not from the platform:

| Mode | Behaviour |
|------|-----------|
| Offline (`validate query`, default) | Structural checks per language. `kuery`: string, bracket, and `and`/`or`/`not` balance. `lucene`: the existing Lucene checker. `eql`: bracket and string balance, and a `where` or `sequence` form. `esql`: bracket and string balance, first command `FROM`, and no dangling `\|`. |
| Live (`validate query --live`) | `POST <base>/preview` with the compiled body plus `{"invocationCount": 1, "timeframeEnd": "<now>"}`. `timeframeEnd` MUST be UTC with a `Z` suffix (`2026-09-25T11:10:00.000Z`); Kibana rejects `+00:00` offsets with 400. For `esql`, the [pre-flight](#esql-pre-flight) also runs. |

Preview outcomes:

| Response | Result |
|----------|--------|
| HTTP 200, every `logs[].errors` empty | valid. `logs[].warnings` (for example a missing index) are reported as warnings. |
| HTTP 200 with `logs[].errors` | invalid, with the errors. A missing preview-index privilege error is a tenant configuration error, not a query error. |
| HTTP 400 | invalid: a rule-level schema error (for example `threshold.value: 0`, four `new_terms` fields) |
| `isAborted: true` | inconclusive |

Preview executes the rule once against live data and writes only to the preview alerts index. It catches KQL, Lucene, and EQL syntax errors, unknown EQL fields, ES\|QL syntax errors inside a command, unknown ES\|QL columns, and rule-level schema errors. Elasticsearch-only checks (`_validate/query`, `_eql/search`) cannot see the rule-level fields. Preview does not check licence-gated behaviour, and on 9.x it does not catch an unknown ES\|QL command.

#### ES\|QL pre-flight

Kibana does not parse ES\|QL on create. `FROM logs-* METADATA _id | WHER process.name == "nope.exe"` creates with 200 on both 8.19.22 and 9.5.4, and what happens next depends on the version:

- **8.19.22:** preview reports the parse error, but every scheduled run fails, so the deployed rule never alerts.
- **9.5.4:** Kibana drops the unknown command. Preview reports no errors, and scheduled runs succeed and raise an alert for every document in the look-back window, as if the `WHERE` were absent.

A one-letter typo therefore becomes a dead rule on 8.19, or a rule that matches everything on 9.5.

Elasticsearch's own parser rejects the query. Before every `POST` or `PUT` of an `esql` rule, and during live validation, the deployer MUST send the query to Elasticsearch with `LIMIT 0` appended:

<!-- rfc0006:esql-preflight -->
```json
{
  "query": "FROM logs-system.auth-*, logs-windows.forwarded-*\n| WHERE event.category == \"authentication\" AND event.outcome == \"failure\"\n| STATS failures = COUNT(*), users = COUNT_DISTINCT(user.name) BY source.ip\n| WHERE users >= 10\n| LIMIT 0"
}
```

This is `POST <elasticsearch_url>/_query` for Example C, sent with the tenant's API key. HTTP 200 means the query parses and resolves. Elasticsearch plans it but reads no documents (`documents_found: 0`). HTTP 400 fails the rule with the Elasticsearch `reason`, for example `mismatched input 'WHER'` or `Unknown column`. 401, 403, 429, and 5xx follow the [deployment error rules](#5-deployment). A tenant without `elasticsearch_url` MUST fail every `esql` rule, and the deployer MUST NOT skip the check.

**Sources not onboarded yet.** Elasticsearch parses before it resolves indices, so a mistyped command returns a `parsing_exception` even when no source index exists. Resolution then fails: a missing concrete index returns `Unknown index`, and a wildcard that matches nothing makes every referenced field an `Unknown column` (both `verification_exception`). Kibana deploys such a rule and warns `Unable to find matching indices` on each run until data arrives. To match that:

- A `parsing_exception` always fails the rule.
- On a `verification_exception`, the deployer MUST call `GET <elasticsearch_url>/_resolve/index/<FROM sources>?ignore_unavailable=true&allow_no_indices=true`. If `indices`, `aliases`, and `data_streams` are all empty, it deploys the rule with a warning. Otherwise the rule fails.

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
- **Two endpoints for ES\|QL.** Tenants that receive `esql` rules need `elasticsearch_url` reachable from the deployer, in addition to Kibana.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| One platform per deployment type (`elastic_cloud`, `elastic_serverless`, …) | The API and schemas are identical, so this would triple configuration for no behavioural difference. |
| `_import` ndjson with `overwrite=true` as the only path | One call per batch, but `overwrite` replaces `actions` and `exceptions_list` unless the deployer round-trips them. Per-rule errors come back in an aggregate response, and multipart upload complicates proxies. Kept as a future fast path. |
| `PATCH` instead of `PUT` | It cannot remove a field the author deleted from YAML (for example `alert_suppression`), so remote state would drift from the MDR. |
| Emit `detection-rules` TOML or Terraform HCL | Adds an external toolchain and state file; both wrap the same API. |
| Raw passthrough block (`body: {...}`) | Loses typed validation and ATT&CK derivation. `overrides` covers the long tail without giving up the typed core. |
| Validate only through Elasticsearch (`_validate/query`, `_eql/search`, `_query`) | Cannot check the rule-level fields (threshold, new terms, suppression shape) that preview checks. It is used for ES\|QL only, because Kibana does not parse ES\|QL on create. |
| Detect the licence instead of a `suppression` flag | Needs the `monitor` cluster privilege (`GET _license`) or Kibana's `/api/licensing/info`, which is internal-only on 9.x. Neither fits a least-privilege deploy key, and Serverless tiers are not licences. |
| Strip `alert_suppression` from every tenant, never send it | Loses a core noise control on Platinum, Enterprise, and Serverless tenants that support it. |

## Unresolved questions

| Question | Proposed direction |
|----------|--------------------|
| Exceptions as code | Separate RFC mapping per-tenant exclusions (as in Sentinel and Defender) to `/api/exception_lists` and rule `exceptions_list`. Until then, exceptions are Kibana-managed and preserved. |
| Orphan pruning | Report rules tagged `OpenTide` that have no MDR. Deletion stays opt-in in a later revision. |
| `threat_match` and `machine_learning` | `platform::elastic::1.1` once indicator-index and ML-job references have a tenant-level model |
| Bulk path for large catalogues | `_import` fast path behind a tenant flag, after per-rule semantics are proven |
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
