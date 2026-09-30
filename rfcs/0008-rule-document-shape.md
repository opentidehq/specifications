# RFC 0008: Detection rule document shape (`rule::2.0`)

- **RFC:** 0008
- **Title:** Detection rule document shape (`rule::2.0`)
- **Author:** OpenTide maintainers
- **Status:** draft
- **Created:** 2026-09-30
- **Revised:** 2026-09-30 — `objective` replaces `detection_model`; deployment `status` lives only on platform blocks; platform blocks are specified in full; versioning 1.1 is a required part of this change
- **Issue:** [OpenTideHQ/specifications#24](https://github.com/OpenTideHQ/specifications/issues/24)
- **Implementation:** [OpenTideHQ/opentide#394](https://github.com/OpenTideHQ/opentide/issues/394)

## Summary

Give the detection rule the same document shape as a threat and an objective. `name`, `metadata`, and `references` stay on the envelope. The detection itself moves into a required `rule:` body: narrative, severity, ATT&CK techniques, the objective this rule implements, the response block, and one key per platform.

Deployment status is not a field of that body. Deploy, promotion, and every platform deployer already read `status` from the platform block. `rule::2.0` keeps it there and drops the unused root `status` from `rule::1.0`.

The link to a detection objective is renamed from `detection_model` to `objective`. The value is still that objective's UUID.

`configurations:` and the legacy `platforms:` dict go away on this revision. Each platform block keeps the schema it has today (`platform::sentinel::1.0` and the others), written out in full below so the rule spec stops pointing at a partial table. The schema identifier is `rule::2.0`. Documents that still declare `rule::1.0` stay valid.

Shipping that identifier requires a versioning contract the current spec does not state. Registry routing can hold two revisions. Deploy, documentation, templates, editor mapping, and the rule loader cannot. Versioning 1.1 is part of accepting this RFC, not a later cleanup.

## Motivation

`rule::1.0` ([specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md)) puts the detection on the document root and then wraps every platform payload in `configurations`, with a second untyped `platforms` map beside it:

```yaml
name: Sentinel KQL Rule
metadata:
  schema: rule::1.0
description: Detects credential access via suspicious process creation
status: STAGING                 # deploy does not read this
severity: High
techniques: [T1059]
detection_model: 00000000-0000-4000-8002-000000000001
response:
  alert_severity: High
configurations:
  sentinel:
    enabled: true
    status: STAGING             # this is the status deploy, promotion, and the Sentinel deployer read
    query: |
      SecurityEvent | take 1
```

Two of those root fields are the wrong shape:

- **`status`.** [deployment.md](../specs/deployment.md) says promotion rewrites status inside platform blocks. `PromoteMDR` only walks `configurations.<platform>.status` (`opentide/mutation/promotion.py`). Sentinel, Defender, Splunk, SentinelOne, CrowdStrike, HarfangLab, and Carbon Black all call `check_status` on the platform block. The root field is what the documentation renderer prints and what MCP returns. It is not the deployment status.
- **`detection_model`.** The value is an objective UUID. Generated metaschema tags it `tide.vocab: objective` (`generation/pydantic_metaschema.py`). The catalogue parent edge is that same key (`generation/framework.py`). The name describes an internal edge, not the object an author is linking.

Platform payloads are a separate problem only because they were never written down. [platforms.md](../specs/platforms.md) lists a handful of required fields and defers the rest to generated JSON Schema. The models in `opentide/models/platform.py` and `platform_configs.py` are the schema authors actually validate against. This RFC copies those models into the rule revision so `rule::2.0` and the platform blocks cannot drift from each other by omission.

## Detailed design

### Document shape (`rule::2.0`)

New spec file: `specs/objects/rule-2.0.md`. Schema id: `rule::2.0`.

`rule::1.0` stays normative. Instances that declare it keep today's layout, including root `status` and `detection_model`. Deprecating `rule::1.0` waits until an implementation can load both shapes and a migrate command can rewrite a file. See [Versioning](#versioning-11).

#### Envelope

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Rule display name. Same place as on threats and objectives. |
| `metadata` | ObjectMetadata | yes | [metadata.md](../specs/metadata.md). `metadata.schema` MUST be `rule::2.0`. |
| `rule` | RuleBody | yes | Detection body. |
| `references` | ObjectReferences | no | Same object as on `rule::1.0`. |

The document root MUST NOT contain `description`, `status`, `severity`, `techniques`, `detection_model`, `objective`, `response`, `configurations`, or `platforms`.

#### `rule` (RuleBody)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `description` | string | yes | — | Rule narrative. |
| `severity` | string | no | `Informational` | Rule severity vocabulary. Classifies the detection. Distinct from `response.alert_severity` and from a platform alert's own `severity`. |
| `techniques` | list[string] | no | `[]` | ATT&CK technique IDs for this detection. MAY be empty. Distinct from technique lists inside a platform alert. |
| `objective` | string (UUID) | no | null | UUID of the detection objective this rule implements. |
| `response` | RuleResponse | no | null | Same response, procedure, and search objects as `rule::1.0`. |
| `<platform>` | platform block | no | — | One optional key per platform identifier. Schemas in [Platform blocks](#platform-blocks). |

There is no `status` on this body. Deployment status is `rule.<platform>.status`.

Reserved body keys are `description`, `severity`, `techniques`, `objective`, and `response`. A platform identifier MUST NOT reuse a reserved key.

A rule is deployable when at least one platform block has `enabled: true`. A body with no platform keys is valid. Static validation MUST NOT require a platform block. Deployment MUST.

`objective` MUST be a UUIDv4 when set, and cross-object validation MUST resolve it to an objective the way `rule::1.0` resolves `detection_model`. It is not a vocabulary pin.

#### Why `objective`

The field names the thing the UUID points at. Objectives already point at threats with `objective.threats`. A rule points at one objective, so the field is singular.

Names considered and set aside:

| Name | Why it loses |
|------|----------------|
| `detection_model` | Current name. Reads as a model object, and the only model in the file is the rule. |
| `implements` | Hides the target type. |
| `parent` | Signals already use `parent` for a signal UUID. A rule's parent is specifically an objective. |
| `detection_objective` | Repeats the family name the key already sits under (`rule.objective`). |

#### Response block

Unchanged from `rule::1.0` (`opentide/models/response.py`):

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `alert_severity` | string | no | `Informational` |
| `playbook` | string | no | null |
| `responders` | string | no | null |
| `procedure` | ResponseProcedure | no | null |

`procedure`: `analysis` (string, required when `procedure` is present), `searches` (list, optional), `containment` (string, optional). Each search has `purpose`, `system`, and `query`, all required.

#### Example

```yaml
name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::2.0
  version: 1
  created: "2026-01-01"
  modified: "2026-01-02"
  tlp: clear
rule:
  description: |
    Detects credential access via suspicious process creation.
  severity: High
  techniques: [T1059]
  objective: 00000000-0000-4000-8002-000000000001
  response:
    alert_severity: High
  sentinel:
    enabled: true
    schema: platform::sentinel::1.0
    name: Sentinel KQL Rule
    status: STAGING
    query: |
      SecurityEvent
      | where EventID == 4688
      | take 1
    scheduling:
      frequency: PT1H
      lookback: PT2H
    alert:
      title: Sentinel KQL Rule
      suppression: false
references:
  public:
    1: https://example.invalid/writeup
```

#### Vocabulary pins

New section in [schemas/pins/rule.toml](../schemas/pins/rule.toml). `rule::1.0` pins stay on their current paths. `objective` is a UUID reference, not a pin.

```toml
["rule::2.0"]
"metadata.tlp" = "tlp::1.0"
"rule.severity" = "severity::1.0"
"rule.techniques" = "att&ck::1.0"
"rule.response.alert_severity" = "alert_severity::1.0"
"rule.response.responders" = "responders::1.0"
```

#### Fixtures (on acceptance, not in this RFC)

| Fixture | Role |
|---------|------|
| `fixtures/valid/rule-2.0.yaml` | The example above, plus one disabled platform block with `status` omitted. |
| `fixtures/invalid/rule-2.0-missing-body.yaml` | No `rule` key. |
| `fixtures/invalid/rule-2.0-configurations.yaml` | `configurations:` present. |
| `fixtures/invalid/rule-2.0-root-status.yaml` | `status` on the envelope or on `rule`. |
| `fixtures/invalid/rule-2.0-enabled-without-status.yaml` | `enabled: true` and no platform `status`. |
| `fixtures/valid/rule-1.0.yaml` | Unchanged. |

### Platform blocks

Location on `rule::2.0`: `rule.<platform>`. Location on `rule::1.0`: `configurations.<platform>` (legacy `platforms.<platform>` still loads). The block schemas are the same in both revisions.

Optionality below is the Pydantic model that validates today (`opentide/models/platform.py`, `platform_configs.py`), plus the `rule::2.0` rule that an enabled block MUST set `status`. [platforms.md](../specs/platforms.md) is a short required-field list and is not this schema. Where that list and the model disagree, this section follows the model and records the disagreement.

Every block extends this base:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | boolean | no | `false` | Whether this platform block is active. |
| `name` | string | no | `""` | Platform-specific rule name. |
| `schema` | string | no | null | Platform schema id, for example `platform::sentinel::1.0`. |
| `status` | string | when `enabled` is true | null | Deployment status name from merged `deployment.toml`. The only status on a `rule::2.0` rule. On `rule::1.0` the model still allows it to be omitted; deploy then fails inside `check_status`. |
| `flags` | list[string] | no | null | Platform flags. |
| `tenants` | list[string] | no | null | Target tenant identifiers. |
| `contributors` | list[string] | no | null | Platform contributors. |

`query`, wherever a block requires it, MUST be a non-empty string after stripping whitespace (`QueryText`).

Adding an optional platform key (Elastic, once [RFC 0007](0007-elastic-security-platform.md) is in the platform matrix) is a non-breaking edit of `rule::2.0`. It does not allocate `rule::2.1`. Platform schema ids version on their own axis. A future `platform::sentinel::2.0` is selected by the block's `schema` field and does not bump the rule schema by itself.

Identifiers and schema ids:

| Key | Model | Schema id |
|-----|-------|-----------|
| `sentinel` | SentinelConfig | `platform::sentinel::1.0` |
| `defender_for_endpoint` | DefenderConfig | `platform::defender_for_endpoint::1.0` |
| `splunk` | SplunkConfig | `platform::splunk::1.0` |
| `sentinel_one` | SentinelOneConfig | `platform::sentinel_one::1.0` |
| `crowdstrike` | CrowdstrikeConfig | `platform::crowdstrike::1.0` |
| `harfanglab` | HarfangLabConfig | `platform::harfanglab::1.0` |
| `carbon_black_cloud` | CarbonBlackConfig | `platform::carbon_black_cloud::1.0` |
| `elastic` | ElasticConfig | `platform::elastic::1.0` |

`elastic` is specified by [RFC 0007](0007-elastic-security-platform.md) and is not in the opentide model yet. Its top-level fields are listed at the end of this section so the key set is complete. Which of those fields are required depends on `type` and is the constraint table in that RFC (`query` is required except for `machine_learning`; `type` is always required). Nested types stay there too; this document does not restate them.

Deploy-written id maps are optional authoring fields on the models today. Names differ by platform and this RFC does not rename them: Defender uses `rule_id: map[string, integer]`; SentinelOne uses `rule_id_bundle: map[string, integer]`; CrowdStrike, HarfangLab, and Carbon Black use `rule_id_bundle: map[string, string]`. Sentinel has no such field.

#### Sentinel (`platform::sentinel::1.0`)

Required on the block, beyond the base: `query`, `scheduling`, `alert`.

| Field | Type | Required |
|-------|------|----------|
| `query` | string | yes |
| `scheduling` | SentinelScheduling | yes |
| `alert` | SentinelAlert | yes |
| `exclusions` | list[SentinelExclusion] | no |
| `template` | SentinelTemplate | no |
| `trigger` | SentinelTrigger | no |
| `grouping` | SentinelGrouping | no |
| `entities` | list[SentinelEntityMapping] | no |

`scheduling` (the object is required; its fields are optional in the model, which is looser than platforms.md's "frequency and lookback required"):

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `nrt` | boolean | no | null |
| `frequency` | string (ISO 8601 duration) | no | null |
| `lookback` | string (ISO 8601 duration) | no | null |

`alert`:

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `title` | string | no | null |
| `description` | string | no | null |
| `severity` | string | no | null |
| `suppression` | string or boolean | no | `false` |
| `create_incident` | boolean | no | `true` |
| `tactics` | list[string] | no | null |
| `techniques` | list[string] | no | null |
| `custom_details` | list[{`key`, `column`}] | no | null |
| `dynamic_properties` | list[{`property`, `column`}] | no | null |

`custom_details[]` and `dynamic_properties[]` require both of their fields. `grouping.event` is required when `grouping` is present. `grouping.alert`, when present, requires `enabled` (boolean) and may set `reopen_closed_incidents`, `grouping_lookback`, `matching`, `group_by_entities`, `group_by_alert_details`, `group_by_custom_details`. `entities[]` requires `entity` and `mappings[]` of `{identifier, column}`. `template` requires `uuid` and `version`. `trigger` requires `operator` and `threshold` (integer). `exclusions[]` requires `query` and `reason`, and may set `tenant` and `let` (map).

#### Defender for Endpoint (`platform::defender_for_endpoint::1.0`)

Required on the block, beyond the base: `query`, `alert`, `impacted_entities`, `scheduling`.

| Field | Type | Required |
|-------|------|----------|
| `query` | string | yes |
| `alert` | DefenderAlert | yes |
| `impacted_entities` | DefenderImpactedEntities | yes |
| `scheduling` | `NRT` \| `1H` \| `3H` \| `12H` \| `24H` | yes |
| `rule_id` | map[string, integer] | no |
| `actions` | DefenderResponseActions | no |
| `scope` | DefenderGroupScoping | no |
| `exclusions` | list[DefenderExclusion] | no |

`alert.category` is required. Optional alert fields: `title`, `description`, `severity`, `recommendation`, `techniques`. `impacted_entities` may set `device`, `mailbox`, and `user`; the object is required even when all three are omitted. `scope.selection` is `All` or `Specific`, with optional `device_groups`. Exclusions match Sentinel exclusions (`query`, `reason`, optional `tenant`, optional `let`).

`actions.devices`: `isolate_device` (string), `collect_investigation_package` (boolean, default false), `run_antivirus_scan` (boolean, default false), `initiate_investigation` (boolean, default false), `restrict_app_execution` (boolean, default false). `actions.files.allow_block`: `action` (`Allow` or `Block`), `identifier`, optional `groups` (`selection` `All` or `Specific`, optional `device_groups`). `actions.files.quarantine_file` is an optional string. `actions.users`: `mark_as_compromised`, `disable_user`, `force_password_reset`, each an optional string.

#### Splunk (`platform::splunk::1.0`)

Required on the block, beyond the base: `query`.

| Field | Type | Required |
|-------|------|----------|
| `query` | string | yes |
| `scheduling` | SplunkScheduling | no |
| `trigger` | SplunkTrigger | no |
| `actions` | SplunkActions | no |
| `correlation_search` | boolean | no |
| `advanced` | map | no |

`scheduling`: optional `type`, `expires`, `schedule`, `timerange`. `schedule`: optional `frequency`, `cron`, `custom_time`. `timerange`: optional `lookback`, `earliest`, `latest`.

`trigger`: optional `condition`, `comparator`, `threshold` (integer), `severity` (integer), `custom_condition`, `type`, `throttling`. `throttling`: optional `fields`, `duration`, `group_name`.

`actions.notable.event`: optional `title`, `description`. `actions.notable.drilldown`: optional `name`, `search`. `actions.notable.security_domain`: optional string. `actions.risk`: optional `message`, `risk_objects[]` (`field`, `type`, `score` integer, all required on an entry), `threat_objects[]` (`field`, `type`, both required on an entry). `actions.email`: optional `to`, `cc`, `bcc`, `priority`, `subject`, `message`, `content_type`, `send_csv`, `send_pdf`, `inline_results`, and `include` (`results_link`, `search_string`, `trigger_condition`, `trigger_time`, each optional booleans).

Before field validation, `normalize_splunk_v2` accepts older spellings and fills the canonical fields when those are absent. The legacy keys stay on the object so a file round-trips. `rule::2.0` keeps that normalizer.

| Legacy input | Canonical field filled when empty |
|--------------|-----------------------------------|
| `search` | `query` |
| `cron_schedule` | `scheduling.schedule.cron` |
| `scheduling.frequency`, `scheduling.cron`, `scheduling.custom_time` | `scheduling.schedule.*` |
| `scheduling.lookback` | `scheduling.timerange.lookback` |
| root `throttling`, root `threshold` | `trigger.throttling`, `trigger.threshold` |
| root `notable`, `risk`, `email` | `actions.notable`, `actions.risk`, `actions.email` |

`search`, `cron_schedule`, and `advanced` are hidden from templates. They remain valid input.

#### SentinelOne (`platform::sentinel_one::1.0`)

Required on the block, beyond the base: `condition`.

| Field | Type | Required |
|-------|------|----------|
| `condition` | SentinelOneCondition | yes |
| `response` | SentinelOneResponse | no |
| `details` | SentinelOneDetails | no |
| `rule_id_bundle` | map[string, integer] | no |

`condition.type` is `Single Event` or `Correlation`. `condition.cool_off` is optional. `single_event.query` is required when `single_event` is present. `correlation` requires `entity`, `match_in_order`, `time_window`, and `sub_queries[]` of `{query, matches_required}`. The model does not require `single_event` when type is `Single Event`, nor `correlation` when type is `Correlation`; the deployer and query validator reject a missing side at deploy time. `rule::2.0` keeps that split: schema validation matches the model, and deploy still requires the side the type names.

`response`, when present, requires `treat_as_threat` (`false`, `Malicious`, or `Suspicious`) and `network_quarantine` (boolean). `details`: optional `name`, `description`, `severity`, `expiration`.

#### CrowdStrike (`platform::crowdstrike::1.0`)

Required on the block, beyond the base: `details`, `schedule`, `query`. Query validation is not offered for this platform.

| Field | Type | Required |
|-------|------|----------|
| `details` | CrowdstrikeDetails | yes |
| `schedule` | CrowdstrikeSchedule | yes |
| `query` | string | yes |
| `rule_id_bundle` | map[string, string] | no |

`details.trigger` and `details.outcome` are required. Optional: `name`, `description`, `severity`, `tactic`, `technique`. `schedule.frequency` and `schedule.lookback` are required. Optional: `start`, `end`.

#### HarfangLab (`platform::harfanglab::1.0`)

No query field. The deployer requires at least one of `sigma` or `yara` and rejects a block that has neither. The model allows both to be omitted; `rule::2.0` keeps that deploy-time check. Query validation is not offered for this platform.

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `maturity` | string | no | `Experimental` |
| `confidence` | string | no | `Moderate` |
| `action` | string | no | `Alert` |
| `tags` | list[string] | no | null |
| `sigma` | HarfangLabSigma | no | null |
| `yara` | HarfangLabYara | no | null |
| `rule_id_bundle` | map[string, string] | no | null |

`sigma.logsource` requires `category` and `product`. `sigma.selections[]` requires `name`, `field`, and `value` (`string`, list of strings, boolean, integer, or float) and may set `modifiers`. `sigma.condition` is required. `sigma.false_positives` is optional. `yara.meta` requires `context` (list of strings) and `os`, and may set `arch`, `score`, `classification`. `yara.strings` and `yara.condition` are required. `yara.imports` is optional.

#### Carbon Black Cloud (`platform::carbon_black_cloud::1.0`)

Required on the block, beyond the base: `query`.

| Field | Type | Required |
|-------|------|----------|
| `query` | string | yes |
| `organizations` | list[string] | no |
| `watchlist` | string | no |
| `report` | string | no |
| `tags` | list[string] | no |
| `rule_id_bundle` | map[string, string] | no |

The Carbon Black deployer also copies `rule.objective` (today `detection_model`) into tags when the link is set. That is deployer behaviour, not a field of this block.

#### Elastic Security (`platform::elastic::1.0`)

Accepted in [RFC 0007](0007-elastic-security-platform.md), not yet a normative platform spec or an opentide model. When that platform lands, the block sits at `rule.elastic` on `rule::2.0` and at `configurations.elastic` on `rule::1.0`. Top-level fields, from that RFC's `ElasticConfig`. `type` is required. Other fields are required or forbidden per `type`, as in that RFC's constraint table. The shared platform base (including `status` when the block is enabled) applies on top:

| Field | Type |
|-------|------|
| `type` | `query` \| `eql` \| `esql` \| `threshold` \| `new_terms` \| `threat_match` \| `machine_learning` |
| `query` | string, absent for `machine_learning` |
| `language` | `kuery` \| `lucene`, absent for `eql`, `esql`, `machine_learning` |
| `index` | list[string] |
| `data_view_id` | string |
| `filters` | list[ElasticFilter] |
| `scheduling` | ElasticScheduling |
| `severity` | string or ElasticSeverity |
| `risk` | integer or ElasticRisk |
| `suppression` | ElasticSuppression |
| `highlighted_fields` | list[string] |
| `threshold` | ElasticThreshold, only when `type` is `threshold` |
| `new_terms` | ElasticNewTerms, only when `type` is `new_terms` |
| `eql` | ElasticEql, only when `type` is `eql` |
| `threat` | ElasticThreatMatch, only when `type` is `threat_match` |
| `machine_learning` | ElasticMachineLearning, only when `type` is `machine_learning` |
| `integration` | list[string or ElasticIntegration] |
| `required_fields` | list[ElasticRequiredField] |
| `guide` | ElasticGuide |
| `false_positives` | list[string] |
| `tags` | list[string] |
| `exceptions` | ElasticExceptions |
| `building_block` | boolean, default false |
| `overrides` | ElasticOverrides |
| `actions` | ElasticActions |

Nested types, durations, and the constraint codes (`type_block`, `language`, `esql_source`, `index_xor_data_view`, `index_list`, `suppression_shape`, `new_terms_fields`, `threshold_fields`, `risk_score`, `duration`, `filter_shape`, `exception_type`, `response_action`) are normative in RFC 0007. This RFC adopts them by reference.

### Migration from `rule::1.0` to `rule::2.0`

One registered step. There is no `rule::1.1`. `SchemaVersionChain` already allows a direct major step.

| `rule::1.0` | `rule::2.0` |
|-------------|-------------|
| `name`, `metadata` except `schema`, `references` | unchanged |
| `description`, `severity`, `techniques`, `response` | `rule.<same key>`, copied only when the key is present |
| `detection_model` | `rule.objective` |
| root `status` | copied onto each platform block that has no `status` of its own, then dropped |
| `configurations.<platform>` | `rule.<platform>` |
| `platforms.<platform>` | `rule.<platform>` when `configurations` has no such key |

Rules:

- Stamp `metadata.schema` to `rule::2.0`.
- Leave `metadata.version`, `created`, and `modified` alone. A structural migration is not a content revision.
- A platform block that already has `status` keeps it. Root `status` fills only the gaps, because deploy already prefers the block.
- Root `status` with no platform blocks is dropped. `rule::2.0` has nowhere else to put it.
- If a platform key appears in both `configurations` and `platforms`, fail.
- If a platform key is not a known platform identifier, fail. Today's loader drops unknown `configurations` keys. A migration that dropped them would hide content.
- Copy only keys that are present. The `2.0` model applies default `severity` (`Informational`) and `techniques` (`[]`) on load.
- Ordinary load MUST NOT run this migration. Loading a `rule::1.0` file validates it as `rule::1.0`.

### Versioning 1.1

[specs/versioning.md](../specs/versioning.md) version 1.0 already says: every object declares `metadata.schema`, consumers do not pick a schema from `metadata.version`, several revisions of one family may coexist, a breaking change allocates a new identifier and a new spec file, an implementation resolves the declared identifier, may migrate, validates the declared model, and indexes one JSON Schema per identifier, and a schema upgrade does not require every file to move in one step.

That is the right architecture, and it does not bind the rest of the framework. The gaps below are why `rule::2.0` cannot ship on versioning 1.0 alone. They were traced through opentide on `development` (validate, deploy, document, generate, editor mapping, pins, and both rule loaders).

#### What already works

Keep this. Do not replace the registry.

| Mechanism | Where | Behaviour |
|-----------|--------|-----------|
| Parse | `SchemaVersion.parse` | `rule::1.0`, `rule::2.0`. |
| Registry | `register_model`, `resolve_model`, `models_for_family` | Keyed by the full identifier. Tests cover a fake family through `2.0`. |
| Chain | `SchemaVersionChain` | Forward only. One step per source version. A direct `1.0 → 2.0` step is valid. Backwards migration raises. |
| Routed load | `load_object` | Uses `metadata.schema`. Migrates only when the caller passes a different `target_schema`, then stamps the identifier. |
| Validate | `validation/session.py` → `load_object_for_validation` | Schema check follows the declared id when `metadata.schema` is present. |
| Artifacts | `generate_schema_for_identifier`, `schema_artifact_name` | `rule::2.0` becomes `rule.2.0.schema.json`, with `metadata.schema` pinned to a const. CLI generation (`generation/schema.py`) writes that file per registered id. |
| Router | `build_opentide_router` | One `if`/`then` branch per registered identifier. |
| Pins | `get_pins(schema_id)`, `apply_vocab_pins` | A revision can pin different paths and different vocabulary contracts. `threat::1.0` pins `killchain::1.0`; the reserved `threat::2.1` table pins `killchain::1.1`. |

#### What fails if `rule::2.0` is only a second class

1. **Bootstrap registers one class per family.** `schema_registry._bootstrap` registers `DetectionRule`, `ThreatVector`, `DetectionObjective`, and `VisibilityConfig`. `ThreatVector_v2_1` is never registered. [schemas/pins/threat.toml](../schemas/pins/threat.toml) marks the `threat::2.1` table reserved and says not to treat it as a live schema id. A class that is not registered is not a supported revision. The same hole would hide `rule::2.0` if it were added the way `ThreatVector_v2_1` was.

2. **Rule, threat, and objective loaders ignore the router.** `load_rule_from_dict` always calls `DetectionRule.from_yaml_dict` and only lifts root `configurations`. `OpenTide.Rules`, deploy, documentation, and the planner use that loader. Threat and objective loading in `core/registry.py` similarly always call the 1.0 `from_yaml_dict`. `validation/pipeline.py` `validate_raw_payload` maps the family name `"rule"` to `DetectionRule` and ignores `metadata.schema`. The CLI validate path does not use that function; anything that does will reject a 2.0 file or, worse, accept a 1.0 reading of it.

3. **Deploy is typed to the 1.0 class and to `.configurations`.** `BaseRuleDeployer._resolve_rules` keeps an object only when `isinstance(first, DetectionRule)`. Each platform deployer repeats that check. `deployment/planning.py` `mdr_configuration_resolver` reads `data.configurations.<platform>`. A sibling model is skipped or treated as a UUID string. Subclassing `DetectionRule` would drag root `description`, root `status`, and `configurations` into the 2.0 document, because `TideModel` forbids extra fields and the 1.0 fields are required or declared.

4. **Family-keyed generation extras would emit a 2.0 schema that still describes 1.0.** `_CORE_ROOT_EXTRAS_BASE["rule"]` sets `required` to `name`, `response`, `description`, and `configurations`, and tags `detection_model`. `build_schema_source_for_identifier` applies those extras by family, so a registered `rule::2.0` model would still be wrapped in the 1.0 root. Templates (`generate_core_template`) are built from `core_object_schemas()`, the latest model per family, and written to the single filename in `paths.toml` (`rule.1.0.template.yaml`).

5. **The filename `rule.1.0.schema.json` is used as the family slot.** `paths.toml` maps `rule` to that name. `generation/artifact_gate.py` checksums one schema and one template per family via that map, so `rule.2.0.schema.json` is not gated. `build_yaml_schema_mappings` points `objects/rules/**/*.yaml` at that one file. The Red Hat YAML language server cannot narrow the `oneOf` router; opentide already avoids mapping `opentide.schema.json` onto object globs for that reason. Mixed revisions in one folder will editor-validate against whichever bytes occupy the 1.0 filename. CLI `generation/schema.py` does **not** copy the latest schema onto that filename. The copy exists only in `generation/schema_pipeline.py` `run()`, which the CLI does not call. The live risk is the template path, the editor map, the checksum gate, and the family root extras, not a silent overwrite during `opentide generate schemas`.

6. **A missing `metadata.schema` selects the latest model.** `load_object` errors. `load_object_by_type`, used when the schema check finds no schema, uses `core_object_schemas()`. `resolve_metaschema` does the same for vocabulary and deprecation. After `rule::2.0` is latest, a file with no schema would be checked as 2.0.

7. **Readers assume 1.0 paths.** Exports read a root `description` for rules and a nested description for threats and objectives. The rule renderer prints root `status` and walks `configurations`. MCP deployment status iterates `configurations` or `platforms` and would report no platforms for a 2.0 document. Offline query validation walks the raw index, which is still shaped like `configurations`.

8. **There is no schema migration command.** `opentide migrate objects` rewrites CoreTide directories. Nothing calls `register_migration` for a shipped family or writes a migrated rule file.

#### Normative requirements to add

Amend [specs/versioning.md](../specs/versioning.md) to 1.1 in the same acceptance PR as `rule-2.0.md`. These requirements sit on top of the 1.0 text:

- An implementation MUST register a validation model for every schema identifier it claims to support. An unregistered class MUST NOT be treated as supported. A pin table marked reserved MUST NOT be treated as a live identifier.
- Load, validate, deploy, document, export, query validation, and editor-facing validation MUST select behaviour from `metadata.schema`. A family-keyed model map is non-conformant once that family has more than one registered revision.
- A missing or unknown `metadata.schema` MUST be an error. It MUST NOT select the latest revision of the family.
- Loading an object MUST validate the declared revision. Changing `metadata.schema` MUST happen only through an explicit migration, not through ordinary load, validate, or deploy.
- Migration is forward-only. A chain MUST fail on a backwards request, on a missing step, and on an unregistered target. A single registered step MAY advance a major version directly (`rule::1.0` → `rule::2.0`). The migration MUST stamp `metadata.schema` to the target and MUST NOT change `metadata.version`, `created`, or `modified`.
- A migration of one object MUST be all-or-nothing. A failed migration MUST leave the file unchanged. Running it again on an already-migrated object MUST be safe: the function is idempotent, or a second apply is defined to no-op when `metadata.schema` is already the target.
- The migrate operation MUST be explicit about the write (a command or an API that names the target schema). It MUST validate the result as the target revision before replacing the file.
- Components that read a field whose path differs across revisions MUST use a reader that understands each registered revision. For rules, that includes description, severity, techniques, the objective link (`detection_model` on 1.0, `objective` on 2.0), response, and platform blocks (`configurations.<platform>` on 1.0, `rule.<platform>` on 2.0). Deployment status is always the platform block's `status`. On `rule::1.0` the root `status` is not the deployment status.
- `generate schemas` MUST emit one JSON Schema and one template per registered identifier, and the generated schema MUST describe that identifier's model. Family-level root extras from another revision MUST NOT be applied. A filename that embeds `{family}.{major}.{minor}` MUST contain that identifier only. A family-level alias MUST NOT receive another revision's bytes.
- When two or more revisions of a family are registered, editor validation MUST choose the schema from `metadata.schema`. Binding the whole object folder to one file is non-conformant in that case. The generated `oneOf` router is the contract for tools that can evaluate it. Tools that cannot MUST still discriminate per file. Directory-per-revision is not required.
- Vocabulary pins are per schema identifier. Pin paths MUST match that revision's document. A new optional platform key on the current rule revision is non-breaking. A platform block's own `schema` id versions independently of the rule id.
- [validation.md](../specs/validation.md) gains one sentence: a validation entry point that selects a model by object family and ignores `metadata.schema` is non-conformant. Query validation MUST read the query from the revision's platform block.

#### Second axes, and how a rule major bump touches them

| Axis | What it versions | Effect of `rule::2.0` |
|------|------------------|------------------------|
| `metadata.schema` | Document shape | New id. 1.0 documents stay on `rule::1.0`. |
| `metadata.version` | Instance content | Unchanged by structural migration. Git remains the history. |
| Platform block `schema` | That platform's payload | Unchanged. Blocks move from `configurations.<id>` to `rule.<id>`. |
| Vocabulary pins | Which contract a field uses | New paths (`rule.severity`, not `severity`). Same vocabulary contracts. |
| Spec file `version` | The markdown spec | `rule-2.0.md` is a new file. `versioning.md` becomes 1.1. |
| Inflight shard `inflight.shard::1.0` | Preview overlay | Compares `metadata.version`, not schema. Out of scope here; a shard that wraps a rule document MUST keep the wrapped document's `metadata.schema`. |

`threat::2.1` is the cautionary example of a pin-only revision: same document shape, different pin, class present, not registered, pin table explicitly reserved. Versioning 1.1 says that combination is not support. Making `threat::2.1` live is separate work and needs `specs/objects/threat-2.1.md` first.

### Spec changes after acceptance

| Path | Change |
|------|--------|
| `specs/objects/rule-2.0.md` | New normative spec from the tables in this RFC, including the platform blocks. |
| `specs/objects/rule-1.0.md` | History row. Status stays `normative`. Root `status` documented as unused by deploy. |
| `specs/versioning.md` | Version 1.1, requirements in [Versioning 1.1](#versioning-11). |
| `specs/validation.md` | Family-keyed validation is non-conformant. Query checks use the revision's platform path. |
| `specs/deployment.md` | Status under promotion is the platform block. `rule::2.0` has no document status. The promoter must recognize `rule.<platform>.status` as well as `configurations.<platform>.status`. |
| `specs/platforms.md` | Point at the full block tables. `rule.<platform>` is the 2.0 location. |
| `schemas/pins/rule.toml` | `["rule::2.0"]` section. |
| Fixtures listed above | Conformance. |
| `SPECS.md`, `CHANGELOG.md` | Index and history. |

No vocabulary TOML changes. No opentide code in the specifications pull request that accepts this RFC. Implementation follows [OpenTideHQ/opentide#394](https://github.com/OpenTideHQ/opentide/issues/394).

## Drawbacks

- Tooling carries two document shapes until catalogues migrate. Deployers, the planner, documentation, exports, MCP, and promotion all read `.configurations` or the root `status` today. The shared reader is a wide mechanical change.
- `rule.objective` is a new key. Catalogues, importers, and tests that look up `detection_model` keep working on `rule::1.0` files and need the reader on `rule::2.0`.
- Dropping root `status` surprises anyone who edited that field and expected deploy to follow it. Deploy already did not. Migration copies it onto platform blocks that lack their own status so the value is not thrown away when it was the only one.
- Requiring `status` on an enabled block is stricter than the 1.0 model, which allows omission and then throws at deploy. Draft blocks (`enabled: false`) may still omit it.
- Editor support needs per-file schema selection. The folder-to-one-file mapping cannot represent coexistence, and the YAML language server cannot evaluate the router.
- Writing the platform blocks into the rule spec makes this RFC long. Leaving them as "see generated JSON Schema" is how platforms.md and the first draft of this RFC both under-specified Sentinel scheduling, Splunk's legacy spellings, and the HarfangLab Sigma/YARA split.

## Alternatives

### Keep `detection_model`

Rejected. The value is an objective UUID, the metaschema already calls the target an objective, and the name collides with "the detection's data model" in ordinary reading.

### Keep a document-level `status` next to platform status

Rejected. Two statuses, and deploy, promotion, and `check_status` use only the platform one. The root field is what made the first draft of this RFC put `status` on `rule`. That repeated the 1.0 mistake inside the new body.

### Rename `configurations` to `platforms` and stop

Rejected. `platforms` is the legacy untyped map. A rename keeps a wrapper the other objects do not have, and it is a breaking change anyway.

### Put platform keys on the envelope, beside `rule:`

Rejected. Platform blocks are part of the detection. Threats and objectives keep domain fields inside the named body.

### Nest `configurations` under `rule:`

Rejected. That preserves the wrapper.

### Subclass `DetectionRule` so deployers keep compiling

Rejected. The 1.0 model requires root `description` and declares `configurations` and root `status`. Those fields would remain on the 2.0 document. Deployers should call a reader: `platform(name)`, `objective`, `description`, `severity`. `rule::1.0` implements `platform` from `configurations`. `rule::2.0` implements it from `rule.<platform>`.

### Edit `rule::1.0` in place

Rejected. Moving fields, renaming `detection_model`, and removing root `status` and `configurations` is a breaking structural change. Existing catalogues stay on `rule::1.0`.

### Require every rule file to migrate when 2.0 ships

Rejected. Objects opt in per file. Load of a 1.0 file keeps validating 1.0.

### Split `objects/rules/` into version directories

Rejected. `metadata.schema` is the discriminator. Editor tooling has to read it anyway.

## Unresolved questions

- Should `opentide new` emit `rule::2.0` as soon as that model is registered, while existing files stay on their declared revision? This RFC assumes yes.
- When is `rule::1.0` marked `deprecated`? After both revisions load and the migrate command exists. Deprecation then means "do not author new 1.0 files". Existing 1.0 files remain valid.
- Sentinel `scheduling.frequency` and `scheduling.lookback` are optional in the model and required in platforms.md's short list. This RFC follows the model. If acceptance wants them required on an enabled Sentinel block, that is a platform-schema tightening and should be called out as such, not slipped in.
- SentinelOne's type/side check and HarfangLab's Sigma-or-YARA check fail at deploy, not at schema validation. Tightening the model would change `platform::sentinel_one::1.0` and `platform::harfanglab::1.0`. This RFC leaves them as deploy checks.
- Elastic's nested types stay in RFC 0007 until that platform's spec file exists. Confirm the `rule.elastic` versus `configurations.elastic` split when the 0007 spec PR opens, so 1.0 and 2.0 each get the key in the place this RFC assigns.

## References

- [OpenTideHQ/specifications#24](https://github.com/OpenTideHQ/specifications/issues/24)
- [OpenTideHQ/opentide#394](https://github.com/OpenTideHQ/opentide/issues/394)
- [specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md), [specs/objects/threat-1.0.md](../specs/objects/threat-1.0.md), [specs/objects/objective-1.0.md](../specs/objects/objective-1.0.md)
- [specs/versioning.md](../specs/versioning.md), [specs/platforms.md](../specs/platforms.md), [specs/validation.md](../specs/validation.md), [specs/deployment.md](../specs/deployment.md)
- [RFC 0007](0007-elastic-security-platform.md) — `platform::elastic::1.0`
- opentide models: `models/rule.py`, `models/platform.py`, `models/platform_configs.py`, `models/response.py`, `models/splunk_legacy.py`, `models/schema_registry.py`, `models/threat.py`, `models/version.py`
- opentide behaviour: `loading/rule_loader.py`, `loading/object_loader.py`, `validation/session.py`, `validation/pipeline.py`, `deployment/planning.py`, `deployment/utils.py` (`check_status`), `mutation/promotion.py`, `generation/pydantic_metaschema.py` (`_CORE_ROOT_EXTRAS_BASE`), `generation/schema.py`, `generation/schema_pipeline.py`, `generation/pydantic_templates.py`, `generation/artifact_gate.py`, `cli/services/setup/vscode.py`, `data/configurations/paths.toml`
