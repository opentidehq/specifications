---
spec: platforms
version: "1.2"
schema_id: null
status: normative
supersedes: null
---

# Platforms

## Summary

OpenTide ships eight detection platform integrations. Each platform has bundled TOML configuration, a deployer, an optional query validator, and a typed rule block under `configurations.<platform>`.

The block's schema identifier is `platform::<identifier>::1.0`. This page is the capability matrix and the shared block. The field contract for each block is its own spec:

| Identifier | Schema | Spec |
|------------|--------|------|
| `sentinel` | `platform::sentinel::1.0` | [sentinel-1.0.md](sentinel-1.0.md) |
| `defender_for_endpoint` | `platform::defender_for_endpoint::1.0` | [defender-for-endpoint-1.0.md](defender-for-endpoint-1.0.md) |
| `splunk` | `platform::splunk::1.0` | [splunk-1.0.md](splunk-1.0.md) |
| `sentinel_one` | `platform::sentinel_one::1.0` | [sentinel-one-1.0.md](sentinel-one-1.0.md) |
| `carbon_black_cloud` | `platform::carbon_black_cloud::1.0` | [carbon-black-cloud-1.0.md](carbon-black-cloud-1.0.md) |
| `crowdstrike` | `platform::crowdstrike::1.0` | [crowdstrike-1.0.md](crowdstrike-1.0.md) |
| `harfanglab` | `platform::harfanglab::1.0` | [harfanglab-1.0.md](harfanglab-1.0.md) |
| `elastic` | `platform::elastic::1.0` | [elastic-1.0.md](elastic-1.0.md) |

These specs describe the blocks as the engine accepts them today, including every optional key. Generated JSON Schema is a build artifact. Where it disagrees with this page or a platform spec, the spec wins. opentide's usage and SDK pages link here. They do not restate the keys. Change a field here first; the implementation follows.

## Requirements

- Platform identifiers MUST use the keys in the capability matrix (snake_case).
- A platform MUST be marked `enabled: true` in merged configuration to appear in `enabled_systems()`.
- Deploy and validate capabilities MUST be reported honestly. A platform without a query validator MUST NOT claim query validation support.
- CrowdStrike and HarfangLab MUST NOT advertise query validation (`can_validate: false`).
- A typed block SHOULD set `schema` to `platform::<identifier>::1.0`. Implementations MUST accept a missing `schema` and MUST accept a legacy identifier (`sentinel::2.4`, `splunk::2.0`, `splunk::3.0`, `carbon_black_cloud::3.0`, and the same shape for the other platforms). The identifier is not a closed enum.
- Unknown keys on a block MUST fail static validation. The model forbids them.
- A block MUST NOT carry a vendor-assigned external id. `rule_id`, `rule_id_bundle`, and `rule_id::<tenant>` at the root of any block, on every platform, MUST fail with `external_id_in_rule` ([External rule ids](#external-rule-ids)).
- Registry load is stricter or looser depending on the platform. Defender, Splunk, Carbon Black, and Elastic pass leftover keys on the block into the model, so an unknown key at the block root fails load as well. The Splunk loader still drops unknown keys inside `scheduling` other than `type`, `expires`, `schedule`, and `timerange`. Sentinel, SentinelOne, CrowdStrike, and HarfangLab drop keys the loader does not map, so those keys pass load and fail `opentide validate`. The [Splunk](splunk-1.0.md) aliases and Defender's `quarantine_files` alias are mapped before that check.
- In every field table, **optional** means the key may be omitted at static validation. A later sentence in that platform spec names the keys deploy or registry load still require.
- `query`, where the platform spec marks it required, MUST be a string and MUST NOT be empty or whitespace.
- Static validation (`opentide validate`) MUST enforce the **Required** column of each platform spec. It MUST NOT require a field only because generated JSON Schema lists it.
- A successful deploy MUST also satisfy that platform spec's **Deploy** section. Those checks are not static-validation failures.

<Callout type="info">
**Three checks, three bars.** Static validation parses the YAML with the platform model. Registry load parses it again through the platform loader before a rule can be deployed. Deploy then applies vendor constraints (a Sentinel rule with no `grouping` validates and fails at deploy). Each platform spec separates those bars. A field marked optional is optional for `opentide validate`.
</Callout>

## Definition

### Platform capability matrix

| Identifier | Display name | Deploy | Query validate | Detection language | Schema spec |
|------------|--------------|--------|----------------|--------------------|-------------|
| `sentinel` | Microsoft Sentinel | yes* | yes | KQL | [sentinel-1.0](sentinel-1.0.md) |
| `defender_for_endpoint` | Microsoft Defender for Endpoint | yes* | yes | KQL | [defender-for-endpoint-1.0](defender-for-endpoint-1.0.md) |
| `splunk` | Splunk | yes | yes | SPL | [splunk-1.0](splunk-1.0.md) |
| `sentinel_one` | SentinelOne | yes* | yes | S1QL | [sentinel-one-1.0](sentinel-one-1.0.md) |
| `carbon_black_cloud` | VMware Carbon Black Cloud | yes | yes | Lucene | [carbon-black-cloud-1.0](carbon-black-cloud-1.0.md) |
| `crowdstrike` | CrowdStrike Falcon | yes* | **no** | correlation filter | [crowdstrike-1.0](crowdstrike-1.0.md) |
| `harfanglab` | HarfangLab | yes* | **no** | Sigma or YARA | [harfanglab-1.0](harfanglab-1.0.md) |
| `elastic` | Elastic Security | yes* | yes† | KQL, Lucene, EQL, or ES\|QL, chosen by the block's `type` and `language` | [elastic-1.0](elastic-1.0.md) |

\* Deploy requires a loaded deployer entry point and `enabled: true` in workspace configuration.

† Live only, through Kibana rule preview (`/api/detection_engine/rules/preview`) plus the Elasticsearch checks, against a tenant, for every language the block can carry. Elastic has no offline syntax check ([elastic-1.0](elastic-1.0.md#query-validation)).

### Query validation platforms

`opentide validate query` supports:

`sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `carbon_black_cloud`, `elastic`

Query validation is a tenant check on every platform: `opentide validate query --live`. Without `--live` the command refuses and names `--live`.

Excluded: `crowdstrike`, `harfanglab`. Implementations MUST report `supported: false` for those two and MUST NOT invent a passing result.

### What a block must contain to validate

This is the static-validation bar. Deploy adds the constraints in each platform spec.

| Platform | Required when the block is present |
|----------|-------------------------------------|
| `sentinel` | `query`, `scheduling`, `alert` |
| `defender_for_endpoint` | `query`, `alert` (with `category`), `impacted_entities`, `scheduling` |
| `splunk` | `query`, or legacy `search` which fills `query` |
| `sentinel_one` | `condition` (with `type`) |
| `carbon_black_cloud` | `query` |
| `crowdstrike` | `details` (with `trigger` and `outcome`), `schedule` (with `frequency` and `lookback`), `query` |
| `harfanglab` | no platform field is required; `maturity`, `confidence`, and `action` have defaults. Deploy requires `sigma` or `yara` |
| `elastic` | `type`, `status`, and `query` (except for `machine_learning`), plus the type object: `threshold`, `new_terms`, `threat`, or `machine_learning` for those types. Every block also meets the [Elastic constraints](elastic-1.0.md#constraints) |

### Shared platform block

Every block includes these fields. Platform specs do not repeat them except where deploy treats one differently.

| Field | YAML key | Type | Required | Default | Description |
|-------|----------|------|----------|---------|-------------|
| `enabled` | `enabled` | boolean | optional | `false` | When `true`, the block is active for deploy. A rule with no enabled block is still valid. |
| `name` | `name` | string | optional | `""` | Platform-specific rule name. Empty means the deployer uses the rule `name`, where that platform has a name field. |
| `platform_schema` | `schema` | string | optional | null | Schema identifier. Canonical value: `platform::<identifier>::1.0`. Templates emit it. Validation does not require it. |
| `status` | `status` | string | optional | null | Deployment status for this block. When set, it MUST be a status name from [deployment.md](../deployment.md). `DISABLEMENT` disables an existing rule; `DELETION` removes it. Other strategies deploy it enabled. Required on `elastic` ([elastic-1.0](elastic-1.0.md)). |
| `flags` | `flags` | list[string] | optional | null | Free-form flags. Splunk modifiers may match on them. |
| `tenants` | `tenants` | list[string] | optional | null | Tenant names this block targets. Empty or omitted means the deployment plan's tenant selection. |
| `contributors` | `contributors` | list[string] | optional | null | People credited on the platform rule. CrowdStrike joins them into the rule comment. |

`schema` is the YAML key. The model field is `platform_schema` because `schema` would collide with the base model's schema method.

### Platform configuration location

Workspace TOML enables a platform and holds tenant credentials. It is not the rule block.

| Location | Purpose |
|----------|---------|
| `opentide/data/configurations/platforms/<id>.toml` | Bundled defaults |
| `.opentide/configurations/platforms/<id>.toml` | Client override |

```toml
[platform]
enabled = false
identifier = "sentinel"
name = "Microsoft Sentinel"
description = "Microsoft Sentinel analytics rules"
flags = []
```

All bundled platforms default to `enabled = false`. Enable one by setting `enabled = true` under `[platform]`. Tenant tables, modifiers, and secrets live in the same file and are configuration, not part of `platform::<identifier>::1.0`.

### External rule ids

Platform blocks MUST NOT contain vendor-assigned external identifiers. Defender for Endpoint, SentinelOne, and CrowdStrike use the committed deployment-state shard defined in [deployment-state.md](../deployment-state.md). Sentinel, HarfangLab, and Elastic use `metadata.uuid`; Carbon Black Cloud uses `metadata.uuid` for the IOC and the title for the report; Splunk uses its saved-search identity.

| Platform | How deploy addresses the remote rule | Where a vendor id lives |
|----------|--------------------------------------|-------------------------|
| `sentinel` | `metadata.uuid` is the analytics rule id | Nowhere |
| `defender_for_endpoint` | Defender-assigned rule id | `.opentide/states/deployment/<uuid>.json` |
| `splunk` | The saved search | Nowhere |
| `sentinel_one` | SentinelOne-assigned STAR rule id | `.opentide/states/deployment/<uuid>.json` |
| `carbon_black_cloud` | `metadata.uuid` on the IOC; title on the report | Nowhere |
| `crowdstrike` | CrowdStrike-assigned correlation rule id | `.opentide/states/deployment/<uuid>.json` |
| `harfanglab` | `metadata.uuid` on the Sigma rule and the YARA meta `id` | Nowhere |
| `elastic` | `metadata.uuid` is the Kibana `rule_id`, in every tenant and space | Nowhere |

Elastic Security ([elastic-1.0](elastic-1.0.md), [RFC 0007](../../rfcs/0007-elastic-security-platform.md)) addresses every rule by `metadata.uuid`. Elastic never stores an external id: Kibana's internal `id` is not recorded in a block or in deployment state.

`rule_id`, `rule_id_bundle`, and `rule_id::<tenant>` are legacy keys from before [RFC 0010](../../rfcs/0010-deployment-external-ids.md). Static validation and every deploy path MUST reject them with `external_id_in_rule`, on every platform block, whether or not a shard also holds the id. No loader folds them into a field. `opentide deploy migrate-state` moves Defender, SentinelOne, and CrowdStrike values into shards and removes the keys from every other platform with an `external_id_unused` warning.

Defender also accepts the alias `quarantine_files` for `actions.files.quarantine_file` on the loader path only.

### Generated schema drift

Published JSON Schema is built from the models plus a `required` overlay. The overlay currently names fields the model does not require:

| Platform | Overlay `required` beyond the model |
|----------|--------------------------------------|
| every platform | `status` |
| `sentinel` | `grouping`, `entities` |
| `splunk` | `scheduling` |

`opentide validate` follows the model, not the overlay. A Sentinel block without `grouping` validates. Deploy of that block fails. Editor validation that consumes the generated schema may reject objects the engine accepts.

The same overlay sets a default for `schema` that is the legacy identifier. The model default is null, and the bundled templates write `platform::<identifier>::1.0`. Validation accepts both. Splunk, Carbon Black, and Elastic also set a `pattern` that only matches the legacy identifier shape (`^splunk::[1-9]\.[0-9]$`, `^carbon_black_cloud::[1-9]\.[0-9]$`, `^elastic::[1-9]\.[0-9]$`). That pattern rejects `platform::splunk::1.0`, `platform::carbon_black_cloud::1.0`, and `platform::elastic::1.0`. `opentide validate` does not apply it. Elastic has no legacy identifier, so its generated default `elastic::1.0` names no schema that ever existed.

Splunk extras also name `threshold`, `throttling`, and `security_domain` on the block root, and `cron` and `lookback` directly under `scheduling`. Those properties are not on the model. The generator skips an extra whose property is missing. The live keys are the nested ones in [splunk-1.0.md](splunk-1.0.md).

| Platform | Generated default `schema` |
|----------|----------------------------|
| `sentinel` | `sentinel::2.4` |
| `defender_for_endpoint` | `defender_for_endpoint::2.3` |
| `splunk` | `splunk::3.0` |
| `sentinel_one` | `sentinel_one::2.0` |
| `crowdstrike` | `crowdstrike::2.0` |
| `harfanglab` | `harfanglab::2.0` |
| `carbon_black_cloud` | `carbon_black_cloud::3.0` |
| `elastic` | `elastic::1.0` |

### Entry points

Deployers register via `opentide.platforms` entry points. Validators load from `opentide.validation.<platform>_query` when the platform supports query validation.

## Relationships

- [rule-1.0.md](../objects/rule-1.0.md) — `configurations` blocks
- [configuration.md](../configuration.md) — platform TOML merge
- [deployment.md](../deployment.md) — `status` strategies
- [validation.md](../validation.md) — `validate` and `validate query`
- [deployment-state.md](../deployment-state.md) — where Defender, SentinelOne, and CrowdStrike ids live
- [metaschema-keywords.md](../metaschema-keywords.md) — `tide.config.systems::enabled`, `recomposition`
- Platform specs linked in the [Summary](#summary)

## Defaults & overrides

| Setting | Default | Override |
|---------|---------|----------|
| Platform enabled | `false` in bundled TOML | `.opentide/configurations/platforms/<id>.toml` |
| Block `enabled` | `false` | Per-block YAML |
| Block `status` | null (rule-level status still applies to the rule). Required on `elastic`, with no default. | Per-block YAML |
| Block `schema` | omitted | Templates write `platform::<identifier>::1.0` |

Vocabulary files are not platform configuration. See [configuration.md](../configuration.md).

## Examples

- Sentinel block on a full rule: [fixtures/valid/rule-1.0.yaml](../../fixtures/valid/rule-1.0.yaml)
- One minimal block per platform: [fixtures/platforms/](../../fixtures/platforms/)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial matrix for seven bundled platforms |
| 1.0 | 2026-09-30 | Field contracts moved to per-platform specs. Static validation, registry load, and deploy are specified separately. Generated JSON Schema is no longer described as the field contract. |
| 1.1 | 2026-10-16 | Platform blocks carry no external ids. `rule_id`, `rule_id_bundle`, and the `rule_id::<tenant>` loader alias are removed from every block and fail `external_id_in_rule`; Defender, SentinelOne, and CrowdStrike ids live in [deployment state](../deployment-state.md) ([RFC 0010](../../rfcs/0010-deployment-external-ids.md)). Elastic is recorded as addressed by `metadata.uuid` with no stored id. Platform `schema_id`s stay `::1.0`. |
| 1.2 | 2026-10-19 | Elastic Security joins the matrix as the eighth platform ([elastic-1.0](elastic-1.0.md), [RFC 0007](../../rfcs/0007-elastic-security-platform.md)): capability row (deploy; live query validation through Kibana rule preview for KQL, Lucene, EQL, and ES\|QL), query-validation allowlist, static-validation bar, `metadata.uuid` identity with no stored id, and its generated-schema `pattern`. `validate query` is a tenant check on every platform (`--live`). |
