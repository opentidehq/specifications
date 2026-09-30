---
spec: platforms
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Platforms

## Summary

OpenTide ships seven detection platform integrations. Each platform has bundled TOML configuration, a deployer, an optional query validator, and a typed rule block under `configurations.<platform>`.

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

These specs describe the blocks as the engine accepts them today. Generated JSON Schema is a build artifact. Where it disagrees with this page or a platform spec, the spec wins.

## Requirements

- Platform identifiers MUST use the keys in the capability matrix (snake_case).
- A platform MUST be marked `enabled: true` in merged configuration to appear in `enabled_systems()`.
- Deploy and validate capabilities MUST be reported honestly. A platform without a query validator MUST NOT claim query validation support.
- CrowdStrike and HarfangLab MUST NOT advertise query validation (`can_validate: false`).
- A typed block SHOULD set `schema` to `platform::<identifier>::1.0`. Implementations MUST accept a missing `schema` and MUST accept a legacy identifier (`sentinel::2.4`, `splunk::2.0`, `splunk::3.0`, `carbon_black_cloud::3.0`, and the same shape for the other platforms). The identifier is not a closed enum.
- Unknown keys on a block MUST fail static validation. The loader aliases in [External rule ids](#external-rule-ids) and [Splunk](splunk-1.0.md) are the only exceptions, and they apply on the registry-load path.
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

\* Deploy requires a loaded deployer entry point and `enabled: true` in workspace configuration.

### Query validation platforms

`opentide validate query` supports:

`sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `carbon_black_cloud`

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

### Shared platform block

Every block includes these fields. Platform specs do not repeat them except where deploy treats one differently.

| Field | YAML key | Type | Required | Default | Description |
|-------|----------|------|----------|---------|-------------|
| `enabled` | `enabled` | boolean | no | `false` | When `true`, the block is active for deploy. A rule with no enabled block is still valid. |
| `name` | `name` | string | no | `""` | Platform-specific rule name. Empty means the deployer uses the rule `name`, where that platform has a name field. |
| `platform_schema` | `schema` | string | no | null | Schema identifier. Canonical value: `platform::<identifier>::1.0`. Templates emit it. Validation does not require it. |
| `status` | `status` | string | no | null | Deployment status for this block. When set, it MUST be a status name from [deployment.md](../deployment.md). `DISABLEMENT` disables an existing rule; `DELETION` removes it. Other strategies deploy it enabled. |
| `flags` | `flags` | list[string] | no | null | Free-form flags. Splunk modifiers may match on them. |
| `tenants` | `tenants` | list[string] | no | null | Tenant names this block targets. Empty or omitted means the deployment plan's tenant selection. |
| `contributors` | `contributors` | list[string] | no | null | People credited on the platform rule. CrowdStrike joins them into the rule comment. |

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

Sentinel addresses the analytics rule by `metadata.uuid`. HarfangLab addresses Sigma and YARA rules by `metadata.uuid`. The other platforms store the vendor's id on the block so the next deploy updates instead of creating.

| Platform | Model field | Value type | Loader alias |
|----------|-------------|------------|--------------|
| `defender_for_endpoint` | `rule_id` | map[string, int] | `rule_id::<tenant>` |
| `sentinel_one` | `rule_id_bundle` | map[string, int] | `rule_id::<tenant>` |
| `crowdstrike` | `rule_id_bundle` | map[string, string] | `rule_id::<tenant>` |
| `harfanglab` | `rule_id_bundle` | map[string, string] | `rule_id::<tenant>` |
| `carbon_black_cloud` | `rule_id_bundle` | map[string, string] | `rule_id::<tenant>` |

The key inside the map is the tenant name. Deploy writes the alias back into the rule file:

```yaml
configurations:
  defender_for_endpoint:
    rule_id::Tenant: 12345
```

The registry loader folds every `rule_id::<tenant>` key into the model field and then validates. Static validation does not run the loader, so a raw `rule_id::<tenant>` key is an unknown key and MUST fail `opentide validate`. The map field (`rule_id` or `rule_id_bundle`) is the spelling static validation accepts. HarfangLab and Carbon Black accept `rule_id_bundle` and do not read it when deploying: HarfangLab uses `metadata.uuid`, and Carbon Black matches the report by title.

Defender also accepts the alias `quarantine_files` for `actions.files.quarantine_file` on the loader path only.

### Generated schema drift

Published JSON Schema is built from the models plus a `required` overlay. The overlay currently names fields the model does not require:

| Platform | Overlay `required` beyond the model |
|----------|--------------------------------------|
| every platform | `status` |
| `sentinel` | `grouping`, `entities` |
| `splunk` | `scheduling` |

`opentide validate` follows the model, not the overlay. A Sentinel block without `grouping` validates. Deploy of that block fails. Editor validation that consumes the generated schema may reject objects the engine accepts.

### Entry points

Deployers register via `opentide.platforms` entry points. Validators load from `opentide.validation.<platform>_query` when the platform supports query validation.

## Relationships

- [rule-1.0.md](../objects/rule-1.0.md) — `configurations` blocks
- [configuration.md](../configuration.md) — platform TOML merge
- [deployment.md](../deployment.md) — `status` strategies
- [validation.md](../validation.md) — `validate` and `validate query`
- [metaschema-keywords.md](../metaschema-keywords.md) — `tide.config.systems::enabled`, `recomposition`
- Platform specs linked in the [Summary](#summary)

## Defaults & overrides

| Setting | Default | Override |
|---------|---------|----------|
| Platform enabled | `false` in bundled TOML | `.opentide/configurations/platforms/<id>.toml` |
| Block `enabled` | `false` | Per-block YAML |
| Block `status` | null (rule-level status still applies to the rule) | Per-block YAML |
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
