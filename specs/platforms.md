---
spec: platforms
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Platforms

## Summary

OpenTide ships seven detection platform integrations. Each platform has bundled TOML configuration, an optional deployer entry point, an optional query validator, and a typed rule configuration model referenced from `rule::1.0` via `configurations.<platform>`.

## Requirements

- Platform identifiers MUST use the keys defined in this spec (snake_case).
- A platform MUST be marked `enabled: true` in merged configuration to appear in `enabled_systems()`.
- Deploy and validate capabilities MUST be reported honestly — platforms without validators MUST NOT claim query validation support.
- Rule platform blocks MUST declare `schema: platform::<identifier>::1.0` when using typed configurations.
- CrowdStrike and HarfangLab MUST NOT advertise query validation (`can_validate: false`).

## Definition

### Platform capability matrix

| Identifier | Display name | Deploy | Query validate | Query language | Schema ID |
|------------|--------------|--------|----------------|----------------|-----------|
| `sentinel` | Microsoft Sentinel | yes* | yes | KQL | `platform::sentinel::1.0` |
| `defender_for_endpoint` | Microsoft Defender for Endpoint | yes* | yes | KQL | `platform::defender_for_endpoint::1.0` |
| `splunk` | Splunk | yes | yes | SPL | `platform::splunk::1.0` |
| `sentinel_one` | SentinelOne | yes* | yes | S1QL | `platform::sentinel_one::1.0` |
| `carbon_black_cloud` | VMware Carbon Black Cloud | yes | yes | Lucene | `platform::carbon_black_cloud::1.0` |
| `crowdstrike` | CrowdStrike Falcon | yes* | **no** | FQL | `platform::crowdstrike::1.0` |
| `harfanglab` | HarfangLab | yes* | **no** | Sigma/YARA | `platform::harfanglab::1.0` |

\* Deploy requires a loaded deployer entry point and `enabled: true` in workspace configuration. Capability availability depends on credentials and platform TOML setup.

### Query validation platforms

The following subset supports `opentide validate query`:

`sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `carbon_black_cloud`

Excluded: `crowdstrike`, `harfanglab`

### Platform configuration location

| Location | Purpose |
|----------|---------|
| `opentide/data/configurations/platforms/<id>.toml` | Bundled defaults |
| `.opentide/configurations/platforms/<id>.toml` | Client override |

### Platform TOML structure (excerpt)

```toml
[platform]
enabled = false
identifier = "sentinel"
name = "Microsoft Sentinel"
description = "Microsoft Sentinel analytics rules"
flags = []                 # optional platform flags; empty by default
```

Enable a platform by setting `enabled = true` under `[platform]` or `[tide]`.

### Per-platform rule configuration

Every platform block shares the fields defined in [rule-1.0.md → Platform block](objects/rule-1.0.md) (`enabled`, `name`, `schema`, `status`, `flags`, `tenants`, `contributors`) and adds platform-specific fields. The authoritative per-field contract for each platform is the generated `platform::<identifier>::1.0` JSON Schema; the required fields below are what a rule MUST provide for an enabled block.

| Platform | Required fields (when enabled) |
|----------|-------------------------------|
| `sentinel` | `query`, `scheduling`, `alert` |
| `defender_for_endpoint` | `query`, `alert`, `impacted_entities`, `scheduling` |
| `splunk` | `query` (legacy `search` accepted) |
| `sentinel_one` | `condition` |
| `crowdstrike` | `details`, `schedule`, `query` |
| `harfanglab` | at least one of `sigma`, `yara` |
| `carbon_black_cloud` | platform query block (Lucene) |

#### Sentinel block (`platform::sentinel::1.0`)

The canonical example. A Sentinel block declares the analytics rule query, its schedule, and alert presentation.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | boolean | yes | Activate this platform block |
| `query` | string (KQL) | yes | The detection query |
| `scheduling.frequency` | ISO 8601 duration | yes | How often the rule runs (e.g. `PT1H`) |
| `scheduling.lookback` | ISO 8601 duration | yes | Time window queried (e.g. `PT2H`) |
| `alert.title` | string | yes | Alert display title |
| `alert.suppression` | boolean | no | Suppress duplicate alerts |
| `grouping` | object | no | Event/alert grouping behaviour |

```yaml
configurations:
  sentinel:
    enabled: true
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
    grouping:
      event: SingleAlert
      alert:
        enabled: false
```

Other platforms follow the same pattern with their own query language and required fields; consult the generated `platform::<identifier>::1.0` schema in `.opentide/schemas/` for the exact contract.

### Entry points

Deployers register via `opentide.platforms` entry points in opentide `pyproject.toml`. Validators load from `opentide.validation.<platform>_query` modules when available.

## Relationships

- [rule-1.0.md](objects/rule-1.0.md) — `configurations` blocks
- [configuration.md](configuration.md) — platform TOML merge
- [deployment.md](deployment.md) — per-platform `status`
- [validation.md](validation.md) — `validate query` command
- [metaschema-keywords.md](metaschema-keywords.md) — `tide.config.systems::enabled`, `recomposition`

## Defaults & overrides

All bundled platforms default to `enabled = false`. Clients enable platforms in `.opentide/configurations/platforms/`. See [configuration.md](configuration.md).

## Examples

- Sentinel rule block: [fixtures/valid/rule-1.0.yaml](../fixtures/valid/rule-1.0.yaml)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial matrix for seven bundled platforms |
