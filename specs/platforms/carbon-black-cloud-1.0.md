---
spec: platform-carbon-black-cloud
version: "1.0"
schema_id: platform::carbon_black_cloud::1.0
status: normative
supersedes: null
---

# VMware Carbon Black Cloud (`platform::carbon_black_cloud::1.0`)

## Summary

`configurations.carbon_black_cloud` is a Carbon Black Cloud Enterprise EDR watchlist report. The detection text is a Lucene query stored as an IOC. Query validation is supported. The IOC id is the Tide rule's `metadata.uuid`. The report is matched by title inside a watchlist that must already exist on the console.

Shared fields are defined in [platforms](index.md#shared-platform-block).

## Requirements

- Static validation MUST require a non-blank `query`.
- `organizations`, `watchlist`, `report`, `tags`, and `rule_id_bundle` MAY be omitted and still validate.
- Registry load MUST accept `organization` as an alias of `organizations`.
- Deploy MUST collapse newlines in `query` to spaces.
- Deploy MUST refuse to create a report on a watchlist that does not already exist.
- `rule_id_bundle` MAY be present. The current deployer does not read it. Identity is `metadata.uuid` on the IOC and the report title on the report.
- Severity MUST be taken from `response.alert_severity`. The block has no severity field.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | Lucene query. Multiline in YAML. Deploy joins lines with spaces. |
| `organizations` | list[string] | no | null | Accepted, including the loader alias `organization`. The current deployer targets the tenant from the deployment plan and does not filter on this list. |
| `watchlist` | string | no | null | Watchlist name. Deploy uses the tenant watchlist when omitted. The watchlist must already exist. |
| `report` | string | no | null | Report title. Deploy uses the Tide rule `name` when omitted. |
| `tags` | list[string] | no | null | Extra report tags, appended after the tags OpenTide always writes. |
| `rule_id_bundle` | map[string, string] | no | null | Accepted. Not used to address the IOC or the report. |

### Report tags and severity

Deploy always tags the report with:

1. The block `status`, stringified. An omitted `status` is the string `None`.
2. When the rule has `detection_model`: that objective UUID, then the ATT&CK technique ids resolved from it.
3. `tags` from this block.

Severity is the Carbon Black report score for `response.alert_severity`:

| `response.alert_severity` | Report severity |
|---------------------------|-----------------|
| `Informational` | 1 |
| `Low` | 3 |
| `Medium` | 6 |
| `High` | 8 |
| `Critical` | 10 |

When `response` is missing, deploy uses `Low` (score 3). An unmapped severity fails deploy.

### Deploy

The report description is the Tide rule `description`.

| Block status strategy | Carbon Black result |
|-----------------------|---------------------|
| `DISABLEMENT` or `DELETION` | The report is deleted when its title is the rule `name`. When the report title is a shared report (`report` names something else) the IOC is removed, and the report is deleted only if that IOC was the last one. |
| any other | IOC upserted. A missing report is created and attached to the watchlist. An existing report whose title is the Tide rule `name` is updated, and its severity is replaced whenever the mapped score differs. A shared report (the `report` title is not the rule `name`) is updated too, but its severity rises only when the new score is higher. |

`metadata.uuid` is the IOC id, so a later deploy replaces that IOC instead of adding a second one.

## Relationships

- [platforms](index.md) — shared fields
- [rule-1.0.md](../objects/rule-1.0.md) — `response.alert_severity`, `detection_model`
- [validation.md](../validation.md) — Lucene query validation
- [configuration.md](../configuration.md) — tenant `watchlist`

## Defaults & overrides

| Field | Default |
|-------|---------|
| `watchlist` | tenant setup `watchlist` |
| `report` | Tide rule `name` |
| Severity | `response.alert_severity`, else `Low` |
| IOC id | `metadata.uuid` |

## Examples

```yaml
configurations:
  carbon_black_cloud:
    enabled: true
    schema: platform::carbon_black_cloud::1.0
    status: STAGING
    query: process_name:cmd.exe
    watchlist: OpenTide
    report: Suspicious command processor
    tags:
      - windows
      - execution
```

Fixture: [fixtures/platforms/carbon-black-cloud.yaml](../../fixtures/platforms/carbon-black-cloud.yaml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-30 | Initial field contract from the Carbon Black configuration model, loader, and deployer. |
