---
spec: platform-defender-for-endpoint
version: "1.1"
schema_id: platform::defender_for_endpoint::1.0
status: normative
supersedes: null
---

# Microsoft Defender for Endpoint (`platform::defender_for_endpoint::1.0`)

## Summary

`configurations.defender_for_endpoint` is a Microsoft Defender custom detection rule. The detection text is KQL. Query validation is supported. Defender assigns the remote rule id; OpenTide stores it per tenant in [deployment state](../deployment-state.md) so the next deploy updates that rule.

Shared fields are defined in [platforms](index.md#shared-platform-block).

## Requirements

- Static validation MUST require `query`, `alert`, `impacted_entities`, and `scheduling`.
- `alert.category` MUST be present. The other alert fields MAY be omitted.
- `impacted_entities` MAY be an empty object. At least the object MUST be present.
- `scheduling` MUST be one of `NRT`, `1H`, `3H`, `12H`, `24H`.
- `query` MUST be non-blank KQL.
- `scope`, `actions`, and `exclusions` MAY be omitted and still pass static validation.
- The block MUST NOT contain `rule_id`, `rule_id_bundle`, or `rule_id::<tenant>`. Each fails `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)).
- Registry load MUST require `scope`. A block that validates without `scope` MUST NOT load for deploy.
- `actions.files.quarantine_files` MAY be used as an alias of `quarantine_file` on the registry-load path.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | KQL. Multiline. Compiled with matching `exclusions` before deploy. |
| `alert` | [DefenderAlert](#alert-defenderalert) | yes | — | Custom detection alert template. |
| `impacted_entities` | [DefenderImpactedEntities](#impacted_entities-defenderimpactedentities) | yes | — | Columns that identify the impacted device, user, or mailbox. |
| `scheduling` | string | yes | — | `NRT`, `1H`, `3H`, `12H`, or `24H`. |
| `scope` | [DefenderGroupScoping](#scope-defendergroupscoping) | optional | null | Device-group scope. Required by registry load. The current deployer does not send it. |
| `actions` | [DefenderResponseActions](#actions-defenderresponseactions) | optional | null | Response actions run when the detection fires. |
| `exclusions` | list[[DefenderExclusion](#exclusions-defenderexclusion)] | optional | null | Per-tenant KQL fragments appended to `query`. |

`scheduling: NRT` is sent as period `0`. The other values are sent unchanged.

### `alert` (DefenderAlert)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `category` | string | yes | — | Defender alert category. Deploy removes spaces (`Suspicious Activity` is sent as `SuspiciousActivity`). |
| `title` | string | optional | null | Alert title. Deploy uses the rule `name` when omitted. |
| `description` | string | optional | null | Alert description. Deploy uses the rule `description` when omitted. |
| `severity` | string | optional | null | `Informational`, `Low`, `Medium`, `High`, or `Critical`. Deploy uses `response.alert_severity` when omitted. `Critical` is sent as `high`. |
| `recommendation` | string | optional | null | Recommended actions text. |
| `techniques` | list[string] | optional | null | Accepted on the block. The current deployer sends an empty technique list. |

### `impacted_entities` (DefenderImpactedEntities)

Each value is a result column. Deploy lowercases the first character (Defender expects a column reference such as `deviceId`). Omitted keys are not sent.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `device` | string | optional | Device column. |
| `user` | string | optional | User column. |
| `mailbox` | string | optional | Mailbox column. |

### `scope` (DefenderGroupScoping)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `selection` | string | yes | `All` or `Specific`. |
| `device_groups` | list[string] | optional | Group names. Used when `selection` is `Specific`. |

### `actions` (DefenderResponseActions)

Any of `devices`, `files`, and `users` MAY be omitted. An empty actions object deploys with no response actions.

#### `actions.devices`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `isolate_device` | string | optional | null | Isolation type. Deploy lowercases the first character (`Full` is sent as `full`). |
| `collect_investigation_package` | boolean | optional | `false` | Collect an investigation package. |
| `run_antivirus_scan` | boolean | optional | `false` | Run an antivirus scan. |
| `initiate_investigation` | boolean | optional | `false` | Start an automated investigation. |
| `restrict_app_execution` | boolean | optional | `false` | Restrict app execution. |

#### `actions.files`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `allow_block` | [AllowBlock](#actionsfilesallow_block) | optional | Allow or block a file identifier. |
| `quarantine_file` | string | optional | Column identifying the file to quarantine. Loader alias: `quarantine_files`. |

`actions.files.allow_block`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | yes | `Allow` or `Block`. |
| `identifier` | string | yes | Column identifying the file. Deploy lowercases the first character. |
| `groups` | [GroupScoping](#actionsfilesallow_blockgroups) | optional | Device groups the allow or block applies to. |

`actions.files.allow_block.groups`:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `selection` | string | yes | — | `All` or `Specific`. |
| `device_groups` | list[string] | optional | null | Group names. Sent when `selection` is `Specific`. |

#### `actions.users`

Each value is a column. Deploy lowercases the first character. Omitted keys are not sent.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mark_as_compromised` | string | optional | User column. |
| `disable_user` | string | optional | User column. |
| `force_password_reset` | string | optional | User column. |

### `exclusions[]` (DefenderExclusion)

Same shape and tenant matching as Sentinel exclusions. See [sentinel-1.0.md](sentinel-1.0.md#exclusions-sentinelexclusion).

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | KQL fragment appended after the base query. The key is required. An empty string is accepted. |
| `reason` | string | yes | — | Why the exclusion exists. Not sent to Defender. |
| `tenant` | string | optional | null | Limit the exclusion to one tenant name. |
| `let` | map[string, scalar] | optional | null | KQL `let` bindings. String, number, or boolean. |

### Deploy

| Block status strategy | Defender result |
|-----------------------|-----------------|
| `DISABLEMENT` | Update the bound remote rule with `isEnabled: false`; without a binding, report `external_id_missing` and make no HTTP call. |
| `DELETION` | Delete the bound remote rule and remove the binding after successful deletion; without a binding, report `external_id_missing`. |
| any other | Update when a binding exists; otherwise create and durably record the returned id. |

The binding is the tenant's entry under `defender_for_endpoint` in `.opentide/states/deployment/<uuid>.json`. A create is refused when the shard directory is gitignored or the run cannot persist state, and the rule file is never written. The decision order and codes are in [deployment-state.md](../deployment-state.md#deploy-decisions).

The display name on the Defender rule is the Tide rule `name`.

## Relationships

- [platforms](index.md) — shared fields and external ids
- [deployment-state.md](../deployment-state.md) — where the Defender rule id is stored
- [rule-1.0.md](../objects/rule-1.0.md) — parent object
- [sentinel-1.0.md](sentinel-1.0.md) — shared KQL exclusion shape
- [validation.md](../validation.md) — KQL query validation

## Defaults & overrides

| Field | Default |
|-------|---------|
| `alert.title` | rule `name` at deploy |
| `alert.description` | rule `description` at deploy |
| `alert.severity` | `response.alert_severity` at deploy |
| Device action flags | `false` |
| `scheduling: NRT` | sent as period `0` |

## Examples

```yaml
configurations:
  defender_for_endpoint:
    enabled: true
    schema: platform::defender_for_endpoint::1.0
    status: STAGING
    query: |
      DeviceProcessEvents
      | where FileName =~ "cmd.exe"
      | take 1
    scheduling: 1H
    alert:
      category: Execution
      title: Suspicious command processor
      severity: High
    impacted_entities:
      device: DeviceId
      user: AccountName
    scope:
      selection: All
    actions:
      devices:
        isolate_device: Full
        collect_investigation_package: true
```

Fixture: [fixtures/platforms/defender-for-endpoint.yaml](../../fixtures/platforms/defender-for-endpoint.yaml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-30 | Initial field contract from the Defender configuration model, loader, and deployer. |
| 1.1 | 2026-10-16 | `rule_id` and the `rule_id::<tenant>` alias are removed and fail `external_id_in_rule`. Deploy reads and writes the Defender id in [deployment state](../deployment-state.md); `DISABLEMENT` and `DELETION` without a binding report `external_id_missing` ([RFC 0010](../../rfcs/0010-deployment-external-ids.md)). Schema id unchanged. |
