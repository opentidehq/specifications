---
spec: platform-bitdefender
version: "1.1"
schema_id: platform::bitdefender::1.0
status: normative
supersedes: null
---

# Bitdefender GravityZone (`platform::bitdefender::1.0`)

## Summary

`configurations.bitdefender` is one GravityZone **custom detection rule**. Deploy creates, updates, and deletes it through the GravityZone Public API: JSON-RPC 2.0, Incidents API, `createCustomRule`, `updateCustomRule`, and `deleteCustomRule`.

The block root holds what every GravityZone rule shares: severity, tags, targets, and automatic actions. Below it sits exactly one kind:

- `detection`: a Basic rule, a list of criteria on a process, file, connection, registry, or XDR event;
- `yara`: a YARA detection rule, a [`YaraSignature`](../languages/yara-1.0.md#yarasignature) checked against the [YARA language](../languages/yara-1.0.md) under the Bitdefender profile.

Deploy derives the GravityZone name, description, severity, and tags from the opentide rule. GravityZone exclusion rules are not opentide rules: deploy never creates, updates, or deletes one.

GravityZone assigns every rule a 24-hex id at create time. That id is kept in deployment state ([deployment-state.md](../deployment-state.md)), never on the rule. Every update sends the whole payload.

Shared fields are defined in [platforms](index.md#shared-platform-block). The design and its alternatives are in [RFC 0016](../../rfcs/0016-bitdefender-gravityzone-platform.md).

## Requirements

Static validation (`opentide validate`) and registry load:

- `status` MUST be present, as on `elastic` and `sysdig`.
- A block MUST set exactly one of `detection` and `yara` (`bitdefender_rule_kind`). Any other key at the block root, `exclusion` included, MUST fail as an unknown key.
- A block MUST satisfy every [constraint](#constraints), reported with its code.
- `yara.signature` MUST be checked against the [YARA language](../languages/yara-1.0.md) under the [Bitdefender profile](#yara-profile). Its errors fail static validation; its warnings do not.
- Unknown keys MUST fail, at the block root and inside every object in the field tables.
- Legacy external-id keys (`rule_id`, `rule_id_bundle`, `rule_id::<tenant>`) MUST fail with `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)).

Deploy:

- Bitdefender is state-backed. Deploy MUST follow the [deploy decisions](../deployment-state.md#deploy-decisions) of deployment state and store the GravityZone rule id under `platforms.bitdefender.<tenant>`, lower-case, matching `^[0-9a-f]{24}$`.
- Deploy MUST NOT find a rule by listing (`getCustomRulesList`), by name, or by tag. It MUST NOT call `getCustomRulesList` on the deploy path.
- Deploy MUST NOT call `createCustomRule` unless the returned id can be kept (`deployment_state_ignored`, `deployment_state_unpersisted`). It MUST send `returnRuleId: true`, and MUST fail the rule with `bitdefender_create_no_id` when the answer is not a 24-hex id.
- Every `updateCustomRule` MUST send the whole payload: `ruleId`, `type`, `name`, `description`, `tags`, the full `settings` with every action type the kind allows, and `targets`. GravityZone keeps the stored value of any optional parameter it is not sent.
- Deploy MUST NOT create, update, or delete an exclusion rule (`type: 2`). Every call carries `type: 1`.
- The client MUST send at most 5 `createCustomRule` and `deleteCustomRule` calls per rolling minute per API key, and MUST honour `-32003` and HTTP 429 (`Retry-After`) by waiting and resending the same request.
- A response with an `error` member is a failure, whatever its HTTP status.
- Deploy MUST NOT write to the rule file.

Query validation:

- `opentide validate query --platform bitdefender` MUST report `supported: false`. GravityZone has no dry run in its API.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `severity` | string | optional | [derived](#severity) | `Low`, `Medium`, or `High` |
| `tags` | list[string] | optional | null | Extra GravityZone tags. Deploy adds the [derived tags](#tags). |
| `targets` | [BitdefenderTargets](#targets-bitdefendertargets) | optional | tenant `targets` | Endpoint tags, or companies on a partner tenant, the rule applies to. Neither means the whole company. |
| `actions` | [BitdefenderActions](#actions-bitdefenderactions) | optional | null | Automatic actions |
| `detection` | [BitdefenderDetection](#detection-bitdefenderdetection) | conditional | — | A Basic detection rule (`type: 1`, `subtype: 0`) |
| `yara` | [BitdefenderYara](#yara-bitdefenderyara) | conditional | — | A YARA detection rule (`type: 1`, `subtype: 1`) |

The shared `name` is the GravityZone rule name. Empty means the opentide rule `name`.

### `detection` (BitdefenderDetection)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `target` | string | yes | — | A GravityZone detection target, as the API spells it: `process`, `file`, `connection`, `registry`, `user connection`, `email`, `application`, `key vault`, `role`, `policy`, `sharing link`, `url`, `ssh key`, `launch template`, `service principal`, `user group`, `automation account`, `automation account hook`, `certificate authority`, `api`, `bucket`, `jira project`, or `confluence page` |
| `criteria` | list[Criterion] | yes | — | At least one. All criteria must match (AND). |
| `alert` | string | optional | null | A GravityZone alert (detection) name. Sent as `filters: [{"field": "detection", "value": <alert>}]`. |

`criteria[]` (Criterion) has `field` and **exactly one** relation key:

| Field | Type | Description |
|-------|------|-------------|
| `field` | string | API field name (`Process.CommandLine`) from the [criteria catalogue](#criteria-catalogue) for the `target` |
| `is` | string or integer | Exact match. Sent as `relation: "is"`. |
| `contains` | string | Substring, with `*` and `?` wildcards. Sent as `relation: "contains"`. |
| `any` | list[string or integer], non-empty | Any of the values. Sent as `relation: "any"`. |

### `yara` (BitdefenderYara)

A [`YaraSignature`](../languages/yara-1.0.md#yarasignature), plus:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `signature` | string | yes | — | The YARA signature: imports, then one or more YARA rules, written out in the block. Sent as `settings.yaraQuery`, verbatim. |
| `on_access` | boolean | optional | `true` | On-access scanning with this rule (`settings.status`). With `false`, the rule serves on-demand scans only. |

### `targets` (BitdefenderTargets)

| Field | Type | Description |
|-------|------|-------------|
| `endpoint_tags` | list[string] | Aliases from the tenant's `endpoint_tags` table. Each resolves to `{tagId, companyId}`. |
| `companies` | list[string] | Partner tenants: aliases from the tenant's `companies` table. Each resolves to a company id. |

At most one of the two is set, and each list is non-empty. A rule file carries aliases, never GravityZone ids, because ids differ per tenant. An alias the tenant does not define fails that rule at deploy (`bitdefender_target_unknown`).

### `actions` (BitdefenderActions)

A map. Each key appears at most once.

| Key | GravityZone `type` | Value | Allowed with |
|-----|--------------------|-------|--------------|
| `isolate` | 1 | `true` | `detection`, `yara` |
| `collect_investigation_package` | 2 | `true` | `detection`, `yara` |
| `sandbox` | 3 | `true` | `detection` with a `process` or `file` target or a `*.CreatedBy.*` criterion; `yara` |
| `kill_process` | 4 | `true`, or `{include_parent: bool, include_children: bool}`, each default `false` | `detection` with a `process` or `file` target or a `*.CreatedBy.*` criterion |
| `antimalware_scan` | 5 | `quick` or `full` | `detection`, `yara` |
| `quarantine` | 6 | `true`, or `{include_parent: bool, include_children: bool}`, each default `false` | as `sandbox` |
| `risk_scan` | 7 | `true` | `detection`, `yara` |

### Constraints

Static validation MUST reject a block that breaks any of these, and report the code:

| Code | Constraint |
|------|------------|
| `bitdefender_rule_kind` | Exactly one of `detection` and `yara` is set. |
| `bitdefender_target` | `target` is a detection target from the [`detection`](#detection-bitdefenderdetection) table. The exclusion-only targets `flow` and `bitbucket repository` are refused. |
| `bitdefender_criterion_shape` | A criterion has `field` and exactly one of `is`, `contains`, and `any`. `is` is a string or an integer, `contains` is a string, and `any` is a non-empty list of strings or integers. A boolean is none of these. |
| `bitdefender_criterion_field` | `field` belongs to the `target` in the [criteria catalogue](#criteria-catalogue). |
| `bitdefender_criterion_relation` | Enum fields take `is` or `any`; `File.CertificateSignedStatus`, `Connection.Protocol`, and `Registry.DataType` take `is` only. `contains` is not allowed on `*.MD5` and `*.SHA2`. |
| `bitdefender_criterion_value` | An enum field's value is one of its values. A port is an integer from 0 to 65535. |
| `bitdefender_criteria_combination` | The catalogue's pairing rules hold. EDR-only and XDR-only fields or values are not mixed. `File.Certificate*` needs `File.Name` or `File.FullPathName`. `Connection.Protocol` needs `Connection.Domain`. An XDR detection uses `alert` or an operation criterion, not both. |
| `bitdefender_action_scope` | Each action is allowed for the kind and target ([`actions`](#actions-bitdefenderactions)). |
| `bitdefender_targets_shape` | At most one of `targets.endpoint_tags` and `targets.companies`; each list is non-empty. |
| `bitdefender_severity` | `severity` is `Low`, `Medium`, or `High`. |
| `bitdefender_yara_ascii` | `yara.signature` holds ASCII characters only. |
| `bitdefender_yara_size` | `yara.signature` is at most 30,000 characters. |
| `bitdefender_name_duplicate` | Workspace check: no two enabled `bitdefender` blocks resolve to the same GravityZone [name](#name-and-description). GravityZone refuses a second rule with one name in a company. |

Every implementation reports each code at the same `field_path`, so opentide and the editor name the same finding. Paths are under `configurations.bitdefender`:

| Code | `field_path` |
|------|--------------|
| `bitdefender_rule_kind` | the block |
| `bitdefender_target` | `detection.target` |
| `bitdefender_criterion_shape`, `bitdefender_criterion_field`, `bitdefender_criterion_relation`, `bitdefender_criterion_value` | `detection.criteria.<N>`, the criterion; `detection.criteria` when the list itself is empty or not a list |
| `bitdefender_criteria_combination` | `detection.criteria` |
| `bitdefender_action_scope` | `actions.<key>` |
| `bitdefender_targets_shape` | `targets` |
| `bitdefender_severity` | `severity` |
| `bitdefender_yara_ascii`, `bitdefender_yara_size` | `yara.signature` |
| advisories | `detection.criteria.<N>` for `bitdefender_registry_full_hive` and `bitdefender_contains_no_wildcard`; the block for `bitdefender_severity_collapsed` |

### Criteria catalogue

The fields per target, their kinds, their enum values, and the pairing rules are Bitdefender's [Detection and exclusion criteria for Basic rules](https://www.bitdefender.com/business/support/en/77209-1486297-detection-and-exclusion-criteria.html). The language server ships them as data in `catalogs/bitdefender/criteria.toml`, generated from that page. The EDR targets:

| Target | Fields |
|--------|--------|
| `process` | `Process.Name`, `Process.Path`, `Process.FullPathName`, `Process.CommandLine`, `Process.Parent.Name`, `Process.Parent.Path`, `Process.Parent.FullPathName`, `Process.Parent.CommandLine`, `Process.User`, `Process.MD5`, `Process.SHA2` |
| `file` | `File.Name`, `File.Path`, `File.FullPathName`, `File.Operation`, `File.CreatedBy.Name`, `File.CreatedBy.Path`, `File.CreatedBy.FullPathName`, `File.CreatedBy.CommandLine`, `File.CreatedBy.User`, `File.CertificateSigner`, `File.CertificateIssuer`, `File.CertificateSignedStatus`, and the XDR fields `File.MD5`, `File.SHA2`, `File.Url`, `File.SourceIP`, `File.DestinationIP` |
| `connection` | `Connection.SourceIP`, `Connection.DestinationIP`, `Connection.SourcePort`, `Connection.DestinationPort`, `Connection.Process.Name`, `Connection.Process.Path`, `Connection.Process.FullPathName`, `Connection.Process.CommandLine`, `Connection.Process.User`, `Connection.URL`, `Connection.Domain`, `Connection.Protocol`, `Connection.HTTPUser`, `Connection.HTTPDownloadedFile`, `Connection.HTTPUploadedFile`, `Connection.FTPUser`, `Connection.SSHUser`, `Connection.TelnetUser`, `Connection.SMBDomain`, `Connection.SMBSharePath`, `Connection.SMBUser`, `Connection.WMIExecQuery`, `Connection.FileRemotePath`, `Connection.FileRemoteOperation`, and the XDR fields `Connection.SourceUser`, `Connection.DestinationUser`, `Connection.Email.Subject`, `Connection.<Resource>.Name` for the resources `File`, `Application`, `KeyVault`, `Role`, `Policy`, `SharingLink`, `Url`, `SshKey`, `LaunchTemplate`, `ServicePrincipal`, `UserGroup`, `AutomationAccount`, `AutomationAccountHook`, `Api`, `CertificateAuthority`, `Bucket`, `ConfluencePage`, `JiraProject`, and `Connection.<Resource>.Operation` for those resources and `Email` |
| `registry` | `Registry.Key`, `Registry.Value`, `Registry.Data`, `Registry.DataType`, `Registry.Operation`, `Registry.CreatedBy.Name`, `Registry.CreatedBy.Path`, `Registry.CreatedBy.FullPathName`, `Registry.CreatedBy.CommandLine` |

| Enum field | Values |
|------------|--------|
| `File.Operation` | `rename`, `copy`, `create` (EDR only); `shared`, `downloaded`, `uploaded` (XDR only); `read`, `write`, `move` |
| `File.CertificateSignedStatus` | `is_signed`, `is_unsigned` |
| `Connection.Protocol` | `http/https`, `smb` |
| `Connection.FileRemoteOperation` | `create`, `rem_delete`, `read`, `write`, `move` |
| `Registry.Operation` | `key_created`, `key_deleted`, `key_renamed`, `value_created`, `value_deleted`, `value_written` |
| `Registry.DataType` | `string`, `expandablestring`, `dword`, `qword`, `binary`, `none`, `link`, `resource_list`, `full_resource_descriptor`, `resource_requirements_list` |
| `Connection.<Resource>.Operation` (XDR) | the values the catalogue lists for each resource |

For a target this table does not cover, the catalogue file is the reference. An unknown field there is a warning, not an error, until the catalogue covers it. For `process`, `file`, `connection`, and `registry`, the table above and the catalogue list the same detection fields, and an unknown field is an error.

### YARA profile

The [Bitdefender profile](../languages/yara-1.0.md#platform-profiles) of the YARA language: dialect `libyara4`, ASCII only, at most 30,000 characters, one or more YARA rules per `signature`, and confirmed modules `pe`, `elf`, `math`, `hash`, and `time`. GravityZone allows at most 50 YARA rules per company.

### Advisories

Advisories are [warnings](../validation.md#platform-advisories): validation reports them under their code and never rejects the rule.

| Code | When | Why |
|------|------|-----|
| `bitdefender_registry_full_hive` | A `Registry.Key` value starts with a full hive name (`HKEY_LOCAL_MACHINE\…`), compared case-insensitively. | GravityZone accepts it, and the rule never triggers. Write `HKLM`, `HKCU`, `HKCR`, `HKCC`, `HKU` for `HKEY_USERS\<SID>…`, or `HKLU` for any other `HKEY_USERS\…` key. |
| `bitdefender_contains_no_wildcard` | A `contains` value has neither `*` nor `?`. | GravityZone matches it as written; the author most likely meant `*value*`. |
| `bitdefender_severity_collapsed` | `response.alert_severity` is `Critical` or `Informational`, and `severity` is not set. | GravityZone has three levels, so the value is sent as `High` or `Low`. |

### Name and description

GravityZone refuses `<`, `>`, `'`, `"`, and leading whitespace in names, descriptions, and tags. Deploy **normalises** text: `<` → `‹`, `>` → `›`, `'` → `’`, `"` → `”`, and leading whitespace removed.

| GravityZone field | Derivation |
|-------------------|------------|
| `name` | The shared `name`, else the opentide rule `name`, normalised, cut at 128 characters |
| `description` | The opentide `description`, whitespace runs collapsed to one space, trimmed, normalised, cut at 1024 characters (the last kept character replaced by `…` when cut) |

### Severity

`settings.severity` is the block `severity` (`Low` → 1, `Medium` → 2, `High` → 3). Without it, it comes from `response.alert_severity`:

| `response.alert_severity` | `settings.severity` |
|---------------------------|---------------------|
| `Critical` | 3 |
| `High` | 3 |
| `Medium` | 2 |
| `Low` | 1 |
| `Informational` | 1 |
| missing | 2 |

### Tags

Deploy sends the union, in this order and without duplicates:

1. The block `tags`.
2. Each ATT&CK technique id of the rule: its `techniques` plus those inherited through `detection_model`, the union [elastic-1.0](elastic-1.0.md#attck) uses.
3. `opentide`, then `opentide:<metadata.uuid>`.
4. The tenant `tags`.

Each tag is normalised. A tag shorter than 2 characters is dropped, and a tag longer than 128 is cut. The `opentide:<uuid>` tag is for analysts and audits; deploy never uses it to find a rule.

### Tenant setup

```toml
[platform]
enabled = true
identifier = "bitdefender"
name = "Bitdefender GravityZone"
subschema = "Bitdefender GravityZone"
description = "Custom detection and YARA detection rules for GravityZone EDR/XDR."
flags = []

[[tenants]]
name = "gravityzone-eu"
description = "GravityZone cloud instance 1 (EU)"
strategies = ["RELEASE"]
[tenants.setup]
ssl = true
url = "https://cloudgz.gravityzone.bitdefender.com/api"
api_key = "$GRAVITYZONE_API_KEY"
key_type = "personal"
automatic_actions = true
tags = ["managed-by-opentide"]

[tenants.setup.endpoint_tags]
tier0-servers = { tag_id = "5b680f6fb1a43d860a7b23c8", company_id = "61827b8036492c2fc0718722" }
```

| `tenants.setup` field | Type | Required | Default | Meaning |
|-----------------------|------|----------|---------|---------|
| `url` | string | yes | — | The Control Center API Access URL, ending in `/api`: `https://cloudgz.gravityzone.bitdefender.com/api` (instance 1, EU), `https://cloud.gravityzone.bitdefender.com/api` (instance 2), `https://cloudap.gravityzone.bitdefender.com/api` (instance 3), or a partner console's. Calls go to `<url>/v1.0/jsonrpc/incidents`. |
| `api_key` | string | yes | — | MUST be a `$ENV` reference. The key needs the Incidents API. |
| `key_type` | string | no | `personal` | `personal`: HTTP Basic, the key as user name and an empty password. `service`: `X-API-Key: <key>`. |
| `company_id` | string | no | the key's company | Partner tenants: the company that owns created rules (`companyId`), 24 hex |
| `automatic_actions` | bool | no | `true` | `false` for subscriptions without automatic actions. Deploy then omits `automaticActions` and reports `bitdefender_actions_unsupported` (warning) for a block that sets `actions`. |
| `targets` | table | no | none | Default `targets` for blocks that set none, as `{endpoint_tags = [...]}` or `{companies = [...]}` |
| `endpoint_tags` | table | no | `{}` | Alias → `{tag_id, company_id}`, each 24 hex |
| `companies` | table | no | `{}` | Alias → company id, 24 hex |
| `tags` | list[string] | no | `[]` | Tags added to every rule deployed to this tenant |
| `ssl` | bool | yes | — | Shared tenant setup (TLS verification) |

A tenant with an unknown setup key, a literal `api_key`, or an id that is not 24 hex fails configuration load. On-premises GravityZone has no Incidents API. An on-premises URL fails the tenant with `bitdefender_incidents_api_unavailable` at the first `-32601` (method not found).

### Deploy

Each request is a JSON-RPC 2.0 `POST` to `<url>/v1.0/jsonrpc/incidents` with `Content-Type: application/json`, a fresh string `id`, and the method's `params`.

| Kind | `type` / `subtype` | `settings` |
|------|--------------------|------------|
| `detection` | 1 / 0 | `status`, `severity`, `target`, `criteriaList` (`[{field, relation, value}]`, in block order), `filters` (`[{field: "detection", value: <alert>}]`, or `[]` without `alert`; omitted on create without `alert`), `automaticActions` |
| `yara` | 1 / 1 | `status`, `severity`, `yaraQuery` (`signature` with `\n` line endings and one trailing newline), `automaticActions` |

`settings.status` is `1`, or `0` under `DISABLEMENT`. On a `yara` rule it is `1` only when `on_access` is `true`, and `0` otherwise.

**Automatic actions.** Every action type the kind allows is sent, in type order, each with `enabled: true` or `false`: types 1–7 for `detection`, and 1, 2, 3, 5, 6, 7 for `yara`. An enabled `kill_process` or `quarantine` carries `settings: {includeParent, includeChildren}`. An enabled `antimalware_scan` carries `settings: {type: 1}` for `quick` or `{type: 2}` for `full`. A disabled entry carries only `type` and `enabled`. With tenant `automatic_actions = false`, `automaticActions` is omitted.

**Targets.** `targets.endpoint_tags` is sent as `targets.endpointTags: [{tagId, companyId}]`, and `targets.companies` as `targets.companiesIds`. Without block or tenant `targets`, the rule applies to the whole company: a create omits `targets`, and an update sends `"targets": {}`. A partner tenant's `company_id` is sent as `companyId` on create.

**Nothing is left to the stored rule.** GravityZone keeps the stored value of any optional parameter an update does not send, so an update sends an explicit value for every parameter the block can change: `filters: []` when `alert` was removed, `targets: {}` when targets were removed. A tenant that refuses an empty value fails the rule with its `error`, rather than leaving the rule scoped or filtered as before.

| Block status strategy | Binding in deployment state | GravityZone calls |
|-----------------------|-----------------------------|-------------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | `createCustomRule` with `type`, `subtype`, `name`, `description`, `tags`, `settings`, `targets`, and `returnRuleId: true`. The returned id is recorded at once. |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present | `updateCustomRule` with `ruleId` and the whole payload: `type`, `name`, `description`, `tags`, `settings`, and `targets` |
| `DISABLEMENT` | present | `updateCustomRule` as above, with `settings.status: 0` |
| `DELETION` | present | `deleteCustomRule` with `ruleId` and `type: 1`, then the binding is removed |
| `DISABLEMENT`, `DELETION` | none | `external_id_missing` (warning), no call |

| Situation | Behaviour |
|-----------|-----------|
| `updateCustomRule` answers `-32002` (resource not found) | Create the rule again and replace the binding, with the `bitdefender_rule_recreated` warning. Under `DISABLEMENT`, create nothing, remove the binding, and warn `bitdefender_rule_missing`. |
| `deleteCustomRule` answers `-32002` | Success. The binding is removed. |
| A create is refused because the name exists in the company | `bitdefender_name_conflict`. Deploy MUST NOT adopt the existing rule. |
| A create gets no answer (timeout, connection reset) | Retry it once. A name conflict on that retry is `bitdefender_create_unconfirmed`: the first create may have succeeded, and the operator resolves it in the console. |
| A create answers anything but a 24-hex id | `bitdefender_create_no_id`. The failure names the rule `name`. |
| An update is refused for a type mismatch | `bitdefender_kind_changed`. GravityZone cannot turn a YARA rule into a Basic rule; changing the kind means `DELETION`, then a new deploy. |
| `-32001`, HTTP 401, or HTTP 403 | `bitdefender_tenant_unauthorized`: the tenant stops. |
| `-32003` or HTTP 429 | Wait for `Retry-After`, then resend the same request. A rate-limited request was not executed. |
| An alias in `targets` that the tenant does not define | `bitdefender_target_unknown`, before any call for that rule |
| Any other `error` | The rule fails with its code and `error.data.details`. |

### Query validation

| Check | Bitdefender |
|-------|-------------|
| `opentide validate` (offline) | yes: the constraints, the criteria catalogue, and the YARA language for `yara.signature` |
| `opentide validate query --live` | no (`supported: false`) |
| `opentide query` | no |

## Relationships

- [platforms](index.md): shared fields, capability matrix, external ids
- [yara-1.0](../languages/yara-1.0.md): `YaraSignature`, the YARA language, the Bitdefender profile
- [deployment-state.md](../deployment-state.md): the GravityZone rule id
- [deployment.md](../deployment.md): status strategies
- [rule-1.0.md](../objects/rule-1.0.md): `response.alert_severity`, `techniques`, `detection_model`, `description`
- [validation.md](../validation.md): static validation, advisories, query validation
- [RFC 0016](../../rfcs/0016-bitdefender-gravityzone-platform.md): design, research, and alternatives

## Defaults & overrides

| Field | Default |
|-------|---------|
| GravityZone name | Shared `name`, else the opentide rule `name` |
| `severity` | [Severity](#severity), else Medium (2) |
| `targets` | Tenant `targets`, else the whole company |
| `yara.on_access` | `true` |
| `key_type` | `personal` |
| `automatic_actions` | `true` |

## Examples

A Basic detection rule:

```yaml
configurations:
  bitdefender:
    enabled: true
    schema: platform::bitdefender::1.0
    status: STAGING
    tags: [office]
    targets:
      endpoint_tags: [tier0-servers]
    actions:
      kill_process: {include_children: true}
      collect_investigation_package: true
    detection:
      target: process
      criteria:
        - field: Process.Parent.Name
          any: [winword.exe, excel.exe, powerpnt.exe]
        - field: Process.Name
          is: powershell.exe
        - field: Process.CommandLine
          contains: "*-enc*"
```

A YARA detection rule:

```yaml
configurations:
  bitdefender:
    enabled: true
    schema: platform::bitdefender::1.0
    status: PRODUCTION
    actions:
      quarantine: true
      antimalware_scan: full
    yara:
      on_access: true
      signature: |
        import "pe"

        rule Loader_Stage1 {
          strings:
            $cfg = { 43 46 47 21 [4-16] 00 01 }
          condition:
            pe.number_of_sections > 3 and $cfg
        }
```

Fixtures:

- block: [fixtures/platforms/bitdefender.yaml](../../fixtures/platforms/bitdefender.yaml);
- rules: [fixtures/valid/rule-bitdefender-detection-1.0.yaml](../../fixtures/valid/rule-bitdefender-detection-1.0.yaml) and [fixtures/valid/rule-bitdefender-yara-1.0.yaml](../../fixtures/valid/rule-bitdefender-yara-1.0.yaml);
- the tenant they deploy to: [fixtures/platforms/bitdefender/tenant.toml](../../fixtures/platforms/bitdefender/tenant.toml);
- the JSON-RPC bodies deploy sends, without the per-request `id`, under [fixtures/platforms/bitdefender/](../../fixtures/platforms/bitdefender/).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-11-10 | Initial field contract ([RFC 0016](../../rfcs/0016-bitdefender-gravityzone-platform.md)): `detection` and `yara` kinds, criteria catalogue, derived name, description, severity, and tags; whole-payload updates; the GravityZone id in deployment state; no exclusion rules. |
| 1.1 | 2026-11-10 | Clarifications from the first implementation review: an update sends `filters: []` and `targets: {}` when the block has none, so a removed alert filter or target scope does not survive on GravityZone (create still omits them); the `connection` row lists the XDR fields Bitdefender's criteria page gives (`Connection.SourceUser`, `Connection.DestinationUser`, `Connection.Email.Subject`, and a `.Name` and `.Operation` per XDR resource); three enum fields take `is` only; value types per relation; one `field_path` per code; the `HKLU` hint for `HKEY_USERS` keys without a SID. Schema id unchanged. |
